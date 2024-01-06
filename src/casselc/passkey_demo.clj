(ns casselc.passkey-demo
  (:require
   [org.httpkit.server :as server]
   [ruuter.core :as ruuter]
   [clojure.java.io :as io]
   [charred.api :as json]
   [clojure.core.cache.wrapped :as c]
   [clojure.tools.logging :as log]
   [casselc.passkey-demo.data :refer [->CredentialRegistration] :as d]
   [casselc.passkey-demo.interop :as i]
   [casselc.passkey-demo.sessions :as s]
   [casselc.passkey-demo.util :as u])
  (:import
   (com.yubico.webauthn RegistrationResult RelyingPartyV2 AssertionRequest)
   (com.yubico.webauthn.data ByteArray  PublicKeyCredentialCreationOptions PublicKeyCredential UserIdentity)
   (com.yubico.webauthn.exception AssertionFailedException)
   (java.time Instant)
   (java.util Base64 Random)
   (java.io ByteArrayOutputStream))
  (:gen-class))

(set! *warn-on-reflection* true)

(let [b64 (Base64/getEncoder)]
  (defn ->b64-out
    [in out]
    (with-open [out-stream (io/output-stream out)
                b64-stream (.wrap b64 out-stream)]
      (io/copy in b64-stream)))

  (defn ->b64-str
    [in]
    (let [baos (ByteArrayOutputStream.)]
      (->b64-out in baos)
      (.toString baos "UTF-8"))))


;; static content
(def index-content (some-> "index.html" io/resource slurp))
(def app-content (some-> "app.mjs" io/resource  slurp))
(def css-content (some-> "base.css" io/resource  slurp))
;; state
(def credentials (i/->in-memory-credential-store))
(def sessions (s/->in-memory-session-manager :session-ttl-minutes 10))
(def pending-registrations (u/new-cache :threshold 100 :ttl-ms (* 3 60 1000)))
(def pending-assertions (u/new-cache :threshold 100 :ttl-ms (* 3 60 1000)))
;; config
(def port (or (some-> (System/getenv "PORT")
                      parse-long)
              8090))
(def rp-name (or (System/getenv "RP_NAME") "Clojure Passkey Demo"))
(def rp-id (or (System/getenv "RP_ID") "localhost"))
;; app
(def rp-identity (i/->RelyingPartyIdentity rp-id rp-name))
(def ^RelyingPartyV2 rp (i/->RelyingParty rp-identity credentials))

(defn start-registration!
  [{:strs [username displayName nickname sessionId]}]
  {:post [(map? %) (let [[key & others] (keys %)]
                     (and (empty? others) (#{:success :error} key)))]}

  (log/info "Starting registration, username:" username ", display:" displayName, ", nickname:" nickname)
  (let [^UserIdentity user (some-> (i/credentials-for-username credentials username)
                                   first
                                   :user)
        user-handle (some-> user .getId)
        session-id (some-> sessionId ByteArray/fromBase64Url)]
    (if (or (nil? user) (s/session-for-user? sessions session-id user-handle))
      (let [register-user (or user (i/->UserIdentity username displayName))
            start-opts  (i/->StartRegistrationOptions register-user)
            request-id (u/random-bytes 32)
            creation-opts (.startRegistration rp start-opts)
            session-id (s/create-session sessions user-handle)
            registration-req (d/->RegistrationRequest request-id session-id username nickname creation-opts)]
        (log/info "Saving pending registration request for user" username "with id:" (.getBase64Url request-id))
        (swap! pending-registrations assoc request-id registration-req)
        {:success registration-req})
      {:error [(str username " is already in use. Please try another username.")]})))

(defn- store-registered-credential!
  [^UserIdentity user ^String nickname ^RegistrationResult result]
  (log/info "Adding registration for user:" user "nickname:" nickname "result:" result)
  (let [reg (->CredentialRegistration user
                                      nickname
                                      (i/->RegisteredCredential (-> result .getKeyId .getId)
                                                                (.getId user)
                                                                (.getPublicKeyCose result)
                                                                (.getSignatureCount result))
                                      (or (some-> result .getKeyId .getTransports) #{})
                                      (Instant/now))]
    (i/add-credential-for-user credentials (.getName user) reg)
    reg))

(defn finish-registration!
  [req]
  (let [json (-> req :body slurp)]
    (log/info "Finishing registration from response:" json)
    (try
      (let [{:strs [requestId credential] :as response} (some-> json json/read-json)
            _ (log/info "Parsed response:" response)
            request-id (some-> requestId ByteArray/fromBase64Url)
            _ (log/info "Parsed request-id:" request-id)
            {:keys [username nickname sessionId ^PublicKeyCredentialCreationOptions options] :as request} (some->> request-id (c/lookup pending-registrations))
            _ (log/info "Cached request:" request)]
        (c/evict pending-registrations request-id)
        (if request
          (try
            (let [credential (i/RegistrationResponse->PublicKeyCredential credential)
                  registration (.finishRegistration rp (i/->FinishRegistrationOptions options credential))
                  user (some-> options .getUser)
                  user-handle (some-> user .getId)]
              (when (and (i/user-exists? credentials username)
                         (not (s/session-for-user? sessions sessionId user-handle)))
                (log/info "User already exists")
                (throw (ex-info "User already exists" {:username username} ::registration-failed)))
              (let [registered (store-registered-credential! user nickname registration)]
                {:success (d/->SuccessfulRegistrationResult request response registered (.isAttestationTrusted registration) (s/create-session sessions user-handle))}))
            (catch clojure.lang.ExceptionInfo e
              (log/debug e "Registration failed with JSON:" json)
              {:error ["Registration failed." (ex-message e)]}))
          {:error ["Registration failed" "Failed to parse response JSON:" (log/spyf :error "Response JSON: %s" json) (log/spyf :error "Parsed: %s" response)]}))
      (catch Exception e
        (log/error e "Registration failed for request:" json)
        {:error ["Registration failed unexpectedly" (ex-message e)]}))))

(defn start-assertion!
  [{:strs [username] :as form}]
  {:post [(map? %) (let [[key & others] (keys %)]
                     (and (empty? others) (#{:success :error} key)))]}
  (log/info "Starting assertion for user:" username)
  (try
    (if (and (seq username) (not (i/user-exists? credentials username)))
      {:error [(str "The user" username "does not exist.")]}
      (let [request-id (u/random-bytes 32)
            assertion-opts (i/->StartAssertionOptions username)
            assertion-req (.startAssertion rp assertion-opts)
            request-opts (.getPublicKeyCredentialRequestOptions assertion-req)
            auth-req (d/->AuthenticationRequest request-id username request-opts assertion-req)]
        (log/info "Saving pending authentication request for user" username "with id:" (.getBase64Url request-id))
        (swap! pending-assertions assoc request-id auth-req)
        {:success auth-req}))
    (catch Exception e
      (log/error e "Failed to start assertion with form:" form)
      {:error ["Authentication failed unexpectedly" (ex-message e)]})))

(defn finish-assertion!
  [req]
  {:post [(map? %) (let [[key & others] (keys %)]
                     (and (empty? others) (#{:success :error} key)))]}
  (let [json (-> req :body slurp)]
    (log/info "Finishing authentication from response:" json)
    (try
      (let [{:strs [requestId credential] :as response} (some-> json json/read-json)
            _ (log/info "Parsed response:" response)
            request-id (some-> requestId ByteArray/fromBase64Url)
            _ (log/info "Parsed request-id:" request-id)
            {:keys [username ^AssertionRequest request] :as cached-request} (some->> request-id (c/lookup pending-assertions))
            _ (log/info "Cached request:" cached-request)]
        (c/evict pending-assertions request-id)
        (if cached-request
          (try
            (let [^PublicKeyCredential credential (i/AssertionResponse->PublicKeyCredential credential)
                  auth-data (-> credential .getResponse .getParsedAuthenticatorData)
                  assertion-result (.finishAssertion rp (i/->FinishAssertionOptions request credential))
                  user-handle (-> assertion-result .getCredential .getUserHandle)]
              (if (.isSuccess assertion-result)
                (do
                  (try
                    (i/update-signature-count credentials assertion-result)
                    (catch Exception e
                      (log/error e "Failed to update signature count for user:" username "and assertion result:" assertion-result)))
                  {:success (d/->SuccessfulAuthenticationResult cached-request (d/->AuthenticationResponse request-id credential) (i/credentials-for-username credentials username) auth-data (s/create-session sessions user-handle))})
                {:error ["Authentication failed" "Invalid assertion"]}))
            (catch AssertionFailedException e
              (log/debug e "Assertion failed for response:" response "with request:" cached-request)
              {:error ["Authentication failed" (ex-message e)]}))
          {:error ["Authentication failed" "Failed to locate a matching request in progress."]}))
      (catch Exception e
        (log/error e "Authentication failed:" json)
        {:error ["Authentication failed unexpectedly" (ex-message e)]}))))

(defn handle-start
  [f]
  (fn [req]
    (try
      (if-let [form (u/parse-form-params req)]
        (let [{:keys [success error]} (f form)]
          (if success
            {:status 200
             :headers {"Content-Type" "application/json"}
             :body (json/write-json-str {:success true
                                         :request success})}
            {:status 400
             :headers {"Content-Type" "application/json"}
             :body (json/write-json-str error)}))
        {:status 400
         :body "Failed to parse form data."})
      (catch Exception e
        (log/error e "failure when starting" f "on" req)
        {:status 500
         :headers {"Content-Type" "text/plain"}
         :body (ex-message e)}))))

(defn handle-finish
  [f]
  (fn [req]
    (try
      (let [{:keys [success error]} (f req)]
        (if success
          {:status 200
           :headers {"Content-Type" "application/json"}
           :body (json/write-json-str (assoc success :success true))}
          {:status 400
           :headers {"Content-Type" "application/json"}
           :body (json/write-json-str error)}))
      (catch Exception e
        (log/error e "failure when finishing" f "on" req)
        {:status 500
         :headers {"Content-Type" "text/plain"}
         :body (ex-message e)}))))




(defn- start-server!
  [port]
  (server/run-server
   #(ruuter/route
     [{:path "/"
       :method :get
       :response {:status 200
                  :headers {"Content-Type" "text/html"}
                  :body index-content}}
      {:path "/public/app.mjs"
       :method :get
       :response {:status 200
                  :headers {"Content-Type" "application/javascript"}
                  :body app-content}}
      {:path "/public/base.css"
       :method :get
       :response {:status 200
                  :headers {"Content-Type" "text/css"}
                  :body css-content}}
      {:path "/register"
       :method :post
       :response (handle-start start-registration!)}
      {:path "/register/finish"
       :method :post
       :response (handle-finish finish-registration!)}
      {:path "/authenticate"
       :method :post
       :response (handle-start start-assertion!)}
      {:path "/authenticate/finish"
       :method :post
       :response (handle-finish finish-assertion!)}
      {:path "/user-admin/deregister-credential"
       :method :post}
      {:path "/user-admin/delete-account"
       :method :delete}]
     %)
   {:port port}))

(comment
  (def server (start-server! 8090))

  (server))

(defn -main [& _args]
  (org.slf4j.bridge.SLF4JBridgeHandler/removeHandlersForRootLogger)
  (org.slf4j.bridge.SLF4JBridgeHandler/install)
  (start-server! port)
  (log/info "Site running on" (str "http://localhost:" port)))

(comment (i/credentials-for-username credentials "test"))