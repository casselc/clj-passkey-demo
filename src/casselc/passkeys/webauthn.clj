(ns casselc.passkeys.webauthn
  (:require
   [charred.api :as json]
   [clojure.core.cache.wrapped :as c]
   [clojure.tools.logging :as log]
   [casselc.passkeys.data :refer [->CredentialRegistration] :as d]
   [casselc.passkeys.interop :as i]
   [casselc.passkeys.sessions :as s]
   [casselc.passkeys.util :as u])
  (:import
   (com.yubico.webauthn RegistrationResult RelyingPartyV2 AssertionRequest)
   (com.yubico.webauthn.data ByteArray  PublicKeyCredentialCreationOptions PublicKeyCredential UserIdentity)
   (com.yubico.webauthn.exception AssertionFailedException)
   (java.time Instant)))

(set! *warn-on-reflection* true)

(defn- start-registration!
  [{::keys [^RelyingPartyV2 relying-party credentials sessions pending-registrations]}
   {:strs [username displayName nickname sessionId]}]
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
            creation-opts (.startRegistration relying-party start-opts)
            session-id (s/create-session sessions user-handle)
            registration-req (d/->RegistrationRequest request-id session-id username nickname creation-opts)]
        (log/info "Saving pending registration request for user" username "with id:" (.getBase64Url request-id))
        (swap! pending-registrations assoc request-id registration-req)
        {:success registration-req})
      {:error [(str username " is already in use. Please try another username.")]})))

(defn- store-registered-credential!
  [credentials & {:keys [^UserIdentity user ^String nickname ^RegistrationResult result]}]
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

(defn- finish-registration!
  [{::keys [^RelyingPartyV2 relying-party credentials sessions pending-registrations]} client-response]
  (let [json (-> client-response :body slurp)]
    (log/info "Finishing registration from response:" json)
    (try
      (let [{:strs [requestId credential] :as response} (some-> json json/read-json)
            request-id (some-> requestId ByteArray/fromBase64Url)
            {:keys [username nickname sessionId ^PublicKeyCredentialCreationOptions options] :as request} (some->> request-id (c/lookup pending-registrations))]
        (c/evict pending-registrations request-id)
        (if request
          (try
            (let [credential (i/RegistrationResponse->PublicKeyCredential credential)
                  registration (.finishRegistration relying-party (i/->FinishRegistrationOptions options credential))
                  user (some-> options .getUser)
                  user-handle (some-> user .getId)]
              (when (and (i/user-exists? credentials username)
                         (not (s/session-for-user? sessions sessionId user-handle)))
                (throw (ex-info "User already exists" {:username username} ::registration-failed)))
              (let [registered (store-registered-credential! credentials  {:user user
                                                                           :nickname nickname
                                                                           :result registration})]
                {:success (d/->SuccessfulRegistrationResult request response registered (.isAttestationTrusted registration) (s/create-session sessions user-handle))}))
            (catch clojure.lang.ExceptionInfo e
              (log/debug e "Registration failed with JSON:" json)
              {:error ["Registration failed." (ex-message e)]}))
          {:error ["Registration failed" "Failed to parse response JSON:" (log/spyf :error "Response JSON: %s" json) (log/spyf :error "Parsed: %s" response)]}))
      (catch Exception e
        (log/error e "Registration failed for request:" json)
        {:error ["Registration failed unexpectedly" (ex-message e)]}))))

(defn- start-assertion!
  [{::keys [^RelyingPartyV2 relying-party credentials pending-assertions]}
   {:strs [username] :as form}]
  {:post [(map? %) (let [[key & others] (keys %)]
                     (and (empty? others) (#{:success :error} key)))]}
  (log/info "Starting assertion for user:" username)
  (try
    (if (and (seq username) (not (i/user-exists? credentials username)))
      {:error [(str "The user" username "does not exist.")]}
      (let [request-id (u/random-bytes 32)
            assertion-opts (i/->StartAssertionOptions username)
            assertion-req (.startAssertion relying-party assertion-opts)
            request-opts (.getPublicKeyCredentialRequestOptions assertion-req)
            auth-req (d/->AuthenticationRequest request-id username request-opts assertion-req)]
        (log/info "Saving pending authentication request for user" username "with id:" (.getBase64Url request-id))
        (swap! pending-assertions assoc request-id auth-req)
        {:success auth-req}))
    (catch Exception e
      (log/error e "Failed to start assertion with form:" form)
      {:error ["Authentication failed unexpectedly" (ex-message e)]})))

(defn- finish-assertion!
  [{::keys [^RelyingPartyV2 relying-party credentials pending-assertions sessions]} client-request]
  {:post [(map? %) (let [[key & others] (keys %)]
                     (and (empty? others) (#{:success :error} key)))]}
  (let [json (-> client-request :body slurp)]
    (log/info "Finishing authentication from response:" json)
    (try
      (let [{:strs [requestId credential] :as response} (some-> json json/read-json)
            request-id (some-> requestId ByteArray/fromBase64Url)
            {:keys [username ^AssertionRequest request] :as cached-request} (some->> request-id (c/lookup pending-assertions))]
        (c/evict pending-assertions request-id)
        (if cached-request
          (try
            (let [^PublicKeyCredential credential (i/AssertionResponse->PublicKeyCredential credential)
                  auth-data (-> credential .getResponse .getParsedAuthenticatorData)
                  assertion-result (.finishAssertion relying-party (i/->FinishAssertionOptions request credential))
                  user-handle (-> assertion-result .getCredential .getUserHandle)]
              (if (.isSuccess assertion-result)
                (do
                  (try
                    (i/update-signature-count credentials assertion-result)
                    (catch Exception e
                      (log/error e "Failed to update signature count for user:" username "and assertion result:" assertion-result)))
                  {:success (d/->SuccessfulAuthenticationResult cached-request
                                                                (d/->AuthenticationResponse request-id credential)
                                                                (i/credentials-for-username credentials username)
                                                                auth-data
                                                                (s/create-session sessions user-handle))})
                {:error ["Authentication failed" "Invalid assertion"]}))
            (catch AssertionFailedException e
              (log/debug e "Assertion failed for response:" response "with request:" cached-request)
              {:error ["Authentication failed" (ex-message e)]}))
          {:error ["Authentication failed" "Failed to locate a matching request in progress."]}))
      (catch Exception e
        (log/error e "Authentication failed:" json)
        {:error ["Authentication failed unexpectedly" (ex-message e)]}))))

(defn make-relying-party
  [& {:keys [rp-name rp-id]}]
  (let [rp-identity (i/->RelyingPartyIdentity rp-id rp-name)
        credentials (i/->in-memory-credential-store)
        state {::relying-party (i/->RelyingParty rp-identity credentials)
               ::credentials credentials
               ::sessions  (s/->in-memory-session-manager :session-ttl-minutes 10)
               ::pending-registrations (u/new-cache :threshold 100 :ttl-ms (* 3 60 1000))
               ::pending-assertions (u/new-cache :threshold 100 :ttl-ms (* 3 60 1000))}
        handle-finish (fn [f]
                        (fn [req]
                          (try
                            (let [{:keys [success error]} (f state req)]
                              (if success
                                (u/success (json/write-json-str (assoc success :success true)) "application/json")
                                (u/error (json/write-json-str error) "application/json")))
                            (catch Exception e
                              (log/error e "failure when finishing" f "on" req)
                              (u/error (ex-message e))))))
        handle-start (fn [f]
                       (fn [req]
                         (try
                           (if-let [form (u/parse-form-params req)]
                             (let [{:keys [success error]} (f state form)]
                               (if success
                                 (u/success (json/write-json-str {:success true
                                                                  :request success})
                                            "application/json")
                                 (u/error (json/write-json-str error) "application/json")))
                             (u/error "Failed to parse form data."))
                           (catch Exception e
                             (log/error e "failure when starting" f "on" req)
                             (u/error (ex-message e))))))]
    {:start-registration (handle-start start-registration!)
     :finish-registration (handle-finish finish-registration!)
     :start-assertion (handle-start start-assertion!)
     :finish-assertion (handle-finish finish-assertion!)}))

(comment {:server-port int?
          :server-name string?
          :remote-addr string?
          :uri #"^/[\w~,.+\-]*$"
          :scheme #{:http :https}
          :protocol #{"HTTP/1.1" "HTTP/2.0"} ;; is it really always?
          :headers (into {} (repeatedly '(#"^[\w!#$%&'*+.`+~\^\-]+$"
                                          #"\b[\t \x21-\xff]*\b")))
          :request-method #{:get :post :put :delete :head
                            :patch :options :trace :connect}
          :query-string-? string?
          :body-? #(instance? java.io.InputStream %)})