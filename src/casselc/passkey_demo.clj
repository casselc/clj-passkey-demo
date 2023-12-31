(ns casselc.passkey-demo
  (:require 
   [org.httpkit.server :as server]
   [ruuter.core :as ruuter]
   [clojure.java.io :as io]
   [ring.util.codec :as codec]
   [charred.api :as json]
   [clojure.java.data :as j]
   [clojure.tools.logging.readable :as log])
  (:import (com.yubico.webauthn CredentialRecord CredentialRepositoryV2 RelyingParty RelyingPartyV2 StartRegistrationOptions FinishRegistrationOptions)
           (com.yubico.webauthn.data ByteArray PublicKeyCredential RelyingPartyIdentity  UserIdentity)
           (java.security SecureRandom)
           (java.util Optional Set))
  (:gen-class))

(set! *warn-on-reflection* true)

(defmethod j/from-java ByteArray
  [^ByteArray ba]
  (.getBase64Url ba))



(def port (or (some-> (System/getenv "PORT")
                      parse-long)
              8090))

(def rp-name (or (System/getenv "RP_NAME") "Clojure Passkey Demo"))
(def rp-id (or (System/getenv "RP_ID") "localhost"))

(def ^SecureRandom random (let [seed (-> (SecureRandom.) (.generateSeed 32))]
              (SecureRandom. seed)))

(defn- random-bytes
  [n]
  (let [bs (byte-array n)]
    (.nextBytes random bs)
    bs))

(def rp-identity (-> (RelyingPartyIdentity/builder)
                     (.id rp-id)
                     (.name rp-name)
                     (.build)))

(def store (atom {:creds-by-id {}
                  :creds-by-handle {}
                  :registration-reqs {}}))

(defn ->in-memory-credential-store
  []
  (reify
    CredentialRepositoryV2
    (credentialIdExists [_ credential-id]
      (let [id (.getBase64Url credential-id)
            s @store]
        (log/info "Checking if" id "exists in" (:creds-by-id s))
        (some? (get-in s [:creds-by-id id]))))

    (getCredentialDescriptorsForUserHandle [_ user-handle]
      (let [s @store]
        (log/info "Getting credentials for" user-handle "from" s)
        (if-let [creds (get-in s [:creds-by-handle user-handle])]
          (-> creds into-array Set/of)
          (Set/of))))

    (lookup [_ credential-id user-handle]
      (log/info "Looking up credential" credential-id "for" user-handle "from" store)
      (Optional/ofNullable
       (when-let [cred ^CredentialRecord (get-in @store [:creds-by-id credential-id])]
         (when (= user-handle (.getUserHandle cred))
           cred))))))

(def ^RelyingPartyV2 rp (-> (RelyingParty/builder)
                            (.identity rp-identity)
                            (.credentialRepositoryV2 (->in-memory-credential-store))
                            (.allowOriginPort true)
                            (.build)))

(defn ->user-identity
  [name display-name] 
  (-> (UserIdentity/builder)
      (.name name)
      (.displayName display-name)
      (.id (ByteArray. (random-bytes 32)))
      (.build)))


(defn ->registration-opts
  [name display-name]
  (let [opts (-> (StartRegistrationOptions/builder)
                 (.user (->user-identity name display-name))
                 (.timeout 300000)
                 (.build))
        id (-> opts .getUser .getId .getBase64Url)
        req (.startRegistration rp opts)]
    (swap! store assoc-in [:registration-reqs id] req)
    (log/info "Saved pending registration request for" id)
    (.toCredentialsCreateJson req)))

(defonce index-content (delay (slurp (io/resource "index.html"))))
(defonce app-content (delay (when-let [js (io/resource "app.mjs")]
                              (slurp js))))

(defn- form-params
  [{:keys [^String content-type character-encoding body] :or {character-encoding "UTF-8"}}]
  (when (.startsWith content-type "application/x-www-form-urlencoded") 
    (-> body
        (slurp :encoding character-encoding)
        (codec/form-decode character-encoding))))

(defn- start-registration!
  [req]
  (if-let [{:strs [username displayName credentialNickname sessionToken] :as form} (form-params req)]
    {:status 200
     :headers {"Content-Type" "application/json"}
     :body (->registration-opts username displayName)}
    {:status 500}))

#_#_(def sessions (atom {:by-session-id {}
                     :by-user-handle {}}))

(defn- create-session
  [^ByteArray user-handle]
  
  )

(defn- start-server!
  [port]
  (server/run-server
   #(ruuter/route
     [{:path "/"
       :method :get
       :response {:status 200
                  :headers {"Content-Type" "text/html"}
                  :body @index-content}}
      {:path "/public/app.mjs"
       :method :get
       :response {:status 200
                  :headers {"Content-Type" "text/javascript"}
                  :body @app-content}}
      {:path "/register"
       :method :post
       :response start-registration!}
      {:path "/register/finish"
       :method :post
       :response (fn [req]
                   (let [{:strs [requestId credential sessionToken]} (-> req :body json/read-json)
                         reg-resp (PublicKeyCredential/parseRegistrationResponseJson (json/write-json-str credential))]
                     (when-let [reg-req (get-in @store [:registration-reqs requestId])]
                       (log/info "Finishing registration request for" requestId)
                       (let [opts (-> (FinishRegistrationOptions/builder)
                                      (.request reg-req)
                                      (.response reg-resp)
                                      .build)
                             result (.finishRegistration rp opts)]
  
                         {:status 500
                          :body (json/write-json-str (j/from-java result))}))))}
  
  
      {:path "/authenticate"
       :method :post}
      {:path "/authenticate/finish"
       :method :post}
      {:path "/user-admin/deregister-credential"
       :method :post}
      {:path "/user-admin/delete-account"
       :method :delete}]
     %)
   {:port port})
  )

(comment 
  (def server (start-server! 8090))
  
  (server)
  )

(defn -main [& _args]
  (start-server! port) 
  (log/info "Site running on" (str "http://localhost:" port)))