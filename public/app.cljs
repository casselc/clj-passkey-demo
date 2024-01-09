(require '["@github/webauthn-json/browser-ponyfill" :as webauthn])

(def ^:squint.compiler/skip-var reg-username-input (js/document.getElementById "reg-username"))
(def display-name-input (js/document.getElementById "displayName"))
(def nickname-input (js/document.getElementById "credentialNickname"))
(def auth-username-input (js/document.getElementById "auth-username"))

(def session-text (js/document.getElementById "session"))
(def status-text (js/document.getElementById "status"))
(def messages (js/document.getElementById "messages"))
(def credentials (js/document.getElementById "credentials"))

(def device-info (js/document.getElementById "device-info"))
(def device-name (js/document.getElementById "device-name"))
(def device-nickname (js/document.getElementById "device-nickname"))
(def device-icon (js/document.getElementById "device-icon"))

(def debug-server (js/document.getElementById "server-response"))
(def debug-authenticator (js/document.getElementById "authenticator-response"))
(def debug-request (js/document.getElementById "request"))

(def register-button (js/document.getElementById "register"))
(def register-form (js/document.getElementById "register-form"))
(def authenticate-button (js/document.getElementById "authenticate"))
(def authenticate-form (js/document.getElementById "sign-in-form"))
(def logout-button (js/document.getElementById "logout"))

(def ^:private session {})

(defn- set-status
  [text]
  (set! (. status-text -textContent) text))

(defn- add-message
  [msg]
  (let [content (js/document.createTextNode msg)
        li (js/document.createElement "li")]
    (.appendChild li content)
    (.appendChild messages li)))

(defn- add-messages
  [msgs]
  (.forEach msgs add-message))

(defn- clear-children
  [parent]
  (loop [el (:firstChild parent)]
    (when el
      (.removeChild parent el)
      (recur (:firstChild parent)))))

(defn clear-messages
  []
  (clear-children messages))

(defn add-credential
  [cred])

(defn add-credentials
  [creds])

(defn clear-credentials
  []
  (clear-children credentials))

(defn- write-json
  [el data]
  (set! (. el -textContent) (js/JSON.stringify data false 2)))

(defn- display-request
  [data]
  (write-json debug-request data))

(defn- display-authenticator-response
  [data]
  (write-json debug-authenticator data))

(defn- display-server-response
  [data]
  (some-> data :messages add-messages)
  (write-json debug-server data))

(defn- hide-device-info
  []
  (set! (. device-info -hidden) true))

(defn- display-device-info
  [{:keys [nickname displayName imageUrl metadataStatement]}]
  (set! (. device-nickname -textContent) nickname)
  (set! (. device-name -textContent) (or  (:description metadataStatement) displayName))
  (set! (. device-icon -src) (or (:icon metadataStatement) imageUrl "")))

(defn reset-displays!
  []
  (clear-messages)
  (display-request nil)
  (display-authenticator-response nil)
  (display-server-response nil)
  (hide-device-info))

(defn- update-session
  [{:keys [success sessionId request] :as resp}]
  (js/console.info "Updating session with" resp)
  (if-let [username (and success (:username request))]
    (do
      (assoc! session :username username)
      (set! (. session-text -textContent) (str "Signed in as " username))
      (set! (. logout-button -disabled) false))
    (do
      (set! (. session-text -textContent) "Not signed in.")
      (set! (. logout-button -disabled) true)))
  (if sessionId
    (do
      (assoc! session :sessionId sessionId)
      (set! (. register-button -textContent) "Add a Passkey"))
    (set! (. register-button -textContent) "Register with a Passkey"))
  resp)

(defn- rejected
  [o]
  (js/Promise. (fn [_ reject] (reject o))))

(defn- reject-unsuccessful
  [resp]
  (if (:success resp)
    resp
    (rejected resp)))

(defn- extract-json [req] (.json req))

(defn- ^:async perform-ceremony!
  [{:keys [start-fn execute-fn error-fn finish-url status-msgs]
    :as params :or {error-fn js/console.error
                    status-msgs {:start "Starting ceremony..."
                                 :execute "Executing action on authenticator..."
                                 :submit "Submitting authenticator response to server..."
                                 :success "Ceremony finished successsfully!"
                                 :error "Ceremony failed."}}}]
  (js/console.info (:start status-msgs))
  (reset-displays!)
  (set-status (:start status-msgs))
  (try
    (let [{:keys [request]} (js-await (-> (start-fn)
                                          (.then extract-json)
                                          (.then update-session)
                                          (.then reject-unsuccessful)
                                          (.catch error-fn)))]

      (js/console.info (:execute status-msgs) request)
      (set-status (:execute status-msgs))
      (display-request request)
      (let [webauthn-resp (js-await (-> (execute-fn request)
                                        (.catch error-fn)))]
        (js/console.info (:submit status-msgs) webauthn-resp)
        (set-status (:submit status-msgs))
        (display-authenticator-response webauthn-resp)
        (let [{:keys [success] :as data} (js-await  (-> (js/fetch finish-url {:body (js/JSON.stringify {:requestId (:requestId request)
                                                                                                        :sessionId (or (:sessionId request) (:sessionId session))
                                                                                                        :credential webauthn-resp})
                                                                              :method "POST"})
                                                        (.then extract-json)
                                                        (.then update-session)
                                                        (.catch error-fn)))]
          (js/console.info data)
          (if success
            (set-status (:success status-msgs))
            (set-status (:error status-msgs)))
          (display-server-response data)
          data)))
    (catch :default e
      (error-fn e))))

(defn- ^:async perform-registration-ceremony!
  []
  (let [username (.-value reg-username-input)
        display-name (.-value display-name-input)
        nickname (.-value nickname-input)]
    (perform-ceremony! {:start-fn #(js/fetch "/register" {:body (let [params (js/URLSearchParams. {:username username
                                                                                                   :displayName (or display-name username)
                                                                                                   :nickname nickname})]
                                                                  (some->> session :sessionId (.append params "sessionId"))
                                                                  params)
                                                          :method "POST"})
                        :execute-fn #(-> % :options webauthn/parseCreationOptionsFromJSON webauthn/create)
                        :error-fn (fn [{:keys [name message messages] :as e}]
                                    (set-status "Registration failed")
                                    (js/console.error "Registration failed" e)
                                    (cond
                                      (= "NotAllowedError" name) (add-message "Credential creation failed, possibly because a previously registered credential is available.")
                                      (= "InvalidStateError" name) (add-message "This authenticator is already registered to the user, try again with a different authenticator.")
                                      (some? message) (add-message (str name ": " message))
                                      (seq messages) (add-messages messages)))
                        :finish-url "/register/finish"
                        :status-msgs {:start "Starting new credential registration..."
                                      :execute "Attempting to create credential on authenticator..."
                                      :submit "Submitting new credential to server..."
                                      :success "Credential registered successfully!"
                                      :error "Failed to register new credential"}})))

(defn- ^:async register
  [evt]
  (.preventDefault evt)
  (let [{:keys [success registration attestationTrusted]} (js-await (perform-registration-ceremony!))]
    (when success
      (let [info (merge {:nickname (:credentialNickname registration)}
                        (or (some-> (:attestationMetadata registration) :deviceProperties)
                            {}))]
        (display-device-info info))
      (when-not attestationTrusted
        (add-message "Warning: attestation is not trusted!")))))

(defn- ^:async perform-authentication-ceremony!
  []
  (let [username (.-value auth-username-input)]
    (perform-ceremony! {:start-fn #(js/fetch "/authenticate" {:body (js/URLSearchParams. (if (seq username) {:username username} {}))
                                                              :method "POST"})
                        :execute-fn #(-> % :options webauthn/parseRequestOptionsFromJSON webauthn/get)
                        :error-fn (fn [{:keys [name message messages] :as e}]
                                    (set-status "Authentication failed")
                                    (js/console.error "Authentication failed" e)
                                    (cond
                                      (= "InvalidStateError" name) (add-message "This authenticator is not registered to the user, try again with a valid authenticator.")
                                      (some? message) (add-message (str name ": " message))
                                      (seq messages) (add-messages messages)))
                        :finish-url "/authenticate/finish"
                        :status-msgs {:start "Starting authentication..."
                                      :execute "Requesting assertion from authenticator..."
                                      :submit "Submitting assertion to server..."
                                      :success "Authenticated successfully!"
                                      :error "Failed to authenticate"}})))

(defn- ^:async authenticate
  [evt]
  (.preventDefault evt)
  (let [{:keys [success registrations]} (js-await (perform-authentication-ceremony!))]
    (when success
      (add-message (str "Authenticated as" (some-> registrations first :username)))
      (add-credentials registrations))))

(defn- logout
  []
  (set! session {})
  (update-session {}))

(defn- deregister-credential
  [id]
  (add-message "Deregistering credential...")
  (-> (js/fetch "/deregister" {:body (js/URLSearchParams. {:credentialId id :sessionId (:sessionId session)})
                               :method "POST"})
      (.then extract-json)
      (.then update-session)
      (.then reject-unsuccessful)
      (.then (fn [{:keys [success droppedRegistration accountDeleted]}]
               (if success
                 (do
                   (add-message (str "Successfully deregistered" (:credential-nickname droppedRegistration id)))
                   (when accountDeleted
                     (add-message "Deregistered final credential and deleted account.")
                     (logout)))
                 (add-message "Deregistration failed."))))
      (.catch (fn [e]
                (set-status "Credential deregistration failed")
                (cond
                  (:message e) (add-message (str (:name e) ": " (:message e)))
                  (:messages e) (add-messages (:messages e)))
                (rejected e)))))


(defn- init []
  (set! (. reg-username-input -oninput) #(let [v (-> % :target :value)]
                                           (set! (. display-name-input -placeholder) v)
                                           (set! (. nickname-input -placeholder) (str v " @ " (.-origin js/location)))))
  (set! (. register-form -onsubmit) register)
  (set! (. authenticate-form -onsubmit) authenticate)
  #_(set! (. deregister-button -onclick) deregister)
  (set! (. logout-button -onclick) logout))

(init)