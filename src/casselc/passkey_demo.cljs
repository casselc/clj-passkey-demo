(ns casselc.passkey-demo
  (:require 
   ["@github/webauthn-json/browser-ponyfill" :refer [create get supported parseCreationOptionsFromJSON]]))

(def session {})

(defonce ^:private username-input (js/document.getElementById "username"))
(defonce ^:private display-name-input (js/document.getElementById "displayName"))
(defonce ^:private nickname-input (js/document.getElementById "credentialNickname"))

(defonce ^:private status-text (js/document.getElementById "statusText"))

(defonce ^:private register-button (js/document.getElementById "register"))
(defonce ^:private authenticate-button (js/document.getElementById "authenticate"))
(defonce ^:private logout-button (js/document.getElementById "logout"))
(defonce ^:private deregister-button (js/document.getElementById "deregister"))
(defonce ^:private delete-button (js/document.getElementById "delete"))

(defn- update-session
  [{:keys [username sessionToken] :as resp}]
  (println "Updating session with" resp)
  (if username
    (do
      (assoc! session :username username)
      (set! (. status-text -textContent) (str "Logged in as" username))
      (set! (. logout-button -disabled) false))
    (do
      (set! (. status-text -textContent) "Not logged in.")
      (set! (. logout-button -disabled) true)))
  (if sessionToken
    (do
      (assoc! session :token sessionToken)
      (set! (. register-button -textContent) "Add passkey"))
    (set! (. register-button -textContent) "Create account with passkey"))
  resp)

(defn- rejected
  [o]
  (js/Promise. (fn [_ reject] (reject o))))

(defn- reject-unsuccessful
  [resp]
  (print "rej un:" resp)
  (if (.-success resp)
    resp
    (rejected resp)))


(defn- extract-json [req] (.json req))

(defn- start-register-request!
  [username display-name nickname]
  (js/fetch "/register" {:body (js/URLSearchParams. {:username username
                                                     :displayName (or display-name username)
                                                     :credentialNickname nickname
                                                     :requireResidentKey true
                                                     :sessionToken (:token session)})
                         :method "POST"}))

(defn- finish-register-request!
  [req resp]
  (let [id (get-in req [:publicKey :user :id])]
    (println "Finishing registration for" id req)
    (js/fetch "/register/finish" {:body (js/JSON.stringify {:requestId id 
                                                            :sessionToken (or (.-sessionToken req) (:token session))
                                                            :credential resp})
                                  :method "POST"})))

(defn- ^:async perform-registration-ceremony!
  [username display-name nickname]
  (let [create-req (js-await (-> (start-register-request! username display-name nickname)
                                 (.then extract-json)
                                 (.then update-session) 
                                 #_(.catch (fn [e]
                                           (println "Register failed with" e)))))
        create-resp (js-await (-> create-req
                                  parseCreationOptionsFromJSON
                                  create))
        reg-resp (js-await (finish-register-request! create-req create-resp))]
    reg-resp))

(defn authenticate [])

(defn ^:async register
  [evt]
  (let [username (.-value username-input)
        display-name (.-value display-name-input)
        nickname (.-value nickname-input)
        data (js-await (perform-registration-ceremony! username display-name nickname))]
    (println "Registration finished with" data)))

(defn deregister [])

(defn delete-account [])

(defn logout
  []
  (set! session {})
  (update-session {}))

(set! (. register-button -onclick) register)