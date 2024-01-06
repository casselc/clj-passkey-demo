(ns casselc.passkey-demo.sessions
  (:require 
   [clojure.tools.logging.readable :as log]
   [clojure.core.cache.wrapped :as c]
   [casselc.passkey-demo.util :refer [random-bytes new-cache]])
  (:import
   (com.yubico.webauthn.data ByteArray)))

(set! *warn-on-reflection* true)

(defprotocol SessionManager
  (create-session [this ^ByteArray user-handle])
  (user-for-session [this ^ByteArray session-id])
  (session-for-user? [this ^ByteArray session-id ^ByteArray user-handle]))

(defn ->in-memory-session-manager
  [& {:keys [^long session-ttl-minutes]}]
  (let [users-by-session (new-cache :ttl-ms (* session-ttl-minutes 60 1000))
        sessions-by-user (new-cache :ttl-ms (* session-ttl-minutes 60 1000))]
    (reify SessionManager
      (create-session
        [_ user-handle]
        (log/trace "Creating new session for" user-handle)
        (let [session-id (c/lookup-or-miss sessions-by-user user-handle (constantly (random-bytes 32)))]
          (swap! users-by-session assoc session-id user-handle)
          session-id))

      (user-for-session
        [_ session-id]
        (log/trace "Looking up session" session-id)
        (c/lookup users-by-session session-id))

      (session-for-user?
        [_ session-id user-handle]
        (log/tracef "Checking if session %s is for user %s" session-id user-handle)
        (when-let [cached-handle (c/lookup users-by-session session-id)]
          (= user-handle cached-handle))))))