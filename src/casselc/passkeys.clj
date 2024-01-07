(ns casselc.passkeys
  (:require
   [clojure.tools.logging :as log]
   [casselc.passkeys.config :refer [read-config]]
   [casselc.passkeys.server :refer [start-server!]]
   [org.httpkit.server :as http])
  (:gen-class))

(set! *warn-on-reflection* true)

(defn -main [& args]
  (try
    (if (= "start-server" (first args))
      (let [stop (promise)
            server (atom nil)]
        (future
          (loop []
            (when-let [s @server]
              (log/info "Current server status:" (http/server-status s)))
            (Thread/sleep 30000)
            (recur)))
        (reset! server (start-server! (read-config)))
        @stop)
      (log/info (clojure-version)))
    (catch Exception e
      (log/fatal e))
    (finally (log/info "Shutting down..."))))