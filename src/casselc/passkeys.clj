(ns casselc.passkeys
  (:require
   [clojure.tools.logging.readable :as log]
   [casselc.passkeys.config :refer [read-config]]
   [casselc.passkeys.server :refer [start-server!]])
  (:gen-class))

(set! *warn-on-reflection* true)

(defn -main [& args]
  (try
    (if (= "start-server" (first args))
      (do
        (start-server! (read-config))
        @(promise))
      (log/info (clojure-version)))
    (catch Exception e
      (log/fatal e))
    (finally (log/info "Shutting down..."))))