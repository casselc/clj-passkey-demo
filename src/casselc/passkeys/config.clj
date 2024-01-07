(ns casselc.passkeys.config
  (:require [clojure.tools.logging.readable :as log]))

(set! *warn-on-reflection* true)

(def ^:private env-config
  (delay (let [cfg {:host (or (System/getenv "HOST") "localhost")
                    :port (or (some-> (System/getenv "PORT")
                                      parse-long)
                              8090)
                    :rp-name (or (System/getenv "RP_NAME") "Clojure Passkey Demo")
                    :rp-id (or (System/getenv "RP_ID") "localhost")}]
           (log/info "Read configuration from environment:" cfg)
           cfg)))

(defn read-config [] @env-config)