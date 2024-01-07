(ns casselc.passkeys.server
  (:require [clojure.java.io :as io]
            [clojure.tools.logging :as log]
            [org.httpkit.server :as http]
            [casselc.passkeys.util :as u]
            [casselc.passkeys.webauthn :refer [make-relying-party]]))

(set! *warn-on-reflection* true)

(defn- static-content
  [path content-type]
  #(or (some-> path io/resource io/input-stream (u/success content-type))
       (some-> (str "./public/" path) io/input-stream (u/success content-type))
       u/gone))

(defonce ^:private index-content (static-content "index.html" "text/html"))
(defonce ^:private app-content (static-content "app.js" "application/javascript"))
(defonce ^:private css-content (static-content "base.css" "text/css"))

(defn- make-relying-party-router
  [& {:keys [start-registration finish-registration start-assertion finish-assertion] :as config}]
  (fn [{:keys [uri request-method] :as req}]
    (log/info "Routing" request-method uri)
    (try
      (case [request-method uri]
        ([:get "/"]
         [:get "/index.html"]) (index-content)
        [:get "/app.js"] (app-content)
        [:get "/base.css"] (css-content)
        [:post "/register"] (start-registration req)
        [:post "/register/finish"] (finish-registration req)
        [:post "/authenticate"] (start-assertion req)
        [:post "/authenticate/finish"] (finish-assertion req)
        [:get "/status"] (u/success (str "Clojure Version:" (clojure-version)))
        u/gone)
      (catch Exception e
        (-> e ex-message u/error)))))

(def ^:private server (atom nil))

(let [start-opts {:server-header "Clojure Passkey Demo"
                  :warn-logger #(log/warn %2 %1)
                  :error-logger #(log/error %2 %1)
                  :event-logger #(log/trace %)}
      start (fn [{:keys [host port] :as config}]
              (let [rp (make-relying-party config)
                    router (make-relying-party-router rp)
                    s (http/run-server router (assoc start-opts :port port))]
                (log/info "Started server:" (http/server-status s))
                (reset! server s)))]
  (defn start-server!
    [config]
    (if-let [s @server]
      (if (= :stopped (http/server-status s))
        (start config)
        (do
          (log/warn "Ignoring request to start server, current instance is still running or stopping." s)
          s))
      (start config))))