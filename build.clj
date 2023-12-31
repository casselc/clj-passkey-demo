(ns build
  (:refer-clojure :exclude [test])
  (:require [clojure.tools.build.api :as b]
            [squint.compiler :as squint]
            [clojure.java.io :as io]))

(def lib 'io.github.casselc/passkey-demo)
(def version "0.1.0-SNAPSHOT")
(def main 'casselc.passkey-demo)
(def class-dir "target/classes")

(defn test "Run all the tests." [opts]
  (let [basis    (b/create-basis {:aliases [:test]})
        cmds     (b/java-command
                  {:basis     basis
                   :main      'clojure.main
                   :main-args ["-m" "cognitect.test-runner"]})
        {:keys [exit]} (b/process cmds)]
    (when-not (zero? exit) (throw (ex-info "Tests failed" {}))))
  opts)

(defn- uber-opts [{:keys [uber-file] :as opts}]
  (assoc opts
         :lib lib 
         :main main
         :uber-file (or (some-> uber-file str) (format "target/%s-%s.jar" lib version))
         :basis (b/create-basis {})
         :class-dir class-dir
         :src-dirs ["src"]
         :ns-compile [main]))

(defn cljs
  [_opts]
  (println "Compiling CLJS...")
  (b/delete {:path "target/js"})
  (io/make-parents "target/js/app.js") 
  (spit "target/js/app.mjs" (squint/compile-string (slurp "src/casselc/passkey_demo.cljs"))))

(defn uber "Build an uberjar"  [opts]
  (b/delete {:path "target"})
  (let [opts (uber-opts opts)]
    (cljs opts)
    (println "\nCopying source...") 
    (b/copy-dir {:src-dirs ["target/js" "resources" "src"] :target-dir class-dir})
    (println (str "\nCompiling " main "..."))
    (b/compile-clj opts)
    (println "\nBuilding JAR...")
    (b/uber opts))
  opts)

(defn ci "Run the CI pipeline of tests (and build the uberjar)." [opts]
  (test opts)
  (uber opts)
  opts)