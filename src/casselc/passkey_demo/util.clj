(ns casselc.passkey-demo.util
  (:require
   [clojure.core.cache :as cache]
   #_[clojure.core.cache.wrapped :as wrapped]
   [ring.util.codec :as codec])
  (:import
   (com.yubico.webauthn.data ByteArray)
   (java.security SecureRandom)))

(let [random (SecureRandom.)]
  (defn random-bytes
    ^ByteArray [n]
    (let [bs (byte-array n)]
      (.nextBytes random bs)
      (ByteArray. bs))))

(comment (random-bytes 32))

(defn new-cache
  [& [{:keys [threshold ttl-ms]
       :or {threshold 1000
            ttl-ms 60000}}]]
  (-> {} (cache/fifo-cache-factory :threshold threshold) (cache/ttl-cache-factory :ttl ttl-ms) atom))

(defn parse-form-params
  [{:keys [^String content-type character-encoding body] :or {character-encoding "UTF-8"}}]
  (when (.startsWith content-type "application/x-www-form-urlencoded")
    (-> body
        (slurp :encoding character-encoding)
        (codec/form-decode character-encoding))))

