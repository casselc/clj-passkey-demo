(ns casselc.passkey-demo.interop
  (:require
   [clojure.set :as set]
   [clojure.tools.logging.readable :as log]
   [charred.api :as json]
   [clojure.java.data :as j]
   [casselc.passkey-demo.util :refer [random-bytes]])
  (:import
   (com.yubico.webauthn CredentialRepositoryV2 FinishRegistrationOptions FinishAssertionOptions AssertionRequest
                        RegisteredCredential RelyingParty  RelyingPartyV2 AssertionResultV2
                        StartAssertionOptions StartRegistrationOptions UsernameRepository)
   (com.yubico.webauthn.data AuthenticatorAssertionResponse AuthenticatorData AuthenticatorDataFlags AuthenticatorSelectionCriteria AuthenticatorTransport ByteArray CollectedClientData PublicKeyCredential PublicKeyCredentialCreationOptions RelyingPartyIdentity ResidentKeyRequirement UserIdentity PublicKeyCredentialRequestOptions ClientAssertionExtensionOutputs ClientRegistrationExtensionOutputs)
   (java.util Optional Set NoSuchElementException)))

(set! *warn-on-reflection* true)

(defmethod j/from-java ByteArray
  [^ByteArray ba] (.getBase64Url ba))

(defmethod j/from-java BigInteger
  [^BigInteger bi]
  (.toString bi 16))

(extend-protocol json/PToJSON
  Optional
  (json/->json-data [this] (.orElse this {}))

  java.math.BigInteger
  (json/->json-data [this] (.toString this 16))

  ByteArray
  (json/->json-data [this] (.getBase64Url this))

  AuthenticatorAssertionResponse
  (json/->json-data [this] (j/from-java-shallow this {:omit #{:clientDataJSON}}))

  AuthenticatorData
  (json/->json-data [this] (j/from-java-shallow this {}))

  AuthenticatorDataFlags
  (json/->json-data [this] {:user-present? (.-UP this)
                            :user-verified? (.-UV this)
                            :backup-eligible? (.-BE this)
                            :backed-up? (.-BS this)
                            :attested-data-present? (.-AT this)
                            :extension-data-present? (.-ED this)
                            :value (.-value this)})

  AuthenticatorTransport
  (json/->json-data [this] (j/from-java-shallow this {}))

  ClientAssertionExtensionOutputs
  (json/->json-data [this] (j/from-java-shallow this {}))

  ClientRegistrationExtensionOutputs
  (json/->json-data [this] (j/from-java-shallow this {}))

  CollectedClientData
  (json/->json-data [this] (j/from-java-shallow this {}))

  PublicKeyCredential
  (json/->json-data [this] (j/from-java-shallow this {}))

  RegisteredCredential
  (json/->json-data [this] (j/from-java-shallow this {}))

  UserIdentity
  (json/->json-data [this] (j/from-java-shallow this {}))

  PublicKeyCredentialCreationOptions
  (json/->json-data [this] (json/read-json (.toCredentialsCreateJson this)))

  PublicKeyCredentialRequestOptions
  (json/->json-data [this] (json/read-json (.toCredentialsGetJson this)))

  AssertionRequest
  (json/->json-data [this] (json/read-json (.toCredentialsGetJson this)))

  java.security.PublicKey
  (json/->json-data [this] (j/from-java-shallow this {:omit #{:algorithmId :encoded :encodedPublicValue :encodedInternal}}))

  java.security.spec.ECPoint
  (json/->json-data [this]
    {:affineX (str "0x" (-> this .getAffineX (.toString 16)))
     :affineY (str "0x" (-> this .getAffineY (.toString 16)))}))

(defprotocol CredentialStore
  (credentials-for-handle [this ^ByteArray user-handle])
  (credentials-for-username [this ^String username])
  (credential-for-username-with-id [this ^String username ^ByteArray credential-id])
  (add-credential-for-user [this ^String username registration])
  (drop-credential-for-user [this ^String username registration])
  (drop-user [this ^String username])
  (user-exists? [this ^String username])
  (update-signature-count [this ^AssertionResultV2 result]))

(defn ->UserIdentity
  ^UserIdentity [name display-name]
  (-> (UserIdentity/builder)
      (.name name)
      (.displayName display-name)
      (.id (random-bytes 32))
      .build))

(defn ->RelyingPartyIdentity
  ^RelyingPartyIdentity [id name]
  (-> (RelyingPartyIdentity/builder)
      (.id id)
      (.name name)
      .build))

(defn ->AuthenticatorSelectionCriteria
  ^AuthenticatorSelectionCriteria []
  (-> (AuthenticatorSelectionCriteria/builder)
      (.residentKey ResidentKeyRequirement/REQUIRED)
      .build))

(defn ->StartRegistrationOptions
  ^StartRegistrationOptions [user-identity]
  (-> (StartRegistrationOptions/builder)
      (.user user-identity)
      (.authenticatorSelection (->AuthenticatorSelectionCriteria))
      (.timeout 300000)
      .build))

(defn ->FinishRegistrationOptions
  ^FinishRegistrationOptions [pk-creation-options pk-credential]
  (-> (FinishRegistrationOptions/builder)
      (.request pk-creation-options)
      (.response pk-credential)
      .build))

(defn ->StartAssertionOptions
  ^StartAssertionOptions [^String username]
  (-> (StartAssertionOptions/builder)
      (.username username)
      .build))

(defn ->FinishAssertionOptions
  ^FinishAssertionOptions [assertion-req pk-credential]
  (-> (FinishAssertionOptions/builder)
      (.request assertion-req)
      (.response pk-credential)
      .build))

(defn ->RelyingParty
  ^RelyingPartyV2 [^RelyingPartyIdentity rp-identity credential-store]
  (-> (RelyingParty/builder)
      (.identity rp-identity)
      (.credentialRepositoryV2 credential-store)
      (.usernameRepository credential-store)
      (.allowOriginPort (= "localhost" (.getId rp-identity)))
      .build))

(defn ->RegisteredCredential
  ^RegisteredCredential [credential-id user-handle public-key signature-count]
  (-> (RegisteredCredential/builder)
      (.credentialId credential-id)
      (.userHandle user-handle)
      (.publicKeyCose public-key)
      (.signatureCount signature-count)
      .build))

(defn RegistrationResponse->PublicKeyCredential
  ^PublicKeyCredential
  [m]
  (-> m json/write-json-str PublicKeyCredential/parseRegistrationResponseJson))

(defn AssertionResponse->PublicKeyCredential
  ^PublicKeyCredential
  [m]
  (-> m json/write-json-str PublicKeyCredential/parseAssertionResponseJson))

(defn ->in-memory-credential-store
  ([]
   (->in-memory-credential-store (atom {::user-registrations {}})))
  ([store]
   (let [registrations #(@store ::user-registrations)
         all-creds #(->> (registrations) vals (apply set/union))]
     (reify
       CredentialStore
       (credentials-for-handle [_ user-handle]
         (let [creds (all-creds)]
           (log/trace "Getting all registered credentials for user" (.getBase64Url ^ByteArray user-handle) "from" creds)
           (set/select (fn [{:keys [^UserIdentity user]}] (= user-handle (.getId user))) creds)))

       (credentials-for-username [_ username]
         (let [regs (registrations)]
           (log/trace "Getting all registered credentials for" username "from" regs)
           (regs username #{})))

       (credential-for-username-with-id [_ username id]
         (let [regs (registrations)]
           (log/trace "Looking up registered credentials for" username "from" regs)
           (some (fn [{:keys [^RegisteredCredential credential] :as registration}]
                   (when (= id (.getCredentialId credential)) registration))
                 (regs username))))

       (add-credential-for-user
         [_ username registration]
         (log/trace "Adding registration for" username ":" registration)
         (swap! store update-in [::user-registrations username] (fn [old new] (if (seq old) (conj old new) #{new})) registration))

       (drop-credential-for-user
         [_ username registration]
         (log/trace "Dropping registration for" username ":" registration)
         (swap! store update-in [::user-registrations username] disj registration))

       (drop-user
         [_ username]
         (log/trace "Dropping" username)
         (swap! store update ::user-registrations dissoc username))

       (user-exists?
         [_ username]
         (boolean ((registrations) username)))

       (update-signature-count
         [this assertion-result]
         (let [{:keys [^UserIdentity user ^RegisteredCredential credential]} (.getCredential ^AssertionResultV2 assertion-result)
               username (.getName user)
               credential-id (.getCredentialId credential)
               {stored-cred :credential :as stored-reg} (credential-for-username-with-id this username credential-id)]
           (log/trace "Updating signature count for:" stored-reg)
           (if stored-reg
             (swap! store update-in [::user-registrations username] (fn [regs]
                                                                      (let [updated-cred (-> stored-cred .toBuilder (.signatureCount (.getSignatureCount ^AssertionResultV2 assertion-result)) .build)
                                                                            updated-reg (assoc stored-reg :credential updated-cred)]
                                                                        (log/trace "Removing" stored-reg "and inserting" updated-reg)
                                                                        (-> regs
                                                                            (disj stored-reg)
                                                                            (conj updated-reg)))))
             (throw (ex-info "Credential is not registered to user." {:username username :credential credential-id} (NoSuchElementException. (str credential-id " is not registered to " username)))))))

       CredentialRepositoryV2
       (credentialIdExists [_ credential-id]
         (let [creds (all-creds)]
           (log/trace "Checking if" (.getBase64Url credential-id) "exists in" creds)
           (->> creds
                (set/select (fn [{:keys [^RegisteredCredential credential]}]
                              (= credential-id (.getCredentialId credential))))
                seq
                boolean)))

       (getCredentialDescriptorsForUserHandle
         [this user-handle]
         (log/trace "Getting descriptors for" (some-> user-handle .getBase64Url))
         (let [user-creds (credentials-for-handle this user-handle)
               result (if (seq user-creds)
                        user-creds
                        (Set/of))]
           result))

       (lookup
         [_ credential-id user-handle]
         (let [creds (all-creds)]
           (log/trace "Looking up credential for user" (.getBase64Url user-handle) "with id" (.getBase64Url credential-id) "in" creds)
           (->> creds
                (set/select (fn [{:keys [^RegisteredCredential credential]}]
                              (and (= user-handle (.getUserHandle credential))
                                   (= credential-id (.getCredentialId credential)))))
                first
                Optional/ofNullable)))

       UsernameRepository
       (getUserHandleForUsername
         [_ username]
         (log/trace "Getting user handle for" username)
         (Optional/ofNullable
          (when-first [{:keys [^UserIdentity user]} ((registrations) username)]
            (.getId user))))

       (getUsernameForUserHandle
         [this user-handle]
         (log/trace "Getting user name for" (.getBase64Url user-handle))
         (when-first [{:keys [^UserIdentity user]} (credentials-for-handle this user-handle)]
           (.getName user)))))))