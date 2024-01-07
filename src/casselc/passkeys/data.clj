(ns casselc.passkeys.data
  (:import
   (com.yubico.webauthn AssertionRequest CredentialRecord RegisteredCredential RegistrationResult ToPublicKeyCredentialDescriptor )
   (com.yubico.webauthn.data ByteArray PublicKeyCredential PublicKeyCredentialDescriptor PublicKeyCredentialCreationOptions PublicKeyCredentialRequestOptions UserIdentity   )
   (java.time Instant)
   (java.util Optional Set)))

(defrecord CredentialRegistration [^UserIdentity user ^String nickname ^RegisteredCredential credential transports ^Instant registered-ts]
  CredentialRecord
  (getCredentialId [_] (.getCredentialId credential))
  (getUserHandle [_] (.getId user))
  (getPublicKeyCose [_] (.getPublicKeyCose credential))
  (getSignatureCount [_] (.getSignatureCount credential))
  (getTransports [_] (Optional/ofNullable (some-> transports into-array Set/of)))
  (isBackupEligible [_] (.isBackupEligible credential))
  (isBackedUp [_] (.isBackedUp credential))

  ToPublicKeyCredentialDescriptor
  (toPublicKeyCredentialDescriptor [_] (-> (PublicKeyCredentialDescriptor/builder) (.id (.getCredentialId credential)) (.transports ^Optional transports) (.build))))

(defrecord RegistrationRequest [^ByteArray requestId ^ByteArray sessionId ^String username ^String nickname ^PublicKeyCredentialCreationOptions options])
(defrecord RegistrationResponse [^ByteArray requestId ^ByteArray sessionId ^String nickname ^PublicKeyCredential credential])
(defrecord SuccessfulRegistrationResult [^RegistrationRequest request ^RegistrationResponse response ^CredentialRegistration registration ^boolean attestation-trusted? ^ByteArray sessionId])

(defrecord AuthenticationRequest [^ByteArray requestId  ^String username ^PublicKeyCredentialRequestOptions options ^AssertionRequest request])
(defrecord AuthenticationResponse [^ByteArray requestId  ^PublicKeyCredential credential])

(defrecord SuccessfulAuthenticationResult [^AuthenticationRequest request ^AuthenticationResponse response registrations authData  ^ByteArray sessionId])
