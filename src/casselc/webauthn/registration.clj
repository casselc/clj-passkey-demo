(ns casselc.webauthn.registration
  "Implements the registration ceremony from §7.1 of the WebAuthn API spec
   at https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential"
  (:require [charred.api :as json])
  (:import
   (java.net URI)
   (java.security MessageDigest)
   (java.util Base64)))

(def ^:private nonempty-str? (every-pred string? seq))
(def ^:private nonempty-seq? #(some->> % seq (apply nonempty-str?)))
(def ^:private str-or-seq? #(or (nonempty-str? %) (nonempty-seq? %)))
(def ^:private b64-url-str? (every-pred string? #(re-find #"^[a-zA-Z0-9_\-]$" %)))
(def ^:private b64-url-seq? #(some->> % seq (apply b64-url-str?)))

(defn- create-registration-options
  "In order to perform a registration ceremony the Relying Party MUST proceed as follows:
   
   1. Let options be a new PublicKeyCredentialCreationOptions structure configured to the Relying Party's needs for the ceremony."
  [])

(comment
  "The value returned from `create-registration-options` should be associated with the user session for later retrieval and returned 
   to the user's browser to continue with step 2 on the client."

  "2. Call navigator.credentials.create() and pass options as the publicKey option. 
        Let `credential` be the result of the successfully resolved promise.
        If the promise is rejected:
        - abort the ceremony with a user-visible error,
        - or otherwise guide the user experience as might be determinable from the context available in the rejected promise. 
        For example if the promise is rejected with an error code equivalent to 'InvalidStateError', the user might be instructed to use a different authenticator.
   For information on different error contexts and the circumstances leading to them, see §6.3.2 The authenticatorMakeCredential Operation.")

(declare do-cbor validate-registration-options ->hex-str UP? UV? AT? ED? BE? BS?)


(defn verify-registration-response
  "The parameters `options` and `credential` should be the original return value from `xxx` and the `RegistrationResponseJSON` from the authenticator as a stream, byte[], or UTF8 string 
   as described by steps 1 and 2 of the registration ceremony
   
   From https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson:
        dictionary RegistrationResponseJSON {
          required Base64URLString id;
          required Base64URLString rawId;
          required AuthenticatorAttestationResponseJSON response;
          DOMString authenticatorAttachment;
          required AuthenticationExtensionsClientOutputsJSON clientExtensionResults;
          required DOMString type;
        };"
  [& {:keys [options credential]}]
  {:pre (fn [{{:keys [challenge origin top-origin rp-id type]} :options}]
          (assert (or (nonempty-str? challenge) (ifn? challenge) "challenge should be a string or a function from string to boolean"))
          (assert (str-or-seq? origin) "origin should be a string or collection of strings")
          (when top-origin
            (assert (str-or-seq? origin) "top-origin should be a string or collection of strings"))
          (when rp-id (assert (str-or-seq? rp-id) "rp-id should be a string or collection of strings"))
          (when type (assert (str-or-seq? type) "type should be a string or collection of strings")))}
  (let [;; Destructure and validate `credential` as a `RegistrationResponse`
        ;; From https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson:
        ;;   dictionary RegistrationResponseJSON
        credential (let [{:strs [id rawId response authenticatorAttachment clientExtensionResults type]
                          :as parsed} (json/read-json credential)]
                     (try
                       (assert (b64-url-str? id) "id should be a valid base64URL-encoded string") ;; required Base64URLString id;
                       (assert (b64-url-str? rawId) "rawId should be a valid base64URL-encoded string") ;; required Base64URLString rawId;
                       (assert response "response should be non-null") ;; required AuthenticatorAttestationResponseJSON response;
                       (when authenticatorAttachment ;; DOMString authenticatorAttachment;
                         (assert (b64-url-str? authenticatorAttachment) "authenticatorAttachment should be a valid base64URL-encoded string"))
                       (assert clientExtensionResults "clientExtensionResults should be non-null") ;; required AuthenticationExtensionsClientOutputsJSON clientExtensionResults;
                       (assert (b64-url-str? type) "type should be a valid base64URL-encoded string") ;; required DOMString type;
                       parsed
                       (catch AssertionError e
                         (throw (ex-info "Invalid credential registration response"
                                         {:credential (.toString credential)
                                          :parsed-credential parsed}
                                         e)))))
        ;; 3. Let response be credential.response.
        ;;    If response is not an instance of AuthenticatorAttestationResponse, abort the ceremony with a user-visible error.
        ;; From https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorattestationresponsejson:
        ;;   dictionary AuthenticatorAttestationResponseJSON {
        ;;     required Base64URLString clientDataJSON;
        ;;     required Base64URLString authenticatorData;
        ;;     required sequence<DOMString> transports;
        ;;     // The publicKey field will be missing if pubKeyCredParams was used to
        ;;     // negotiate a public-key algorithm that the user agent doesn't
        ;;     // understand. (See section “Easily accessing credential data” for a
        ;;     // list of which algorithms user agents must support.) If using such an
        ;;     // algorithm then the public key must be parsed directly from
        ;;     // attestationObject or authenticatorData.
        ;;     Base64URLString publicKey;
        ;;     required long long publicKeyAlgorithm;
        ;;     // This value contains copies of some of the fields above. See
        ;;     // section “Easily accessing credential data”.
        ;;     required Base64URLString attestationObject;
        ;;   };"
        response (let [response (:response credential)
                       {:strs [clientDataJSON authenticatorData transports publicKey publicKeyAlgorithm attestationObject]
                        :as parsed} (json/read-json response)]
                   (try
                     (assert (b64-url-str? clientDataJSON) "clientDataJSON should be a valid base64URL-encoded string")
                     (assert (b64-url-str? authenticatorData) "authenticatorData should be a valid base64URL-encoded string")
                     (assert (b64-url-seq? transports) "transports should be a collection of one or more valid base64URL-encoded strings")
                     (when publicKey
                       (assert (b64-url-str? publicKey) "publicKey should be a valid base64URL-encoded string"))
                     (assert (some-> publicKeyAlgorithm bigint) "publicKeyAlgorithm should be a valid bigint")
                     (assert (b64-url-str? attestationObject) "attestationObject should be a valid base64URL-encoded string")
                     parsed
                     (catch AssertionError e
                       (throw (ex-info "Registration ceremony failed at step 3, validating the AuthenticatorAttestationResponse"
                                       {:response response
                                        :parsed-response parsed}
                                       e)))))
        ;; 4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
        ;; From https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-getclientextensionresults:
        ;;   This operation returns the value of [[clientExtensionsResults]], which is a map containing
        ;;    extension identifier → client extension output entries produced by the extension's client extension processing.
        ;; Set of known identifiers taken from https://www.iana.org/assignments/webauthn/webauthn.txt on 2024-01-09, last updated 2023-09-13"
        known-extensions #{"appid" "txAuthSimple" "txAuthGeneric" "authnSel" "exts" "uvi" "loc"
                           "uvm" "credProtect" "credBlob" "largeBlobKey" "minPinLength" "hmac-secret"
                           "appidExclude" "credProps" "largeBlob" "payment"}
        client-extension-results (let [results (response "clientExtensionsResults")]
                                   (try
                                     (assert (and (map? results)
                                                  (every? known-extensions (keys results)))
                                             "clientExtensionsResults should be map with valid extension ids as keys\n(http://www.iana.org/assignments/webauthn/webauthn.txt)")
                                     results
                                     (catch AssertionError e
                                       (throw (ex-info "Registration ceremony failed at step 4, validating the clientExten"
                                                       {:extension-results results
                                                        :known-extension-ids known-extensions}
                                                       e)))))
        ;; 5. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
        ;; NOTE: Using any implementation of UTF-8 decode is acceptable as long as it yields the same result as that yielded by the UTF-8 decode algorithm. 
        ;; In particular, any leading byte order mark (BOM) MUST be stripped.
        b64 (Base64/getUrlDecoder)
        client-data-bytes (->> "clientDataJSON" response (.decode b64))
        json-text (let [str-start (if (#{(byte 0xBB) (byte 0xBF) (byte 0xEF)} (aget client-data-bytes 0)) 1 0)]
                    (String. client-data-bytes str-start (- (alength client-data-bytes) str-start) "UTF-8"))
        ;; 6. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
        ;; NOTE: C may be any implementation-specific data structure representation, as long as C's components are referenceable, as required by this algorithm.
        c (json/read-json json-text)
        ;; 7. Verify that the value of C.type is webauthn.create.
        _step-7 (when-not (= "webauth.create" (c "type"))
                  (throw (ex-info "Registration ceremony failed at step 7, expected `C.type` = 'webauthn.create'"
                                  {:C c})))
        ;; 8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
        response-challenge (c "challenge")
        expected-challenge (options "challenge")
        _step-8 (when-not (= expected-challenge response-challenge)
                  (throw (ex-info "Registration ceremony failed at step 8, expected `C.challenge` = `options.challenge`"
                                  {:challenge response-challenge
                                   :expected-challenge expected-challenge})))
        ;; 9. Verify that the value of C.origin is an origin expected by the Relying Party. See §13.4.9 Validating the origin of a credential for guidance.
        response-origin (c "origin")
        expected-origin (set (options :origin))
        _step-9 (when-not (expected-origin response-origin)
                  (throw (ex-info "Registration ceremony failed at step 9, expected `C.origin` \\in `options.origin`"
                                  {:origin response-origin
                                   :expected-origin expected-origin})))
        ;; 10. If C.topOrigin is present:
        ;;   10.1. Verify that the Relying Party expects that this credential would have been created within an iframe that is not same-origin with its ancestors.
        ;;   10.2. Verify that the value of C.topOrigin matches the origin of a page that the Relying Party expects to be sub-framed within. See §13.4.9 Validating the origin of a credential for guidance.
        response-top (c "topOrigin")
        expected-top (options :top-origin)
        expected-top (if (string? expected-top)
                       expected-top
                       (set expected-top))
        _step-10 (when (and response-top
                            (not (expected-top response-top)))
                   (throw (ex-info "Registration ceremony failed at step 10, expected `C.topOrigin` \\in `options.topOrigin`"
                                   {:top response-top
                                    :expected-top expected-top})))
        ;;11. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
        sha256 (MessageDigest/getInstance "SHA256")
        client-data-hash (.digest sha256 client-data-bytes)
        ;; 12. Perform CBOR decoding on the attestationObject field of the 
        ;;     AuthenticatorAttestationResponse structure to obtain the attestation
        ;;     statement format fmt, the authenticator data authData, and the
        ;;     attestation statement attStmt.
        attestation-obj (response "attestationObject")
        {:strs [fmt authData attStmt]} (do-cbor attestation-obj)
        ;; 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
        response-rp-hash (authData "rpIdHash")
        rp-id (options :rp-id)
        expected-rp-hash (.digest sha256 (.getBytes rp-id "UTF-8"))
        _step-13 (when-not (= (seq expected-rp-hash) (seq response-rp-hash))
                   (throw (ex-info "Registration ceremony failed at step 13, expected `attStmt.rpIdHash` = `sha256(options.rp-id)`"
                                   {:rp-id-hash (response-rp-hash)
                                    :expected-rp-id-hash expected-rp-hash})))
        ;; 14. Verify that the UP bit of the flags in authData is set.
        flags (authData "flags")
        _step-14 (when-not (UP? flags)
                   (throw (ex-info "Registration ceremony failed at step 14, expected `attStmt.flags` to have `UP` bit set."
                                   {:flags flags})))
        ;; 15. If the Relying Party requires user verification for this registration, verify that the UV bit of the flags in authData is set.
        _step-15 (when (and (options :require-user-verification?) (not (UV? flags)))
                   (throw (ex-info "Registration ceremony failed at step 15, expected `attStmt.flags` to have `UV` bit set."
                                   {:flags flags})))
        ;; 16. If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
        _step-16 (when (and (not (BE? flags))
                            (BS? flags))
                   (throw (ex-info "Registration ceremony failed at step 16, expected `attStmt.flags` to have `BS` bit clear since `BE` is clear."
                                   {:flags flags})))
        ;; 17. If the Relying Party uses the credential's backup eligibility to inform its user experience flows and/or policies, evaluate the BE bit of the flags in authData.
        _step-17 (when-let [validate-fn (options :validate-backup-eligibility)]
                   (when-not (validate-fn flags)
                     (throw (ex-info "Registration ceremony failed at step 17, value of `BE` in `attStmt.flags` did not pass relying party's policies."
                                     {:flags flags}))))
        ;; 18. If the Relying Party uses the credential's backup state to inform its user experience flows and/or policies, evaluate the BS bit of the flags in authData.
        _step-18 (when-let [validate-fn (options :validate-backup-state)]
                   (when-not (validate-fn flags)
                     (throw (ex-info "Registration ceremony failed at step 18, value of `BS` in `attStmt.flags` did not pass relying party's policies."
                                     {:flags flags}))))
        ;; 19. Verify that the 'alg' parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
        ;; 20. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general case, the meaning of 'are as expected' is specific to the Relying Party and which extensions are in use.
        ;; NOTE: Client platforms MAY enact local policy that sets additional authenticator extensions or client extensions and thus cause values to appear in the authenticator extension outputs or client extension outputs that were not originally specified as part of options.extensions. Relying Parties MUST be prepared to handle such situations, whether it be to ignore the unsolicited extensions or reject the attestation. The Relying Party can make this decision based on local policy and the extensions in use.
        ;; NOTE: Since all extensions are OPTIONAL for both the client and the authenticator, the Relying Party MUST also be prepared to handle cases where none or not all of the requested extensions were acted upon.
        ;; NOTE: The devicePubKey extension has explicit verification procedures, see §10.2.2.3.1 Registration (create()).
        ;; 21. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the IANA 'WebAuthn Attestation Statement Format Identifiers' registry [IANA-WebAuthn-Registries] established by [RFC8809].
        ;; 22. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt's verification procedure given attStmt, authData and hash.
        ;; NOTE: Each attestation statement format specifies its own verification procedure. See §8 Defined Attestation Statement Formats for the initially-defined formats, and [IANA-WebAuthn-Registries] for the up-to-date list.
        ;; 23. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.
        ;; 24. Assess the attestation trustworthiness using the outputs of the verification procedure in step 21, as follows:
        ;;     - If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.
        ;;     - If self attestation was used, verify that self attestation is acceptable under Relying Party policy.
        ;;     - Otherwise, use the X.509 certificates returned as the attestation trust path from the verification procedure to verify that the attestation public key either correctly chains up to an acceptable root certificate, or is itself an acceptable certificate (i.e., it and the root certificate obtained in Step 22 may be the same).
        ;; 25. Verify that the credentialId is ≤ 1023 bytes. Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.
        ;; 26. Verify that the credentialId is not yet registered for any user. If the credentialId is already known then the Relying Party SHOULD fail this registration ceremony.
        ;; NOTE: The rationale for Relying Parties rejecting duplicate credential IDs is as follows: credential IDs contain sufficient entropy that accidental duplication is very unlikely. However, attestation types other than self attestation do not include a self-signature to explicitly prove possession of the credential private key at registration time. Thus an attacker who has managed to obtain a user's credential ID and credential public key for a site (this could be potentially accomplished in various ways), could attempt to register a victim's credential as their own at that site. If the Relying Party accepts this new registration and replaces the victim's existing credential registration, and the credentials are discoverable, then the victim could be forced to sign into the attacker's account at their next attempt. Data saved to the site by the victim in that state would then be available to the attacker.
        ;; 27. If the attestation statement attStmt verified successfully and is found to be trustworthy, then create and store a new credential record in the user account that was denoted in options.user, with the following contents:
        ]))






(comment



  "19. Verify that the 'alg' parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
  20. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general case, the meaning of 'are as expected' is specific to the Relying Party and which extensions are in use.
      NOTE: Client platforms MAY enact local policy that sets additional authenticator extensions or client extensions and thus cause values to appear in the authenticator extension outputs or client extension outputs that were not originally specified as part of options.extensions. Relying Parties MUST be prepared to handle such situations, whether it be to ignore the unsolicited extensions or reject the attestation. The Relying Party can make this decision based on local policy and the extensions in use.
      NOTE: Since all extensions are OPTIONAL for both the client and the authenticator, the Relying Party MUST also be prepared to handle cases where none or not all of the requested extensions were acted upon.
      NOTE: The devicePubKey extension has explicit verification procedures, see §10.2.2.3.1 Registration (create()).
  21. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the IANA 'WebAuthn Attestation Statement Format Identifiers' registry [IANA-WebAuthn-Registries] established by [RFC8809].
  22. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt's verification procedure given attStmt, authData and hash.
      NOTE: Each attestation statement format specifies its own verification procedure. See §8 Defined Attestation Statement Formats for the initially-defined formats, and [IANA-WebAuthn-Registries] for the up-to-date list.
  23. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.
  24. Assess the attestation trustworthiness using the outputs of the verification procedure in step 21, as follows:
      - If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.
      - If self attestation was used, verify that self attestation is acceptable under Relying Party policy.
      - Otherwise, use the X.509 certificates returned as the attestation trust path from the verification procedure to verify that the attestation public key either correctly chains up to an acceptable root certificate, or is itself an acceptable certificate (i.e., it and the root certificate obtained in Step 22 may be the same).
  25. Verify that the credentialId is ≤ 1023 bytes. Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.
  26. Verify that the credentialId is not yet registered for any user. If the credentialId is already known then the Relying Party SHOULD fail this registration ceremony.
      NOTE: The rationale for Relying Parties rejecting duplicate credential IDs is as follows: credential IDs contain sufficient entropy that accidental duplication is very unlikely. However, attestation types other than self attestation do not include a self-signature to explicitly prove possession of the credential private key at registration time. Thus an attacker who has managed to obtain a user's credential ID and credential public key for a site (this could be potentially accomplished in various ways), could attempt to register a victim's credential as their own at that site. If the Relying Party accepts this new registration and replaces the victim's existing credential registration, and the credentials are discoverable, then the victim could be forced to sign into the attacker's account at their next attempt. Data saved to the site by the victim in that state would then be available to the attacker.
  27. If the attestation statement attStmt verified successfully and is found to be trustworthy, then create and store a new credential record in the user account that was denoted in options.user, with the following contents:
      type
        credential.type.
      id
        credential.id or credential.rawId, whichever format is preferred by the Relying Party.
      publicKey
        The credential public key in authData.
      signCount
        authData.signCount.
      uvInitialized
        The value of the UV flag in authData.
      transports
        The value returned from response.getTransports().
      backupEligible
        The value of the BE flag in authData.
      backupState
        The value of the BS flag in authData.
        
    The new credential record MAY also include the following OPTIONAL contents:
      attestationObject
        response.attestationObject.
      attestationClientDataJSON
        response.clientDataJSON.
  28. If the attestation statement attStmt successfully verified but is not trustworthy per step 23 above, the Relying Party SHOULD fail the registration ceremony.
      NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and credential public key but treat the credential as one with self attestation (see §6.5.4 Attestation Types). If doing so, the Relying Party is asserting there is no cryptographic proof that the public key credential has been generated by a particular authenticator model. See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.

  Verification of attestation objects requires that the Relying Party has a trusted method of determining acceptable trust anchors in step 22 above. Also, if certificates are being used, the Relying Party MUST have access to certificate status information for the intermediate CA certificates. The Relying Party MUST also be able to build the attestation certificate chain if the client did not provide this chain in the attestation information.")