//! Authentificateur FIDO2 natif Windows (`webauthn.dll`) : clés de sécurité
//! USB/NFC (YubiKey…) et Windows Hello. Windows affiche lui-même l'interface
//! (choix de la clé, PIN, contact). Le `clientDataJSON` est construit par
//! l'appelant (`msg-client-core::passkey`), qui contrôle l'origine et le rpId.

use crate::PlatformError;

pub struct MakeCredential<'a> {
    pub rp_id: &'a str,
    pub rp_name: &'a str,
    pub user_id: &'a [u8],
    pub user_name: &'a str,
    pub user_display_name: &'a str,
    pub client_data_json: &'a [u8],
    pub algorithms: &'a [i64],
    pub exclude_credentials: &'a [Vec<u8>],
    pub require_resident_key: bool,
    pub user_verification: &'a str,
    pub timeout_ms: u32,
}

pub struct GetAssertion<'a> {
    pub rp_id: &'a str,
    pub client_data_json: &'a [u8],
    pub allow_credentials: &'a [Vec<u8>],
    pub user_verification: &'a str,
    pub timeout_ms: u32,
}

pub struct Attestation {
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
}

/// `true` si l'API WebAuthn de Windows est disponible.
pub fn available() -> bool {
    imp::available()
}

/// `hwnd` : fenêtre parente des boîtes de dialogue Windows.
pub fn make_credential(hwnd: isize, req: &MakeCredential<'_>) -> Result<Attestation, PlatformError> {
    imp::make_credential(hwnd, req)
}

pub fn get_assertion(hwnd: isize, req: &GetAssertion<'_>) -> Result<Assertion, PlatformError> {
    imp::get_assertion(hwnd, req)
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    pub fn available() -> bool {
        false
    }
    pub fn make_credential(_: isize, _: &MakeCredential<'_>) -> Result<Attestation, PlatformError> {
        Err(PlatformError::Unsupported)
    }
    pub fn get_assertion(_: isize, _: &GetAssertion<'_>) -> Result<Assertion, PlatformError> {
        Err(PlatformError::Unsupported)
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::wide;
    use windows_sys::Win32::Networking::WindowsWebServices::*;

    /// HRESULT renvoyé quand l'utilisateur annule (NTE_USER_CANCELLED / ERROR_CANCELLED).
    const NTE_USER_CANCELLED: i32 = 0x8009_0036_u32 as i32;
    const HRESULT_CANCELLED: i32 = 0x8007_04C7_u32 as i32;

    fn check(hr: i32) -> Result<(), PlatformError> {
        match hr {
            0 => Ok(()),
            NTE_USER_CANCELLED | HRESULT_CANCELLED => Err(PlatformError::Cancelled),
            e => Err(PlatformError::HResult(e as u32)),
        }
    }

    fn uv(s: &str) -> u32 {
        match s {
            "required" => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            "discouraged" => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
            _ => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
        }
    }

    /// Copie d'un tampon renvoyé par Windows.
    ///
    /// # Safety
    /// `p` doit pointer vers `n` octets valides (ou être nul si `n == 0`).
    unsafe fn copy(p: *const u8, n: u32) -> Vec<u8> {
        if p.is_null() || n == 0 {
            Vec::new()
        } else {
            // SAFETY: garanti par l'appelant.
            unsafe { std::slice::from_raw_parts(p, n as usize) }.to_vec()
        }
    }

    pub fn available() -> bool {
        // SAFETY: fonction sans paramètre.
        (unsafe { WebAuthNGetApiVersionNumber() }) >= 1
    }

    fn credential_list(ids: &[Vec<u8>]) -> Vec<WEBAUTHN_CREDENTIAL> {
        ids.iter()
            .map(|id| WEBAUTHN_CREDENTIAL {
                dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                cbId: id.len() as u32,
                pbId: id.as_ptr() as *mut u8,
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            })
            .collect()
    }

    pub fn make_credential(hwnd: isize, req: &MakeCredential<'_>) -> Result<Attestation, PlatformError> {
        let rp_id = wide(req.rp_id);
        let rp_name = wide(req.rp_name);
        let user_name = wide(req.user_name);
        let user_display = wide(req.user_display_name);
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: rp_id.as_ptr(),
            pwszName: rp_name.as_ptr(),
            pwszIcon: std::ptr::null(),
        };
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: req.user_id.len() as u32,
            pbId: req.user_id.as_ptr() as *mut u8,
            pwszName: user_name.as_ptr(),
            pwszIcon: std::ptr::null(),
            pwszDisplayName: user_display.as_ptr(),
        };
        let mut params: Vec<WEBAUTHN_COSE_CREDENTIAL_PARAMETER> = req
            .algorithms
            .iter()
            .map(|a| WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
                dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                lAlg: *a as i32,
            })
            .collect();
        if params.is_empty() {
            return Err(PlatformError::Invalid("aucun algorithme"));
        }
        let cose = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: params.len() as u32,
            pCredentialParameters: params.as_mut_ptr(),
        };
        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: req.client_data_json.len() as u32,
            pbClientDataJSON: req.client_data_json.as_ptr() as *mut u8,
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut exclude = credential_list(req.exclude_credentials);
        // SAFETY: structure POD ; seuls les champs de la version 1 sont lus.
        let mut options: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = unsafe { std::mem::zeroed() };
        options.dwVersion = 1;
        options.dwTimeoutMilliseconds = req.timeout_ms;
        options.CredentialList =
            WEBAUTHN_CREDENTIALS { cCredentials: exclude.len() as u32, pCredentials: exclude.as_mut_ptr() };
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
        options.bRequireResidentKey = req.require_resident_key as i32;
        options.dwUserVerificationRequirement = uv(req.user_verification);
        options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
        let mut out: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = std::ptr::null_mut();
        // SAFETY: toutes les structures et chaînes vivent jusqu'à la fin de l'appel.
        check(unsafe {
            WebAuthNAuthenticatorMakeCredential(hwnd as _, &rp, &user, &cose, &client_data, &options, &mut out)
        })?;
        if out.is_null() {
            return Err(PlatformError::Invalid("réponse vide"));
        }
        // SAFETY: `out` valide jusqu'à WebAuthNFreeCredentialAttestation.
        let res = unsafe {
            let a = &*out;
            Attestation {
                credential_id: copy(a.pbCredentialId, a.cbCredentialId),
                attestation_object: copy(a.pbAttestationObject, a.cbAttestationObject),
            }
        };
        // SAFETY: libération unique du résultat alloué par Windows.
        unsafe { WebAuthNFreeCredentialAttestation(out) };
        if res.credential_id.is_empty() || res.attestation_object.is_empty() {
            return Err(PlatformError::Invalid("attestation incomplète"));
        }
        Ok(res)
    }

    pub fn get_assertion(hwnd: isize, req: &GetAssertion<'_>) -> Result<Assertion, PlatformError> {
        let rp_id = wide(req.rp_id);
        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: req.client_data_json.len() as u32,
            pbClientDataJSON: req.client_data_json.as_ptr() as *mut u8,
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut allow = credential_list(req.allow_credentials);
        // SAFETY: structure POD ; seuls les champs de la version 1 sont lus.
        let mut options: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = unsafe { std::mem::zeroed() };
        options.dwVersion = 1;
        options.dwTimeoutMilliseconds = req.timeout_ms;
        options.CredentialList =
            WEBAUTHN_CREDENTIALS { cCredentials: allow.len() as u32, pCredentials: allow.as_mut_ptr() };
        options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
        options.dwUserVerificationRequirement = uv(req.user_verification);
        let mut out: *mut WEBAUTHN_ASSERTION = std::ptr::null_mut();
        // SAFETY: toutes les structures et chaînes vivent jusqu'à la fin de l'appel.
        check(unsafe {
            WebAuthNAuthenticatorGetAssertion(hwnd as _, rp_id.as_ptr(), &client_data, &options, &mut out)
        })?;
        if out.is_null() {
            return Err(PlatformError::Invalid("réponse vide"));
        }
        // SAFETY: `out` valide jusqu'à WebAuthNFreeAssertion.
        let res = unsafe {
            let a = &*out;
            let user = copy(a.pbUserId, a.cbUserId);
            Assertion {
                credential_id: copy(a.Credential.pbId, a.Credential.cbId),
                authenticator_data: copy(a.pbAuthenticatorData, a.cbAuthenticatorData),
                signature: copy(a.pbSignature, a.cbSignature),
                user_handle: (!user.is_empty()).then_some(user),
            }
        };
        // SAFETY: libération unique du résultat alloué par Windows.
        unsafe { WebAuthNFreeAssertion(out) };
        Ok(res)
    }
}
