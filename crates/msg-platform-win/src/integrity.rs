//! Vérification de la signature Authenticode d'un fichier (l'exécutable de
//! l'application au démarrage), **sans accès réseau** : pas de vérification
//! de révocation en ligne (zéro télémétrie), seules les données en cache
//! sont consultées.

/// État de la signature Authenticode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// Signature valide, chaîne de confiance reconnue par Windows.
    Valid,
    /// Fichier non signé (releases actuelles : vérifier l'empreinte publiée).
    Unsigned,
    /// Signature présente mais invalide : fichier **modifié** après signature.
    Tampered,
    /// Signature intacte mais éditeur non approuvé (racine inconnue, expirée,
    /// méfiance explicite…), avec le code d'erreur Windows.
    Untrusted(u32),
    /// Vérification impossible sur ce système.
    NotApplicable,
}

/// Vérifie la signature Authenticode de `path`.
pub fn verify_file(path: &std::path::Path) -> Signature {
    imp::verify(path)
}

#[cfg(not(windows))]
mod imp {
    pub fn verify(_: &std::path::Path) -> super::Signature {
        super::Signature::NotApplicable
    }
}

#[cfg(windows)]
mod imp {
    use super::Signature;
    use windows_sys::Win32::Foundation::{
        TRUST_E_BAD_DIGEST, TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SUBJECT_FORM_UNKNOWN,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    /// TRUST_E_NOSIGNATURE et équivalents : « aucune signature ».
    const CRYPT_E_FILE_ERROR: i32 = 0x80092003_u32 as i32;

    pub fn verify(path: &std::path::Path) -> Signature {
        let wide = crate::wide(&path.to_string_lossy());
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide.as_ptr(),
            hFile: std::ptr::null_mut(),
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            // Aucune récupération réseau (CRL/OCSP) : cache uniquement.
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE | WTD_DISABLE_MD2_MD4,
            ..Default::default()
        };
        data.Anonymous.pFile = &mut file;
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY : `data` et `file` sont initialisés et vivent pendant les deux
        // appels ; `wide` (chemin terminé par NUL) survit à `file`. Le second
        // appel libère l'état alloué par le premier.
        let status = unsafe {
            let s = WinVerifyTrust(std::ptr::null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast());
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(std::ptr::null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast());
            s
        };
        match status {
            0 => Signature::Valid,
            TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN | CRYPT_E_FILE_ERROR => {
                Signature::Unsigned
            }
            TRUST_E_BAD_DIGEST => Signature::Tampered,
            other => Signature::Untrusted(other as u32),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_or_not_applicable_file() {
        let dir = std::env::temp_dir().join(format!("msg-integrity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("fichier.exe");
        std::fs::write(&f, b"MZ pas une vraie image").unwrap();
        let s = verify_file(&f);
        if cfg!(windows) {
            assert_eq!(s, Signature::Unsigned);
        } else {
            assert_eq!(s, Signature::NotApplicable);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Un exécutable système signé par Microsoft est reconnu (Windows seulement).
    #[cfg(windows)]
    #[test]
    fn system_binary_is_signed() {
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
        let s = verify_file(&std::path::Path::new(&windir).join(r"System32\notepad.exe"));
        // notepad.exe est signé par catalogue sur certaines versions : la
        // vérification « fichier » le voit alors non signé, jamais altéré.
        assert!(matches!(s, Signature::Valid | Signature::Unsigned), "{s:?}");
    }
}
