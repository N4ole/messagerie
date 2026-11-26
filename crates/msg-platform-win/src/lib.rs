//! Intégrations spécifiques à Windows.
//!
//! Ce crate est le **seul** du dépôt à contenir du code `unsafe` (appels FFI
//! vers l'API Win32). Chaque bloc est commenté et minimal. Sur les autres
//! systèmes, les fonctions renvoient [`PlatformError::Unsupported`].
#![deny(unsafe_op_in_unsafe_fn)]

use zeroize::Zeroizing;

pub mod capture;
pub mod integrity;
pub mod tpm;
pub mod webauthn;

#[cfg(windows)]
pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("fonction non disponible sur ce système")]
    Unsupported,
    #[error("échec de l'appel système Windows (code {0})")]
    Win32(u32),
    #[error("échec de l'appel système Windows (HRESULT 0x{0:08X})")]
    HResult(u32),
    #[error("opération annulée ou refusée par l'utilisateur")]
    Cancelled,
    #[error("paramètre invalide : {0}")]
    Invalid(&'static str),
}

/// `true` si la protection DPAPI est disponible.
pub fn dpapi_available() -> bool {
    cfg!(windows)
}

/// Chiffre `data` avec DPAPI, lié à la session Windows de l'utilisateur
/// courant (`CryptProtectData`, sans interface utilisateur).
pub fn dpapi_protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, PlatformError> {
    imp::protect(data, entropy)
}

/// Inverse de [`dpapi_protect`].
pub fn dpapi_unprotect(data: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
    imp::unprotect(data, entropy)
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    pub fn protect(_: &[u8], _: &[u8]) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::Unsupported)
    }
    pub fn unprotect(_: &[u8], _: &[u8]) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
        Err(PlatformError::Unsupported)
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
    }

    /// Copie la sortie allouée par Windows puis la libère (après effacement).
    ///
    /// # Safety
    /// `out` doit provenir d'un appel réussi à `CryptProtectData`/`CryptUnprotectData`.
    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
        // SAFETY: Windows garantit que `pbData` pointe vers `cbData` octets valides.
        let slice = unsafe { std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize) };
        let v = Zeroizing::new(slice.to_vec());
        slice.iter_mut().for_each(|b| *b = 0);
        // SAFETY: tampon alloué par LocalAlloc côté Windows, libéré une seule fois.
        unsafe { LocalFree(out.pbData as _) };
        v
    }

    pub fn protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, PlatformError> {
        let input = blob(data);
        let ent = blob(entropy);
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY: pointeurs valides pendant l'appel ; aucune interface demandée.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &ent,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            // SAFETY: lecture du code d'erreur du thread courant.
            return Err(PlatformError::Win32(unsafe { GetLastError() }));
        }
        // SAFETY: `out` provient d'un appel réussi.
        Ok(unsafe { take(out) }.to_vec())
    }

    pub fn unprotect(data: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
        let input = blob(data);
        let ent = blob(entropy);
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY: idem `protect`.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &ent,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            // SAFETY: lecture du code d'erreur du thread courant.
            return Err(PlatformError::Win32(unsafe { GetLastError() }));
        }
        // SAFETY: `out` provient d'un appel réussi.
        Ok(unsafe { take(out) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn dpapi_roundtrip() {
        let p = dpapi_protect(b"cle secrete", b"entropie").unwrap();
        assert_ne!(&p[..], b"cle secrete");
        assert_eq!(&dpapi_unprotect(&p, b"entropie").unwrap()[..], b"cle secrete");
        assert!(dpapi_unprotect(&p, b"autre").is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_elsewhere() {
        assert!(!dpapi_available());
        assert!(matches!(dpapi_protect(b"x", b""), Err(PlatformError::Unsupported)));
    }
}
