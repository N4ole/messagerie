//! Scellement de secrets par le TPM 2.0 via CNG (Microsoft Platform Crypto
//! Provider).
//!
//! Une clé RSA-2048 **non exportable** est créée dans le TPM (une par compte
//! local) ; elle chiffre (RSA-OAEP-SHA256) une clé de 256 bits. Le secret
//! scellé ne peut donc être ouvert que sur cette machine, par ce TPM. Le TPM
//! ne gérant ni Ed25519 ni X25519, il protège la clé de la base locale et non
//! les clés de messagerie elles-mêmes (ADR-0005).

use zeroize::Zeroizing;

use crate::PlatformError;

/// `true` si un TPM utilisable est présent.
pub fn available() -> bool {
    imp::available()
}

/// Chiffre `secret` (≤ 190 octets) avec la clé TPM `key_name` (créée au besoin).
pub fn seal(key_name: &str, secret: &[u8]) -> Result<Vec<u8>, PlatformError> {
    if secret.is_empty() || secret.len() > 190 {
        return Err(PlatformError::Invalid("taille de secret TPM"));
    }
    imp::seal(key_name, secret)
}

pub fn unseal(key_name: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
    imp::unseal(key_name, sealed)
}

/// Supprime la clé TPM (le secret scellé devient définitivement illisible).
pub fn delete_key(key_name: &str) -> Result<(), PlatformError> {
    imp::delete_key(key_name)
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    pub fn available() -> bool {
        false
    }
    pub fn seal(_: &str, _: &[u8]) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::Unsupported)
    }
    pub fn unseal(_: &str, _: &[u8]) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
        Err(PlatformError::Unsupported)
    }
    pub fn delete_key(_: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::wide;
    use windows_sys::Win32::Foundation::NTE_BAD_KEYSET;
    use windows_sys::Win32::Security::Cryptography::{
        NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptFinalizeKey, NCryptFreeObject,
        NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM,
        BCRYPT_SHA256_ALGORITHM, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY,
        NCRYPT_PAD_OAEP_FLAG, NCRYPT_PROV_HANDLE,
    };

    fn check(hr: i32) -> Result<(), PlatformError> {
        if hr == 0 {
            Ok(())
        } else {
            Err(PlatformError::HResult(hr as u32))
        }
    }

    /// Handle CNG libéré automatiquement.
    struct Handle(usize);
    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: handle obtenu de CNG, libéré une seule fois.
                unsafe { NCryptFreeObject(self.0) };
            }
        }
    }

    fn provider() -> Result<Handle, PlatformError> {
        let mut h: NCRYPT_PROV_HANDLE = 0;
        // SAFETY: pointeur de sortie valide ; nom de fournisseur constant.
        check(unsafe { NCryptOpenStorageProvider(&mut h, MS_PLATFORM_CRYPTO_PROVIDER, 0) })?;
        Ok(Handle(h))
    }

    fn key(prov: &Handle, name: &str, create: bool) -> Result<Handle, PlatformError> {
        let wname = wide(name);
        let mut k: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: handle de fournisseur valide, nom terminé par zéro.
        let hr = unsafe { NCryptOpenKey(prov.0, &mut k, wname.as_ptr(), 0, 0) };
        if hr == 0 {
            return Ok(Handle(k));
        }
        if hr != NTE_BAD_KEYSET || !create {
            return Err(PlatformError::HResult(hr as u32));
        }
        // SAFETY: idem ; création d'une clé persistante RSA dans le TPM.
        check(unsafe { NCryptCreatePersistedKey(prov.0, &mut k, BCRYPT_RSA_ALGORITHM, wname.as_ptr(), 0, 0) })?;
        let key = Handle(k);
        let bits: u32 = 2048;
        // SAFETY: propriété « Length » de 4 octets.
        check(unsafe { NCryptSetProperty(key.0, NCRYPT_LENGTH_PROPERTY, (&bits as *const u32).cast(), 4, 0) })?;
        // SAFETY: finalisation de la clé (aucune politique d'export : non exportable).
        check(unsafe { NCryptFinalizeKey(key.0, 0) })?;
        Ok(key)
    }

    fn padding() -> BCRYPT_OAEP_PADDING_INFO {
        BCRYPT_OAEP_PADDING_INFO { pszAlgId: BCRYPT_SHA256_ALGORITHM, pbLabel: std::ptr::null_mut(), cbLabel: 0 }
    }

    pub fn available() -> bool {
        provider().is_ok()
    }

    pub fn seal(key_name: &str, secret: &[u8]) -> Result<Vec<u8>, PlatformError> {
        let prov = provider()?;
        let k = key(&prov, key_name, true)?;
        let pad = padding();
        let mut len = 0u32;
        // SAFETY: premier appel pour connaître la taille de sortie.
        check(unsafe {
            NCryptEncrypt(
                k.0,
                secret.as_ptr(),
                secret.len() as u32,
                (&pad as *const BCRYPT_OAEP_PADDING_INFO).cast(),
                std::ptr::null_mut(),
                0,
                &mut len,
                NCRYPT_PAD_OAEP_FLAG,
            )
        })?;
        let mut out = vec![0u8; len as usize];
        // SAFETY: tampon de sortie de la taille annoncée.
        check(unsafe {
            NCryptEncrypt(
                k.0,
                secret.as_ptr(),
                secret.len() as u32,
                (&pad as *const BCRYPT_OAEP_PADDING_INFO).cast(),
                out.as_mut_ptr(),
                len,
                &mut len,
                NCRYPT_PAD_OAEP_FLAG,
            )
        })?;
        out.truncate(len as usize);
        Ok(out)
    }

    pub fn unseal(key_name: &str, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
        let prov = provider()?;
        let k = key(&prov, key_name, false)?;
        let pad = padding();
        let mut len = 0u32;
        // SAFETY: premier appel pour connaître la taille de sortie.
        check(unsafe {
            NCryptDecrypt(
                k.0,
                sealed.as_ptr(),
                sealed.len() as u32,
                (&pad as *const BCRYPT_OAEP_PADDING_INFO).cast(),
                std::ptr::null_mut(),
                0,
                &mut len,
                NCRYPT_PAD_OAEP_FLAG,
            )
        })?;
        let mut out = Zeroizing::new(vec![0u8; len as usize]);
        // SAFETY: tampon de sortie de la taille annoncée.
        check(unsafe {
            NCryptDecrypt(
                k.0,
                sealed.as_ptr(),
                sealed.len() as u32,
                (&pad as *const BCRYPT_OAEP_PADDING_INFO).cast(),
                out.as_mut_ptr(),
                len,
                &mut len,
                NCRYPT_PAD_OAEP_FLAG,
            )
        })?;
        out.truncate(len as usize);
        Ok(out)
    }

    pub fn delete_key(key_name: &str) -> Result<(), PlatformError> {
        let prov = provider()?;
        let mut k = key(&prov, key_name, false)?;
        // SAFETY: NCryptDeleteKey libère aussi le handle : on l'oublie ensuite.
        let hr = unsafe { NCryptDeleteKey(k.0, 0) };
        k.0 = 0;
        check(hr)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_when_tpm_present() {
        if !available() {
            eprintln!("TPM absent sur cette machine : test ignoré");
            return;
        }
        let name = format!("Messagerie-test-{}", std::process::id());
        let secret = [7u8; 32];
        let sealed = seal(&name, &secret).unwrap();
        assert_ne!(&sealed[..], &secret[..]);
        assert_eq!(&unseal(&name, &sealed).unwrap()[..], &secret[..]);
        delete_key(&name).unwrap();
        assert!(unseal(&name, &sealed).is_err());
    }
}
