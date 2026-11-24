//! Protection contre la capture d'écran (Windows 10 2004+).
//!
//! `WDA_EXCLUDEFROMCAPTURE` retire la fenêtre des captures logicielles
//! (outil Capture, PrintScreen, enregistreurs, partage d'écran) : elle y
//! apparaît vide. Sur les versions plus anciennes, repli sur `WDA_MONITOR`
//! (fenêtre noire). **Limites** : n'empêche ni l'appareil photo, ni une carte
//! d'acquisition, ni un logiciel malveillant noyau.

use crate::PlatformError;

/// Niveau de protection effectivement appliqué.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureProtection {
    /// Fenêtre exclue des captures (Windows 10 2004+).
    Excluded,
    /// Fenêtre noircie dans les captures (versions antérieures).
    Monitor,
    None,
}

/// Active ou désactive la protection pour la fenêtre `hwnd` (handle natif).
pub fn protect_window(hwnd: isize, enabled: bool) -> Result<CaptureProtection, PlatformError> {
    imp::protect(hwnd, enabled)
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    pub fn protect(_: isize, _: bool) -> Result<CaptureProtection, PlatformError> {
        Err(PlatformError::Unsupported)
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetWindowDisplayAffinity, SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR, WDA_NONE,
    };

    pub fn protect(hwnd: isize, enabled: bool) -> Result<CaptureProtection, PlatformError> {
        let h = hwnd as windows_sys::Win32::Foundation::HWND;
        if !enabled {
            // SAFETY: handle de fenêtre fourni par Tauri, valide pendant l'appel.
            if unsafe { SetWindowDisplayAffinity(h, WDA_NONE) } == 0 {
                // SAFETY: lecture du code d'erreur du thread courant.
                return Err(PlatformError::Win32(unsafe { GetLastError() }));
            }
            return Ok(CaptureProtection::None);
        }
        // SAFETY: idem.
        let level = if unsafe { SetWindowDisplayAffinity(h, WDA_EXCLUDEFROMCAPTURE) } != 0 {
            WDA_EXCLUDEFROMCAPTURE
        } else if unsafe { SetWindowDisplayAffinity(h, WDA_MONITOR) } != 0 {
            WDA_MONITOR
        } else {
            // SAFETY: lecture du code d'erreur du thread courant.
            return Err(PlatformError::Win32(unsafe { GetLastError() }));
        };
        // Relecture pour confirmer l'état réellement appliqué.
        let mut current = 0u32;
        // SAFETY: pointeur valide vers un u32 local.
        if unsafe { GetWindowDisplayAffinity(h, &mut current) } == 0 || current != level {
            return Err(PlatformError::Invalid("protection non appliquée"));
        }
        Ok(if level == WDA_EXCLUDEFROMCAPTURE { CaptureProtection::Excluded } else { CaptureProtection::Monitor })
    }
}
