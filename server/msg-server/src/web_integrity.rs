//! Intégrité du client web servi par le serveur : un manifeste SHA-256
//! (`integrity.json`), produit à la construction de l'image, est vérifié au
//! démarrage. Tout fichier modifié, ajouté ou manquant empêche le démarrage.
//!
//! Portée : détecte une altération des fichiers déployés (disque, image,
//! volume) entre la construction et l'exécution. Ne protège pas contre un
//! serveur entièrement compromis, qui peut réécrire le manifeste et servir
//! un autre client (limite fondamentale du web, voir la Phase 3).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MANIFEST: &str = "integrity.json";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub algorithm: String,
    /// Chemin relatif (séparateur `/`) → empreinte SHA-256 hexadécimale.
    pub files: BTreeMap<String, String>,
}

fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) -> anyhow::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        let ty = e.file_type()?;
        if ty.is_symlink() {
            bail!("lien symbolique refusé dans le client web : {}", path.display());
        }
        if ty.is_dir() {
            walk(root, &path, out)?;
            continue;
        }
        let rel: PathBuf = path.strip_prefix(root)?.into();
        let rel = rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
        if rel == MANIFEST {
            continue;
        }
        let data = std::fs::read(&path).with_context(|| format!("lecture de {rel}"))?;
        out.insert(rel, hex::encode(Sha256::digest(&data)));
    }
    Ok(())
}

/// Calcule le manifeste du répertoire `dir`.
pub fn generate(dir: &Path) -> anyhow::Result<Manifest> {
    let mut files = BTreeMap::new();
    walk(dir, dir, &mut files)?;
    if files.is_empty() {
        bail!("répertoire du client web vide : {}", dir.display());
    }
    Ok(Manifest { algorithm: "sha256".into(), files })
}

/// Écrit le manifeste ; renvoie l'empreinte du manifeste (à publier).
pub fn write(dir: &Path) -> anyhow::Result<String> {
    let m = generate(dir)?;
    let json = serde_json::to_vec_pretty(&m)?;
    std::fs::write(dir.join(MANIFEST), &json)?;
    Ok(hex::encode(Sha256::digest(&json)))
}

/// Vérifie `dir` contre son manifeste. `Ok(None)` : aucun manifeste
/// (développement) ; `Ok(Some(empreinte du manifeste))` : conforme.
pub fn verify(dir: &Path) -> anyhow::Result<Option<String>> {
    let raw = match std::fs::read(dir.join(MANIFEST)) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let expected: Manifest = serde_json::from_slice(&raw).context("manifeste d'intégrité illisible")?;
    if expected.algorithm != "sha256" {
        bail!("algorithme de manifeste non pris en charge : {}", expected.algorithm);
    }
    let actual = generate(dir)?;
    let mut problems = Vec::new();
    for (f, h) in &expected.files {
        match actual.files.get(f) {
            None => problems.push(format!("manquant : {f}")),
            Some(a) if a != h => problems.push(format!("modifié : {f}")),
            _ => {}
        }
    }
    for f in actual.files.keys().filter(|f| !expected.files.contains_key(*f)) {
        problems.push(format!("inattendu : {f}"));
    }
    if !problems.is_empty() {
        problems.truncate(10);
        bail!("client web altéré ({})", problems.join(", "));
    }
    Ok(Some(hex::encode(Sha256::digest(&raw))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_modified_added_and_missing_files() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("assets")).unwrap();
        std::fs::write(d.path().join("index.html"), "<html></html>").unwrap();
        std::fs::write(d.path().join("assets/app.js"), "console.log(1)").unwrap();
        assert_eq!(verify(d.path()).unwrap(), None, "sans manifeste : rien à vérifier");
        let digest = write(d.path()).unwrap();
        assert_eq!(verify(d.path()).unwrap(), Some(digest));

        std::fs::write(d.path().join("assets/app.js"), "console.log(2)").unwrap();
        assert!(verify(d.path()).unwrap_err().to_string().contains("modifié : assets/app.js"));
        std::fs::write(d.path().join("assets/app.js"), "console.log(1)").unwrap();

        std::fs::write(d.path().join("piege.js"), "x").unwrap();
        assert!(verify(d.path()).unwrap_err().to_string().contains("inattendu : piege.js"));
        std::fs::remove_file(d.path().join("piege.js")).unwrap();

        std::fs::remove_file(d.path().join("index.html")).unwrap();
        assert!(verify(d.path()).unwrap_err().to_string().contains("manquant : index.html"));
    }
}
