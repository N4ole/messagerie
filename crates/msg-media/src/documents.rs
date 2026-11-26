//! Nettoyage des métadonnées des documents, avant chiffrement :
//!
//! - **PDF** (`lopdf`) : dictionnaire `Info` (auteur, logiciel, dates),
//!   métadonnées XMP (catalogue, pages, images), `PieceInfo`, identifiant de
//!   fichier `ID`, auteur et dates des annotations ; le fichier est réécrit
//!   en entier (les révisions antérieures disparaissent). Les PDF chiffrés
//!   ne sont pas modifiés.
//! - **Office Open XML** (docx, xlsx, pptx…) et **OpenDocument** (odt, ods,
//!   odp…) (`zip`) : propriétés du document (auteur, société, modèle,
//!   dates, propriétés personnalisées), miniature, auteurs et dates des
//!   commentaires et des modifications suivies, imprimante ; dates des
//!   entrées de l'archive remises à zéro.
//!
//! Le type est reconnu par le contenu (signature, structure), jamais par
//! l'extension. Le contenu visible du document n'est pas modifié.

use std::io::{Cursor, Read, Write};

use lopdf::{Document, Object};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

use crate::MediaError;

/// Taille décompressée maximale d'un document traité (bombe ZIP).
const MAX_UNCOMPRESSED: u64 = 200 * 1024 * 1024;
/// Nombre maximal d'entrées d'une archive.
const MAX_ENTRIES: usize = 10_000;
/// Valeur de remplacement des noms d'auteur.
const ANONYMOUS: &str = "Auteur";
/// Date de remplacement (format xsd:dateTime).
const EPOCH: &str = "1980-01-01T00:00:00Z";

/// Format de document reconnu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentKind {
    Pdf,
    /// Office Open XML (Word, Excel, PowerPoint).
    Ooxml,
    /// OpenDocument (LibreOffice, OpenOffice).
    OpenDocument,
}

fn invalid(e: impl std::fmt::Display) -> MediaError {
    MediaError::Invalid(e.to_string())
}

/// Reconnaît un document par son contenu ; `None` pour tout autre fichier
/// (archives ZIP ordinaires comprises).
pub fn detect_document(bytes: &[u8]) -> Option<DocumentKind> {
    if bytes.starts_with(b"%PDF-") {
        return Some(DocumentKind::Pdf);
    }
    if !bytes.starts_with(b"PK\x03\x04") {
        return None;
    }
    let mut zip = ZipArchive::new(Cursor::new(bytes)).ok()?;
    if zip.index_for_name("[Content_Types].xml").is_some() {
        return Some(DocumentKind::Ooxml);
    }
    let i = zip.index_for_name("mimetype")?;
    let mut mime = String::new();
    zip.by_index(i).ok()?.take(256).read_to_string(&mut mime).ok()?;
    mime.starts_with("application/vnd.oasis.opendocument").then_some(DocumentKind::OpenDocument)
}

/// Nettoie un document. `Ok(None)` : format non pris en charge (fichier
/// laissé tel quel) ; `Err` : document reconnu mais impossible à nettoyer
/// (chiffré, corrompu, trop volumineux).
pub fn sanitize_document(bytes: &[u8]) -> Result<Option<Vec<u8>>, MediaError> {
    match detect_document(bytes) {
        None => Ok(None),
        Some(DocumentKind::Pdf) => sanitize_pdf(bytes).map(Some),
        Some(kind) => sanitize_zip(bytes, kind).map(Some),
    }
}

// --- PDF ---------------------------------------------------------------------

fn sanitize_pdf(bytes: &[u8]) -> Result<Vec<u8>, MediaError> {
    if bytes.windows(8).any(|w| w == b"/Encrypt") {
        return Err(MediaError::Invalid("PDF chiffré : métadonnées non modifiables".into()));
    }
    let mut doc = Document::load_mem(bytes).map_err(invalid)?;
    if doc.is_encrypted() {
        return Err(MediaError::Invalid("PDF chiffré : métadonnées non modifiables".into()));
    }
    doc.trailer.remove(b"Info");
    doc.trailer.remove(b"ID");
    for obj in doc.objects.values_mut() {
        let dict = match obj {
            Object::Dictionary(d) => d,
            Object::Stream(s) => &mut s.dict,
            _ => continue,
        };
        // Métadonnées XMP (catalogue, pages, images) et données d'application.
        dict.remove(b"Metadata");
        dict.remove(b"PieceInfo");
        let is_annotation = matches!(dict.get(b"Type"), Ok(Object::Name(n)) if n == b"Annot")
            || dict.has(b"Subtype") && dict.has(b"Rect");
        let is_widget = matches!(dict.get(b"Subtype"), Ok(Object::Name(n)) if n == b"Widget");
        if is_annotation && !is_widget {
            // /T d'une annotation = son auteur (/T d'un champ de formulaire,
            // un nom technique, est conservé).
            dict.remove(b"T");
            dict.remove(b"M");
            dict.remove(b"CreationDate");
        }
    }
    // Info et flux XMP devenus orphelins sont supprimés ; le fichier est
    // réécrit sans ses révisions antérieures.
    doc.prune_objects();
    doc.compress();
    let mut out = Vec::new();
    doc.save_to(&mut out).map_err(invalid)?;
    // Le résultat doit rester un PDF lisible.
    Document::load_mem(&out).map_err(invalid)?;
    Ok(out)
}

// --- Office Open XML et OpenDocument -----------------------------------------

const CORE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"></cp:coreProperties>"#;
const APP_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"></Properties>"#;
const CUSTOM_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"></Properties>"#;

fn odf_meta(original: &str) -> String {
    let version = attr_value(original, "office:version").unwrap_or_else(|| "1.2".into());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" office:version="{version}"><office:meta/></office:document-meta>"#
    )
}

/// Que faire d'une entrée de l'archive.
enum Action {
    Keep,
    Drop,
    Replace(String),
    Scrub,
}

fn is_thumbnail(name: &str) -> bool {
    name.starts_with("docProps/thumbnail") || name.starts_with("Thumbnails/")
}

fn action(kind: DocumentKind, name: &str) -> Action {
    match (kind, name) {
        (_, n) if is_thumbnail(n) => Action::Drop,
        (DocumentKind::Ooxml, "docProps/core.xml") => Action::Replace(CORE_XML.into()),
        (DocumentKind::Ooxml, "docProps/app.xml") => Action::Replace(APP_XML.into()),
        (DocumentKind::Ooxml, "docProps/custom.xml") => Action::Replace(CUSTOM_XML.into()),
        (_, n) if n.ends_with(".xml") || n.ends_with(".rels") => Action::Scrub,
        _ => Action::Keep,
    }
}

/// Nettoie le XML d'une entrée (auteurs, dates, imprimante, références à la
/// miniature supprimée).
fn scrub(kind: DocumentKind, name: &str, xml: &str) -> String {
    let mut s = xml.to_owned();
    match kind {
        DocumentKind::Ooxml => {
            // Commentaires et modifications suivies (Word).
            for a in ["w:author", "w15:author", "w:initials"] {
                s = replace_attr(&s, a, ANONYMOUS);
            }
            s = replace_attr(&s, "w:date", EPOCH);
            for a in ["w15:userId", "w15:providerId"] {
                s = replace_attr(&s, a, "");
            }
            // Commentaires Excel, personnes (Excel, PowerPoint).
            if name.starts_with("xl/comments") {
                s = replace_element_text(&s, "author", ANONYMOUS);
            }
            if name.starts_with("xl/persons/") || name == "ppt/authors.xml" || name == "ppt/commentAuthors.xml" {
                for a in ["displayName", "name"] {
                    s = replace_attr(&s, a, ANONYMOUS);
                }
                s = replace_attr(&s, "initials", "A");
                for a in ["userId", "providerId"] {
                    s = replace_attr(&s, a, "");
                }
            }
            if name.starts_with("ppt/comments/") || name.starts_with("ppt/comments") {
                s = replace_attr(&s, "dt", EPOCH);
            }
            // Références à la miniature supprimée.
            if name == "_rels/.rels" {
                s = remove_elements(&s, "Relationship", |tag| tag.contains("thumbnail"));
            }
            if name == "[Content_Types].xml" {
                s = remove_elements(&s, "Override", |tag| tag.contains("/docProps/thumbnail"));
            }
        }
        DocumentKind::OpenDocument => {
            if name == "meta.xml" {
                return odf_meta(xml);
            }
            // Auteurs et dates des annotations et des modifications suivies.
            s = replace_element_text(&s, "dc:creator", ANONYMOUS);
            s = replace_element_text(&s, "dc:date", "1980-01-01T00:00:00");
            if name == "settings.xml" {
                s = replace_config_item(&s, "PrinterName");
                s = replace_config_item(&s, "PrinterSetup");
            }
            if name == "META-INF/manifest.xml" {
                s = remove_elements(&s, "manifest:file-entry", |tag| tag.contains("Thumbnails/"));
            }
        }
        DocumentKind::Pdf => {}
    }
    s
}

fn sanitize_zip(bytes: &[u8], kind: DocumentKind) -> Result<Vec<u8>, MediaError> {
    let mut zip = ZipArchive::new(Cursor::new(bytes)).map_err(invalid)?;
    if zip.len() > MAX_ENTRIES {
        return Err(MediaError::Invalid("trop d'entrées dans le document".into()));
    }
    let mut out = ZipWriter::new(Cursor::new(Vec::new()));
    let mut total: u64 = 0;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(invalid)?;
        if entry.encrypted() {
            return Err(MediaError::Invalid("document protégé par mot de passe".into()));
        }
        let name = entry.name().map_err(invalid)?.into_owned();
        let method = match entry.compression() {
            CompressionMethod::Stored => CompressionMethod::Stored,
            _ => CompressionMethod::Deflated,
        };
        let budget = MAX_UNCOMPRESSED.saturating_sub(total);
        let mut data = Vec::new();
        (&mut entry).take(budget + 1).read_to_end(&mut data).map_err(invalid)?;
        total += data.len() as u64;
        if total > MAX_UNCOMPRESSED {
            return Err(MediaError::Invalid("document trop volumineux une fois décompressé".into()));
        }
        let is_dir = entry.is_dir();
        drop(entry);
        let data = match action(kind, &name) {
            Action::Drop => continue,
            Action::Keep => data,
            Action::Replace(xml) => xml.into_bytes(),
            Action::Scrub => match String::from_utf8(data) {
                Ok(xml) => scrub(kind, &name, &xml).into_bytes(),
                Err(e) => e.into_bytes(),
            },
        };
        // Dates d'entrée neutres (1980-01-01), aucun champ supplémentaire
        // (horodatages étendus, propriétaire) n'est recopié.
        let options = SimpleFileOptions::default().compression_method(method).last_modified_time(DateTime::default());
        if is_dir {
            out.add_directory(name, options).map_err(invalid)?;
        } else {
            out.start_file(name, options).map_err(invalid)?;
            out.write_all(&data).map_err(invalid)?;
        }
    }
    let cleaned = out.finish().map_err(invalid)?.into_inner();
    // Le résultat doit rester une archive lisible du même type.
    if detect_document(&cleaned) != Some(kind) {
        return Err(MediaError::Invalid("document nettoyé illisible".into()));
    }
    Ok(cleaned)
}

// --- Outils XML (remplacements textuels ciblés) -------------------------------

/// Remplace la valeur de chaque attribut `name="…"` (ou `'…'`).
fn replace_attr(xml: &str, name: &str, value: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(pos) = find_attr(rest, name) {
        let after_eq = pos + name.len() + 1;
        let quote = rest.as_bytes()[after_eq] as char;
        let Some(end) = rest[after_eq + 1..].find(quote) else { break };
        out.push_str(&rest[..after_eq + 1]);
        out.push_str(value);
        out.push(quote);
        rest = &rest[after_eq + 1 + end + 1..];
    }
    out.push_str(rest);
    out
}

/// Position de `name=` suivi d'un guillemet, précédé d'un blanc.
fn find_attr(xml: &str, name: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(i) = xml[from..].find(name) {
        let pos = from + i;
        let before = xml[..pos].chars().next_back();
        let after = xml.as_bytes().get(pos + name.len()..pos + name.len() + 2);
        if before.is_some_and(char::is_whitespace) && matches!(after, Some([b'=', b'"' | b'\''])) {
            return Some(pos);
        }
        from = pos + name.len();
    }
    None
}

fn attr_value(xml: &str, name: &str) -> Option<String> {
    let pos = find_attr(xml, name)?;
    let after_eq = pos + name.len() + 1;
    let quote = xml.as_bytes()[after_eq] as char;
    let end = xml[after_eq + 1..].find(quote)?;
    Some(xml[after_eq + 1..after_eq + 1 + end].to_owned())
}

/// Remplace le texte de chaque élément `<tag …>texte</tag>`.
fn replace_element_text(xml: &str, tag: &str, value: &str) -> String {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = rest.as_bytes().get(i + open.len()).copied();
        if !matches!(after, Some(b'>' | b' ' | b'\t' | b'\n' | b'\r')) {
            out.push_str(&rest[..i + open.len()]);
            rest = &rest[i + open.len()..];
            continue;
        }
        let Some(gt) = rest[i..].find('>') else { break };
        let start_end = i + gt + 1;
        if rest[..start_end].ends_with("/>") {
            out.push_str(&rest[..start_end]);
            rest = &rest[start_end..];
            continue;
        }
        let Some(c) = rest[start_end..].find(&close) else { break };
        out.push_str(&rest[..start_end]);
        out.push_str(value);
        out.push_str(&close);
        rest = &rest[start_end + c + close.len()..];
    }
    out.push_str(rest);
    out
}

/// Vide la valeur d'un réglage OpenDocument `<config:config-item config:name="…">`.
fn replace_config_item(xml: &str, item: &str) -> String {
    let marker = format!("config:name=\"{item}\"");
    let close = "</config:config-item>";
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(i) = rest.find(&marker) {
        let Some(gt) = rest[i..].find('>') else { break };
        let start_end = i + gt + 1;
        let Some(c) = rest[start_end..].find(close) else { break };
        out.push_str(&rest[..start_end]);
        out.push_str(close);
        rest = &rest[start_end + c + close.len()..];
    }
    out.push_str(rest);
    out
}

/// Supprime les éléments vides `<tag …/>` dont la balise satisfait `pred`.
fn remove_elements(xml: &str, tag: &str, pred: impl Fn(&str) -> bool) -> String {
    let open = format!("<{tag} ");
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let Some(gt) = rest[i..].find('>') else { break };
        let end = i + gt + 1;
        let element = &rest[i..end];
        out.push_str(&rest[..i]);
        if !(element.ends_with("/>") && pred(element)) {
            out.push_str(element);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::{dictionary, Stream};

    const MARKERS: [&str; 6] = [
        "MARQUEUR-AUTEUR-7Q",
        "MARQUEUR-SOCIETE-7Q",
        "MARQUEUR-COMMENTAIRE-7Q",
        "marqueur.courriel@exemple.fr",
        "MARQUEUR-IMPRIMANTE-7Q",
        "2019-04-23",
    ];

    fn zip_of(entries: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data, method) in entries {
            let o = SimpleFileOptions::default()
                .compression_method(*method)
                .last_modified_time(DateTime::from_date_and_time(2019, 4, 23, 10, 0, 0).unwrap());
            w.start_file(*name, o).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn entries(bytes: &[u8]) -> Vec<(String, String, CompressionMethod, DateTime)> {
        let mut z = ZipArchive::new(Cursor::new(bytes)).unwrap();
        (0..z.len())
            .map(|i| {
                let mut e = z.by_index(i).unwrap();
                let mut s = Vec::new();
                e.read_to_end(&mut s).unwrap();
                let name = e.name().unwrap().into_owned();
                (name, String::from_utf8_lossy(&s).into_owned(), e.compression(), e.last_modified().unwrap())
            })
            .collect()
    }

    fn assert_no_markers(all: &str) {
        for m in MARKERS {
            assert!(!all.contains(m), "« {m} » encore présent");
        }
    }

    const D: CompressionMethod = CompressionMethod::Deflated;

    fn sample_docx() -> Vec<u8> {
        zip_of(&[
            ("[Content_Types].xml", br#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/docProps/thumbnail.jpeg" ContentType="image/jpeg"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#, D),
            ("_rels/.rels", br#"<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail" Target="docProps/thumbnail.jpeg"/></Relationships>"#, D),
            ("docProps/core.xml", br#"<cp:coreProperties xmlns:cp="c" xmlns:dc="d"><dc:creator>MARQUEUR-AUTEUR-7Q</dc:creator><cp:lastModifiedBy>MARQUEUR-AUTEUR-7Q</cp:lastModifiedBy><dcterms:created>2019-04-23T10:00:00Z</dcterms:created></cp:coreProperties>"#, D),
            ("docProps/app.xml", br#"<Properties><Company>MARQUEUR-SOCIETE-7Q</Company><Template>Normal.dotm</Template></Properties>"#, D),
            ("docProps/custom.xml", br#"<Properties><property name="Client"><vt:lpwstr>MARQUEUR-SOCIETE-7Q</vt:lpwstr></property></Properties>"#, D),
            ("docProps/thumbnail.jpeg", b"\xff\xd8MARQUEUR-AUTEUR-7Q", D),
            ("word/document.xml", br#"<w:document><w:body><w:p><w:r><w:t>Texte du rapport</w:t></w:r></w:p><w:ins w:id="1" w:author="MARQUEUR-AUTEUR-7Q" w:date="2019-04-23T10:00:00Z"><w:r><w:t>ajout</w:t></w:r></w:ins></w:body></w:document>"#, D),
            ("word/comments.xml", br#"<w:comments><w:comment w:id="0" w:author="MARQUEUR-AUTEUR-7Q" w:initials="MA" w:date='2019-04-23T10:00:00Z'><w:p><w:r><w:t>Relire</w:t></w:r></w:p></w:comment></w:comments>"#, D),
            ("word/people.xml", br#"<w15:people><w15:person w15:author="MARQUEUR-AUTEUR-7Q"><w15:presenceInfo w15:providerId="AD" w15:userId="marqueur.courriel@exemple.fr"/></w15:person></w15:people>"#, D),
        ])
    }

    #[test]
    fn docx_metadata_is_removed_and_content_kept() {
        let docx = sample_docx();
        assert_eq!(detect_document(&docx), Some(DocumentKind::Ooxml));
        let clean = sanitize_document(&docx).unwrap().unwrap();
        let e = entries(&clean);
        let all: String = e.iter().map(|(n, d, _, _)| format!("{n}\n{d}\n")).collect();
        assert_no_markers(&all);
        assert!(e.iter().all(|(n, ..)| !n.contains("thumbnail")), "miniature supprimée");
        assert!(e.iter().all(|(.., t)| *t == DateTime::default()), "dates d'archive neutres");
        let get = |n: &str| e.iter().find(|(m, ..)| m == n).map(|(_, d, ..)| d.clone()).unwrap();
        assert!(get("word/document.xml").contains("Texte du rapport"));
        assert!(get("word/document.xml").contains(r#"w:author="Auteur""#));
        assert!(get("word/comments.xml").contains("Relire"), "texte des commentaires conservé");
        assert!(!get("[Content_Types].xml").contains("thumbnail"));
        assert!(get("[Content_Types].xml").contains("/word/document.xml"));
        assert!(!get("_rels/.rels").contains("thumbnail"));
        assert!(get("_rels/.rels").contains("word/document.xml"));
    }

    #[test]
    fn opendocument_metadata_is_removed_and_structure_kept() {
        let odt = zip_of(&[
            ("mimetype", b"application/vnd.oasis.opendocument.text", CompressionMethod::Stored),
            ("meta.xml", br#"<office:document-meta office:version="1.3"><office:meta><meta:initial-creator>MARQUEUR-AUTEUR-7Q</meta:initial-creator><dc:creator>MARQUEUR-AUTEUR-7Q</dc:creator><meta:creation-date>2019-04-23T10:00:00</meta:creation-date><meta:user-defined meta:name="Client">MARQUEUR-SOCIETE-7Q</meta:user-defined></office:meta></office:document-meta>"#, D),
            ("content.xml", br#"<office:document-content><office:text><text:p>Texte du rapport</text:p><office:annotation><dc:creator>MARQUEUR-AUTEUR-7Q</dc:creator><dc:date>2019-04-23T10:00:00</dc:date><text:p>MARQUEUR-COMMENTAIRE-7Q-garde</text:p></office:annotation></office:text></office:document-content>"#, D),
            ("settings.xml", br#"<office:settings><config:config-item config:name="PrinterName" config:type="string">MARQUEUR-IMPRIMANTE-7Q</config:config-item><config:config-item config:name="PrinterSetup" config:type="base64Binary">TUFSUVVFVVI=</config:config-item></office:settings>"#, D),
            ("Thumbnails/thumbnail.png", b"\x89PNG MARQUEUR-AUTEUR-7Q", D),
            ("META-INF/manifest.xml", br#"<manifest:manifest><manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/><manifest:file-entry manifest:full-path="Thumbnails/thumbnail.png" manifest:media-type="image/png"/><manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/></manifest:manifest>"#, D),
        ]);
        assert_eq!(detect_document(&odt), Some(DocumentKind::OpenDocument));
        let clean = sanitize_document(&odt).unwrap().unwrap();
        let e = entries(&clean);
        // Le texte d'une annotation est du contenu : conservé ; son auteur non.
        let all: String =
            e.iter().map(|(n, d, _, _)| format!("{n}\n{}\n", d.replace("MARQUEUR-COMMENTAIRE-7Q-garde", ""))).collect();
        assert_no_markers(&all);
        assert_eq!(
            (e[0].0.as_str(), e[0].2),
            ("mimetype", CompressionMethod::Stored),
            "mimetype en tête, non compressé"
        );
        let get = |n: &str| e.iter().find(|(m, ..)| m == n).map(|(_, d, ..)| d.clone()).unwrap();
        assert!(get("content.xml").contains("Texte du rapport"));
        assert!(get("content.xml").contains("MARQUEUR-COMMENTAIRE-7Q-garde"));
        assert!(get("meta.xml").contains(r#"office:version="1.3""#));
        assert!(!get("META-INF/manifest.xml").contains("Thumbnails"));
        assert!(get("META-INF/manifest.xml").contains("content.xml"));
        assert!(e.iter().all(|(n, ..)| !n.starts_with("Thumbnails")));
    }

    fn sample_pdf() -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let content = Stream::new(dictionary! {}, b"BT /F1 12 Tf 72 712 Td (Texte du rapport) Tj ET".to_vec());
        let content_id = doc.add_object(content);
        let annot_id = doc.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Text", "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
            "T" => Object::string_literal("MARQUEUR-AUTEUR-7Q"), "Contents" => Object::string_literal("Relire"),
            "M" => Object::string_literal("D:20190423100000"),
        });
        let xmp = doc.add_object(Stream::new(
            dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
            b"<x:xmpmeta><dc:creator>MARQUEUR-AUTEUR-7Q</dc:creator><pdf:Producer>MARQUEUR-SOCIETE-7Q</pdf:Producer></x:xmpmeta>".to_vec(),
        ));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()], "Annots" => vec![annot_id.into()],
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! { "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1 }),
        );
        let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id, "Metadata" => xmp });
        let info = doc.add_object(dictionary! {
            "Author" => Object::string_literal("MARQUEUR-AUTEUR-7Q"), "Producer" => Object::string_literal("MARQUEUR-SOCIETE-7Q"),
            "CreationDate" => Object::string_literal("D:20190423100000"),
        });
        doc.trailer.set("Root", catalog);
        doc.trailer.set("Info", info);
        doc.trailer.set("ID", vec![Object::string_literal("MARQUEUR-IMPRIMANTE-7Q"), Object::string_literal("x")]);
        let mut out = Vec::new();
        doc.save_to(&mut out).unwrap();
        out
    }

    /// Tout le contenu d'un PDF, flux décompressés compris.
    fn pdf_text(bytes: &[u8]) -> String {
        let doc = Document::load_mem(bytes).unwrap();
        let mut all = format!("{:?}", doc.trailer);
        for obj in doc.objects.values() {
            match obj {
                Object::Stream(s) => {
                    all.push_str(&format!("{:?}", s.dict));
                    let data = s.decompressed_content().unwrap_or_else(|_| s.content.clone());
                    all.push_str(&String::from_utf8_lossy(&data));
                }
                o => all.push_str(&format!("{o:?}")),
            }
        }
        all
    }

    #[test]
    fn pdf_metadata_is_removed_and_content_kept() {
        let pdf = sample_pdf();
        assert!(pdf_text(&pdf).contains("MARQUEUR-AUTEUR-7Q"));
        assert_eq!(detect_document(&pdf), Some(DocumentKind::Pdf));
        let clean = sanitize_document(&pdf).unwrap().unwrap();
        let text = pdf_text(&clean);
        assert_no_markers(&text.replace("D:20190423", ""));
        assert!(!text.contains("D:20190423"), "dates supprimées");
        assert!(text.contains("Texte du rapport"), "contenu des pages conservé");
        assert!(text.contains("Relire"), "texte de l'annotation conservé");
        let doc = Document::load_mem(&clean).unwrap();
        assert_eq!(doc.get_pages().len(), 1);
    }

    #[test]
    fn other_files_are_left_alone_and_hostile_documents_refused() {
        assert_eq!(sanitize_document(b"fn main() {}").unwrap(), None);
        let plain_zip = zip_of(&[("notes.txt", b"bonjour", D)]);
        assert_eq!(sanitize_document(&plain_zip).unwrap(), None, "archive ZIP ordinaire non modifiée");
        assert!(sanitize_document(b"%PDF-1.7\n tronque").is_err());
        let mut encrypted = sample_pdf();
        encrypted.extend_from_slice(b"\n/Encrypt 9 0 R\n");
        assert!(sanitize_document(&encrypted).is_err(), "PDF chiffré : jamais modifié");
        // Bombe ZIP : plus de 200 Mio une fois décompressée.
        let zeros = vec![0u8; 64 * 1024 * 1024];
        let bomb = zip_of(&[
            ("[Content_Types].xml", b"<Types/>", D),
            ("a.bin", &zeros, D),
            ("b.bin", &zeros, D),
            ("c.bin", &zeros, D),
            ("d.bin", &zeros, D),
        ]);
        assert!(bomb.len() < 2 * 1024 * 1024);
        assert!(sanitize_document(&bomb).is_err());
    }

    #[test]
    fn xml_helpers() {
        assert_eq!(
            replace_attr(r#"<a w:author="X" xw:author="Y" w:author='Z'/>"#, "w:author", "A"),
            r#"<a w:author="A" xw:author="Y" w:author='A'/>"#
        );
        assert_eq!(
            replace_element_text("<author>X</author><authors/><author/>", "author", "A"),
            "<author>A</author><authors/><author/>"
        );
        assert_eq!(remove_elements(r#"<R a="thumb"/><R a="doc"/>"#, "R", |t| t.contains("thumb")), r#"<R a="doc"/>"#);
    }
}
