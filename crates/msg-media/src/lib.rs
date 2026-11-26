//! Préparation des images avant envoi.
//!
//! Toute image est **décodée puis ré-encodée** : seules les données de pixels
//! survivent. EXIF (dont la position GPS, le modèle d'appareil, la date),
//! XMP, IPTC, profils et commentaires disparaissent par construction, sans
//! dépendre d'une liste de balises à retirer. L'orientation EXIF est
//! appliquée aux pixels avant d'être supprimée.
//!
//! Le décodage se fait en Rust sûr avec des limites strictes (dimensions,
//! mémoire) contre les « bombes de décompression ».
#![forbid(unsafe_code)]

use std::io::Cursor;

pub mod documents;
pub use documents::{detect_document, sanitize_document, DocumentKind};

use image::codecs::jpeg::JpegEncoder;
use image::{DynamicImage, ImageDecoder, ImageFormat, ImageReader, Limits};

/// Dimensions maximales acceptées (côté) et mémoire de décodage.
pub const MAX_DIMENSION: u32 = 12_000;
/// Nombre maximal de pixels (≈ 50 Mpx, photos de 48 Mpx comprises), vérifié
/// **avant** le décodage : un fichier minuscule annonçant une image géante
/// (bombe de décompression, trouvée par le fuzzing) est refusé d'emblée.
pub const MAX_PIXELS: u64 = 50_000_000;
pub const MAX_DECODE_BYTES: u64 = 256 * 1024 * 1024;
/// Côté maximal d'une miniature et taille cible.
pub const THUMBNAIL_SIDE: u32 = 320;
pub const THUMBNAIL_MAX_BYTES: usize = 48 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("format d'image non pris en charge")]
    Unsupported,
    #[error("image invalide ou trop grande : {0}")]
    Invalid(String),
}

/// Image nettoyée prête à être chiffrée.
#[derive(Debug, Clone)]
pub struct CleanImage {
    pub bytes: Vec<u8>,
    pub mime: &'static str,
    /// Extension conseillée pour le nom de fichier.
    pub extension: &'static str,
    pub width: u32,
    pub height: u32,
    /// Miniature JPEG (sans métadonnées).
    pub thumbnail: Vec<u8>,
}

/// Format d'image reconnu par signature (pas par extension).
pub fn detect(bytes: &[u8]) -> Option<ImageFormat> {
    match image::guess_format(bytes).ok()? {
        f @ (ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::Gif | ImageFormat::WebP) => Some(f),
        _ => None,
    }
}

fn limits() -> Limits {
    let mut l = Limits::default();
    l.max_image_width = Some(MAX_DIMENSION);
    l.max_image_height = Some(MAX_DIMENSION);
    l.max_alloc = Some(MAX_DECODE_BYTES);
    l
}

fn decode(bytes: &[u8], format: ImageFormat) -> Result<DynamicImage, MediaError> {
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    reader.limits(limits());
    let mut decoder = reader.into_decoder().map_err(|e| MediaError::Invalid(e.to_string()))?;
    let (w, h) = decoder.dimensions();
    if u64::from(w) * u64::from(h) > MAX_PIXELS {
        return Err(MediaError::Invalid(format!("{w} × {h} pixels (maximum {MAX_PIXELS})")));
    }
    let orientation = decoder.orientation().ok();
    let mut img = DynamicImage::from_decoder(decoder).map_err(|e| MediaError::Invalid(e.to_string()))?;
    if let Some(o) = orientation {
        img.apply_orientation(o);
    }
    Ok(img)
}

fn encode_jpeg(img: &DynamicImage, quality: u8) -> Result<Vec<u8>, MediaError> {
    let mut out = Vec::new();
    let rgb = img.to_rgb8();
    JpegEncoder::new_with_quality(&mut out, quality)
        .encode_image(&rgb)
        .map_err(|e| MediaError::Invalid(e.to_string()))?;
    Ok(out)
}

fn encode_png(img: &DynamicImage) -> Result<Vec<u8>, MediaError> {
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png).map_err(|e| MediaError::Invalid(e.to_string()))?;
    Ok(out)
}

/// Miniature JPEG d'au plus [`THUMBNAIL_SIDE`] px et [`THUMBNAIL_MAX_BYTES`] octets.
fn thumbnail(img: &DynamicImage) -> Result<Vec<u8>, MediaError> {
    let mut side = THUMBNAIL_SIDE;
    loop {
        let t = img.thumbnail(side, side);
        for q in [70u8, 55, 40] {
            let bytes = encode_jpeg(&t, q)?;
            if bytes.len() <= THUMBNAIL_MAX_BYTES {
                return Ok(bytes);
            }
        }
        side /= 2;
        if side < 32 {
            return Err(MediaError::Invalid("miniature impossible".into()));
        }
    }
}

/// Nettoie une image : JPEG → JPEG (qualité 90), autres formats → PNG
/// (sans perte ; une GIF animée est réduite à sa première image).
pub fn sanitize_image(bytes: &[u8]) -> Result<CleanImage, MediaError> {
    let format = detect(bytes).ok_or(MediaError::Unsupported)?;
    let img = decode(bytes, format)?;
    let (bytes, mime, extension) = match format {
        ImageFormat::Jpeg => (encode_jpeg(&img, 90)?, "image/jpeg", "jpg"),
        _ => (encode_png(&img)?, "image/png", "png"),
    };
    Ok(CleanImage { thumbnail: thumbnail(&img)?, bytes, mime, extension, width: img.width(), height: img.height() })
}

/// Type MIME d'un fichier non image, déduit de son extension (liste courte ;
/// à défaut `application/octet-stream`).
pub fn mime_from_name(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "txt" | "md" => "text/plain",
        "csv" => "text/csv",
        "zip" => "application/zip",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "odp" => "application/vnd.oasis.opendocument.presentation",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Rgb, RgbImage};

    const MARKER: &[u8] = b"GPS-MARQUEUR-48.8566N-2.3522E";

    fn sample(w: u32, h: u32) -> DynamicImage {
        DynamicImage::ImageRgb8(RgbImage::from_fn(w, h, |x, y| Rgb([(x % 256) as u8, (y % 256) as u8, 128])))
    }

    /// JPEG avec un segment APP1 « Exif » contenant un marqueur GPS factice.
    fn jpeg_with_exif() -> Vec<u8> {
        let plain = encode_jpeg(&sample(64, 48), 90).unwrap();
        let mut payload = b"Exif\0\0MM\0*\0\0\0\x08".to_vec();
        payload.extend_from_slice(MARKER);
        let len = (payload.len() + 2) as u16;
        let mut out = vec![0xFF, 0xD8, 0xFF, 0xE1];
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&payload);
        out.extend_from_slice(&plain[2..]);
        out
    }

    /// PNG avec un bloc tEXt de métadonnées.
    fn png_with_text() -> Vec<u8> {
        let plain = encode_png(&sample(40, 30)).unwrap();
        // Insertion d'un bloc tEXt juste après IHDR (8 + 25 octets).
        let mut data = b"tEXt".to_vec();
        data.extend_from_slice(b"Comment\0");
        data.extend_from_slice(MARKER);
        let crc = crc32(&data);
        let mut chunk = ((data.len() - 4) as u32).to_be_bytes().to_vec();
        chunk.extend_from_slice(&data);
        chunk.extend_from_slice(&crc.to_be_bytes());
        let mut out = plain[..33].to_vec();
        out.extend_from_slice(&chunk);
        out.extend_from_slice(&plain[33..]);
        out
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for b in data {
            crc ^= u32::from(*b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            }
        }
        !crc
    }

    fn contains(h: &[u8], n: &[u8]) -> bool {
        h.windows(n.len()).any(|w| w == n)
    }

    #[test]
    fn jpeg_exif_is_removed() {
        let input = jpeg_with_exif();
        assert!(contains(&input, MARKER) && contains(&input, b"Exif"));
        let clean = sanitize_image(&input).unwrap();
        assert_eq!(clean.mime, "image/jpeg");
        assert!(!contains(&clean.bytes, MARKER), "marqueur GPS toujours présent");
        assert!(!contains(&clean.bytes, b"Exif"), "segment EXIF toujours présent");
        assert!(!contains(&clean.thumbnail, MARKER));
        assert_eq!((clean.width, clean.height), (64, 48));
        assert!(clean.thumbnail.len() <= THUMBNAIL_MAX_BYTES);
    }

    #[test]
    fn png_text_chunks_are_removed() {
        let input = png_with_text();
        assert!(contains(&input, MARKER));
        image::load_from_memory(&input).expect("PNG de test valide");
        let clean = sanitize_image(&input).unwrap();
        assert_eq!(clean.mime, "image/png");
        assert!(!contains(&clean.bytes, MARKER));
        assert!(!contains(&clean.bytes, b"tEXt"));
    }

    #[test]
    fn rejects_non_images_and_garbage() {
        assert!(matches!(sanitize_image(b"%PDF-1.7 pas une image"), Err(MediaError::Unsupported)));
        let mut broken = encode_jpeg(&sample(10, 10), 90).unwrap();
        broken.truncate(30);
        assert!(sanitize_image(&broken).is_err());
    }

    #[test]
    fn oversized_dimensions_are_rejected() {
        // En-tête PNG annonçant 20000×20000 px (bombe de décompression).
        let mut png = encode_png(&sample(1, 1)).unwrap();
        png[16..20].copy_from_slice(&20_000u32.to_be_bytes());
        png[20..24].copy_from_slice(&20_000u32.to_be_bytes());
        assert!(sanitize_image(&png).is_err());
    }

    #[test]
    fn large_image_thumbnail_is_bounded() {
        let clean = sanitize_image(&encode_png(&sample(2000, 1500)).unwrap()).unwrap();
        let t = image::load_from_memory(&clean.thumbnail).unwrap();
        assert!(t.width() <= THUMBNAIL_SIDE && t.height() <= THUMBNAIL_SIDE);
        assert!(clean.thumbnail.len() <= THUMBNAIL_MAX_BYTES);
    }

    #[test]
    fn mime_guess() {
        assert_eq!(mime_from_name("Rapport.PDF"), "application/pdf");
        assert_eq!(mime_from_name("sans-extension"), "application/octet-stream");
    }

    /// Régression (fuzzing) : GIF de 150 octets annonçant 11 308 × 11 308 px.
    #[test]
    fn decompression_bomb_is_rejected_before_decoding() {
        let bomb = include_bytes!("../tests/data/gif-bombe.gif");
        let t = std::time::Instant::now();
        let e = sanitize_image(bomb).unwrap_err();
        assert!(e.to_string().contains("pixels"), "{e}");
        assert!(t.elapsed() < std::time::Duration::from_millis(500), "{:?}", t.elapsed());
    }
}
