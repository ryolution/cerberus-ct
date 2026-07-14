use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use ring::signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo};

use crate::error::{CerberusError, Result};

pub const STATIC_CT_ROOT_HASH_LEN: usize = 32;
const RFC6962_LOG_ID_LEN: usize = 32;
const NOTE_KEY_ID_LEN: usize = 4;
const NOTE_SIGNATURE_PREFIX: &str = "\u{2014} ";
const STATIC_CT_NOTE_SIGNATURE_TYPE: u8 = 0x05;
const TLS_HASH_SHA256: u8 = 4;
const TLS_HASH_SHA384: u8 = 5;
const TLS_HASH_SHA512: u8 = 6;
const TLS_SIGNATURE_RSA: u8 = 1;
const TLS_SIGNATURE_ECDSA: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCtCheckpoint {
    pub origin: String,
    pub size: u64,
    pub root_hash: String,
    pub signatures: Vec<String>,
    pub raw: String,
    #[serde(skip)]
    note_text: String,
}

#[derive(Debug, Clone)]
pub struct TrustedCtLog {
    pub origin: String,
    pub base_url: Url,
    public_key_bytes: Vec<u8>,
    log_id: [u8; RFC6962_LOG_ID_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NoteSignature {
    key_name: String,
    key_id: [u8; NOTE_KEY_ID_LEN],
    body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rfc6962NoteSignature {
    timestamp: u64,
    hash_algorithm: u8,
    signature_algorithm: u8,
    signature: Vec<u8>,
}

impl TrustedCtLog {
    pub fn from_base64_public_key(
        origin: impl Into<String>,
        base_url: impl AsRef<str>,
        public_key: impl AsRef<str>,
    ) -> Result<Self> {
        Self::from_base64_public_key_and_log_id(origin, base_url, public_key, None::<&str>)
    }

    pub fn from_base64_public_key_and_log_id(
        origin: impl Into<String>,
        base_url: impl AsRef<str>,
        public_key: impl AsRef<str>,
        log_id: Option<impl AsRef<str>>,
    ) -> Result<Self> {
        let origin = origin.into();
        let public_key_der_or_raw = decode_public_key_material(public_key.as_ref())?;
        let derived_log_id: [u8; RFC6962_LOG_ID_LEN] =
            Sha256::digest(&public_key_der_or_raw).into();
        let log_id = match log_id {
            Some(log_id) => decode_log_id(log_id.as_ref())?,
            None => derived_log_id,
        };
        let public_key_bytes = extract_spki_public_key(&public_key_der_or_raw)
            .unwrap_or_else(|| public_key_der_or_raw.clone());
        let base_url = Url::parse(base_url.as_ref()).map_err(|error| {
            CerberusError::CtSource(format!("trusted CT log base URL is invalid: {error}"))
        })?;

        Ok(Self {
            origin,
            base_url,
            public_key_bytes,
            log_id,
        })
    }

    pub fn verify_checkpoint(&self, checkpoint: &StaticCtCheckpoint) -> Result<()> {
        if checkpoint.origin != self.origin {
            return Err(CerberusError::CtSource(format!(
                "checkpoint origin `{}` does not match trusted log origin `{}`",
                checkpoint.origin, self.origin
            )));
        }

        checkpoint.root_hash_bytes()?;

        if checkpoint.signatures.is_empty() {
            return Err(CerberusError::CtSource(
                "checkpoint does not contain a signature".to_string(),
            ));
        }

        let expected_key_id =
            note_key_id(&self.origin, STATIC_CT_NOTE_SIGNATURE_TYPE, &self.log_id);
        let mut malformed_signature_count = 0usize;
        let mut unknown_signature_count = 0usize;

        for signature_line in &checkpoint.signatures {
            let note_signature = match parse_note_signature_line(signature_line) {
                Ok(note_signature) => note_signature,
                Err(_) => {
                    malformed_signature_count += 1;
                    continue;
                }
            };

            if note_signature.key_name != self.origin || note_signature.key_id != expected_key_id {
                unknown_signature_count += 1;
                continue;
            }

            verify_static_ct_note_signature(checkpoint, &note_signature, &self.public_key_bytes)?;
            return Ok(());
        }

        Err(CerberusError::CtSource(format!(
            "checkpoint does not contain a signature from trusted key `{}`; {malformed_signature_count} malformed signature line(s), {unknown_signature_count} unknown signature line(s)",
            self.origin
        )))
    }
}

impl StaticCtCheckpoint {
    pub fn root_hash_bytes(&self) -> Result<[u8; STATIC_CT_ROOT_HASH_LEN]> {
        decode_root_hash(&self.root_hash)
    }

    pub fn root_hash_hex(&self) -> Result<String> {
        Ok(hex::encode(self.root_hash_bytes()?))
    }

    pub fn signed_payload(&self) -> String {
        if self.note_text.is_empty() {
            format!("{}\n{}\n{}\n", self.origin, self.size, self.root_hash)
        } else {
            self.note_text.clone()
        }
    }
}

pub fn parse_static_ct_checkpoint(input: &str) -> Result<StaticCtCheckpoint> {
    validate_note_text(input)?;

    let separator_index = input.rfind("\n\n").ok_or_else(|| {
        CerberusError::CtSource(
            "checkpoint is missing the signed-note signature separator".to_string(),
        )
    })?;
    let note_text = &input[..separator_index + 1];
    let signature_block = &input[separator_index + 2..];
    let note_body = note_text.strip_suffix('\n').ok_or_else(|| {
        CerberusError::CtSource("checkpoint note text is not newline terminated".to_string())
    })?;
    let note_lines = note_body.split('\n').collect::<Vec<_>>();

    if note_lines.len() != 3 {
        return Err(CerberusError::CtSource(
            "Static CT checkpoints must contain exactly origin, tree size, and root hash lines"
                .to_string(),
        ));
    }

    let origin = note_lines[0];
    if origin.is_empty() {
        return Err(CerberusError::CtSource(
            "checkpoint is missing origin".to_string(),
        ));
    }

    let size_line = note_lines[1];
    validate_tree_size_line(size_line)?;
    let size = size_line.parse::<u64>().map_err(|_| {
        CerberusError::CtSource(format!("checkpoint has invalid tree size: {size_line}"))
    })?;

    let root_hash = note_lines[2];
    if root_hash.is_empty() {
        return Err(CerberusError::CtSource(
            "checkpoint is missing root hash".to_string(),
        ));
    }
    let _ = decode_root_hash(root_hash)?;

    let signatures = signature_block
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    if signatures.is_empty() {
        return Err(CerberusError::CtSource(
            "checkpoint is missing signature lines".to_string(),
        ));
    }

    if signatures
        .iter()
        .any(|line| !line.starts_with(NOTE_SIGNATURE_PREFIX))
    {
        return Err(CerberusError::CtSource(
            "checkpoint contains a malformed signed-note signature line".to_string(),
        ));
    }

    Ok(StaticCtCheckpoint {
        origin: origin.to_string(),
        size,
        root_hash: root_hash.to_string(),
        signatures,
        raw: input.to_string(),
        note_text: note_text.to_string(),
    })
}

fn verify_static_ct_note_signature(
    checkpoint: &StaticCtCheckpoint,
    note_signature: &NoteSignature,
    public_key_bytes: &[u8],
) -> Result<()> {
    let parsed = parse_rfc6962_note_signature_body(&note_signature.body)?;
    let signed_data = rfc6962_tree_head_signature_input(
        parsed.timestamp,
        checkpoint.size,
        &checkpoint.root_hash_bytes()?,
    );

    if verify_tls_digitally_signed(
        parsed.hash_algorithm,
        parsed.signature_algorithm,
        public_key_bytes,
        &signed_data,
        &parsed.signature,
    ) {
        Ok(())
    } else {
        Err(CerberusError::CtSource(
            "checkpoint RFC6962 tree-head signature verification failed".to_string(),
        ))
    }
}

fn parse_note_signature_line(signature_line: &str) -> Result<NoteSignature> {
    let rest = signature_line
        .strip_prefix(NOTE_SIGNATURE_PREFIX)
        .ok_or_else(|| {
            CerberusError::CtSource("note signature line must start with an em dash".to_string())
        })?;
    let (key_name, encoded_signature) = rest.split_once(' ').ok_or_else(|| {
        CerberusError::CtSource("note signature line is missing key name or signature".to_string())
    })?;

    if key_name.is_empty() || key_name.contains('+') || key_name.chars().any(char::is_whitespace) {
        return Err(CerberusError::CtSource(
            "note signature key name is invalid".to_string(),
        ));
    }

    let signature = decode_base64(encoded_signature).map_err(|error| {
        CerberusError::CtSource(format!("note signature is not valid base64: {error}"))
    })?;

    if signature.len() < NOTE_KEY_ID_LEN {
        return Err(CerberusError::CtSource(
            "note signature is shorter than the key ID".to_string(),
        ));
    }

    let key_id = signature[..NOTE_KEY_ID_LEN]
        .try_into()
        .expect("slice length is fixed");
    let body = signature[NOTE_KEY_ID_LEN..].to_vec();

    Ok(NoteSignature {
        key_name: key_name.to_string(),
        key_id,
        body,
    })
}

fn parse_rfc6962_note_signature_body(body: &[u8]) -> Result<Rfc6962NoteSignature> {
    if body.len() < 12 {
        return Err(CerberusError::CtSource(
            "RFC6962 checkpoint signature body is too short".to_string(),
        ));
    }

    let timestamp = u64::from_be_bytes(body[..8].try_into().expect("slice length is fixed"));
    let hash_algorithm = body[8];
    let signature_algorithm = body[9];
    let signature_len =
        u16::from_be_bytes(body[10..12].try_into().expect("slice length is fixed")) as usize;
    let expected_len = 12usize.checked_add(signature_len).ok_or_else(|| {
        CerberusError::CtSource("RFC6962 checkpoint signature length overflow".to_string())
    })?;

    if body.len() != expected_len {
        return Err(CerberusError::CtSource(format!(
            "RFC6962 checkpoint signature body has {} bytes but declares {signature_len} signature bytes",
            body.len()
        )));
    }

    Ok(Rfc6962NoteSignature {
        timestamp,
        hash_algorithm,
        signature_algorithm,
        signature: body[12..].to_vec(),
    })
}

fn rfc6962_tree_head_signature_input(
    timestamp: u64,
    tree_size: u64,
    root_hash: &[u8; STATIC_CT_ROOT_HASH_LEN],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(50);
    input.push(0);
    input.push(1);
    input.extend_from_slice(&timestamp.to_be_bytes());
    input.extend_from_slice(&tree_size.to_be_bytes());
    input.extend_from_slice(root_hash);
    input
}

fn verify_tls_digitally_signed(
    hash_algorithm: u8,
    signature_algorithm: u8,
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    match (hash_algorithm, signature_algorithm) {
        (TLS_HASH_SHA256, TLS_SIGNATURE_RSA) => verify_with_algorithm(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            public_key_bytes,
            message,
            signature_bytes,
        ),
        (TLS_HASH_SHA384, TLS_SIGNATURE_RSA) => verify_with_algorithm(
            &signature::RSA_PKCS1_2048_8192_SHA384,
            public_key_bytes,
            message,
            signature_bytes,
        ),
        (TLS_HASH_SHA512, TLS_SIGNATURE_RSA) => verify_with_algorithm(
            &signature::RSA_PKCS1_2048_8192_SHA512,
            public_key_bytes,
            message,
            signature_bytes,
        ),
        (TLS_HASH_SHA256, TLS_SIGNATURE_ECDSA) => {
            verify_with_algorithm(
                &signature::ECDSA_P256_SHA256_ASN1,
                public_key_bytes,
                message,
                signature_bytes,
            ) || verify_with_algorithm(
                &signature::ECDSA_P384_SHA256_ASN1,
                public_key_bytes,
                message,
                signature_bytes,
            )
        }
        (TLS_HASH_SHA384, TLS_SIGNATURE_ECDSA) => {
            verify_with_algorithm(
                &signature::ECDSA_P256_SHA384_ASN1,
                public_key_bytes,
                message,
                signature_bytes,
            ) || verify_with_algorithm(
                &signature::ECDSA_P384_SHA384_ASN1,
                public_key_bytes,
                message,
                signature_bytes,
            )
        }
        _ => false,
    }
}

fn verify_with_algorithm(
    algorithm: &'static dyn signature::VerificationAlgorithm,
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    signature::UnparsedPublicKey::new(algorithm, public_key_bytes)
        .verify(message, signature_bytes)
        .is_ok()
}

fn note_key_id(
    key_name: &str,
    signature_type: u8,
    log_id: &[u8; RFC6962_LOG_ID_LEN],
) -> [u8; NOTE_KEY_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(key_name.as_bytes());
    hasher.update([b'\n', signature_type]);
    hasher.update(log_id);
    let digest = hasher.finalize();
    digest[..NOTE_KEY_ID_LEN]
        .try_into()
        .expect("slice length is fixed")
}

fn decode_public_key_material(input: &str) -> Result<Vec<u8>> {
    if input.contains("-----BEGIN PUBLIC KEY-----") {
        let body = input
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        return decode_base64(&body).map_err(|error| {
            CerberusError::CtSource(format!("trusted CT log public key PEM is invalid: {error}"))
        });
    }

    decode_base64(input).map_err(|error| {
        CerberusError::CtSource(format!("trusted CT log public key is not base64: {error}"))
    })
}

fn extract_spki_public_key(input: &[u8]) -> Option<Vec<u8>> {
    let Ok((remaining, spki)) = SubjectPublicKeyInfo::from_der(input) else {
        return None;
    };

    if !remaining.is_empty() {
        return None;
    }

    Some(spki.subject_public_key.data.to_vec())
}

fn decode_log_id(input: &str) -> Result<[u8; RFC6962_LOG_ID_LEN]> {
    let bytes = if input.len() == RFC6962_LOG_ID_LEN * 2
        && input.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        hex::decode(input).map_err(|error| {
            CerberusError::CtSource(format!("trusted CT log ID is not valid hex: {error}"))
        })?
    } else {
        decode_base64(input).map_err(|error| {
            CerberusError::CtSource(format!("trusted CT log ID is not valid base64: {error}"))
        })?
    };

    bytes.try_into().map_err(|bytes: Vec<u8>| {
        CerberusError::CtSource(format!(
            "trusted CT log ID must be {RFC6962_LOG_ID_LEN} bytes, got {}",
            bytes.len()
        ))
    })
}

fn decode_root_hash(root_hash: &str) -> Result<[u8; STATIC_CT_ROOT_HASH_LEN]> {
    let bytes = decode_base64(root_hash).map_err(|error| {
        CerberusError::CtSource(format!("checkpoint root hash is not valid base64: {error}"))
    })?;

    bytes.try_into().map_err(|bytes: Vec<u8>| {
        CerberusError::CtSource(format!(
            "checkpoint root hash must be {STATIC_CT_ROOT_HASH_LEN} bytes, got {}",
            bytes.len()
        ))
    })
}

fn decode_base64(input: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    let compact = input
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>();
    STANDARD
        .decode(&compact)
        .or_else(|_| STANDARD_NO_PAD.decode(compact))
}

fn validate_note_text(input: &str) -> Result<()> {
    if input.chars().any(|ch| ch.is_ascii_control() && ch != '\n') {
        return Err(CerberusError::CtSource(
            "checkpoint contains an ASCII control character other than newline".to_string(),
        ));
    }

    Ok(())
}

fn validate_tree_size_line(size_line: &str) -> Result<()> {
    if size_line.is_empty() {
        return Err(CerberusError::CtSource(
            "checkpoint is missing tree size".to_string(),
        ));
    }

    if size_line.len() > 1 && size_line.starts_with('0') {
        return Err(CerberusError::CtSource(format!(
            "checkpoint tree size has a leading zero: {size_line}"
        )));
    }

    if !size_line.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CerberusError::CtSource(format!(
            "checkpoint has invalid tree size: {size_line}"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        NOTE_KEY_ID_LEN, STATIC_CT_NOTE_SIGNATURE_TYPE, STATIC_CT_ROOT_HASH_LEN, TLS_HASH_SHA256,
        TLS_SIGNATURE_ECDSA, TrustedCtLog, note_key_id, parse_static_ct_checkpoint,
        rfc6962_tree_head_signature_input,
    };
    use base64::Engine;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    use sha2::Digest;

    const ORIGIN: &str = "example.com/log";

    fn root_hash() -> String {
        base64::engine::general_purpose::STANDARD.encode([7u8; STATIC_CT_ROOT_HASH_LEN])
    }

    #[test]
    fn parses_checkpoint() {
        let input = format!(
            "example.com/log\n42\n{}\n\n\u{2014} example.com/log abcdef\n",
            root_hash()
        );
        let checkpoint = parse_static_ct_checkpoint(&input).unwrap();

        assert_eq!(checkpoint.origin, "example.com/log");
        assert_eq!(checkpoint.size, 42);
        assert_eq!(checkpoint.root_hash, root_hash());
        assert_eq!(checkpoint.signatures.len(), 1);
        assert_eq!(
            checkpoint.signed_payload(),
            format!("example.com/log\n42\n{}\n", root_hash())
        );
    }

    #[test]
    fn rejects_missing_origin() {
        assert!(parse_static_ct_checkpoint("").is_err());
    }

    #[test]
    fn rejects_invalid_size() {
        let input = format!(
            "example.com/log\nnot-a-number\n{}\n\n\u{2014} example.com/log abcdef\n",
            root_hash()
        );
        assert!(parse_static_ct_checkpoint(&input).is_err());
    }

    #[test]
    fn rejects_extension_lines_for_static_ct() {
        let input = format!(
            "example.com/log\n42\n{}\nextension\n\n\u{2014} example.com/log abcdef\n",
            root_hash()
        );
        assert!(parse_static_ct_checkpoint(&input).is_err());
    }

    #[test]
    fn rejects_short_root_hash() {
        let input =
            "example.com/log\n42\nZmFrZS1yb290LWhhc2g=\n\n\u{2014} example.com/log abcdef\n";
        assert!(parse_static_ct_checkpoint(input).is_err());
    }

    #[test]
    fn rejects_missing_signature() {
        let input = format!("example.com/log\n42\n{}\n", root_hash());
        assert!(parse_static_ct_checkpoint(&input).is_err());
    }

    #[test]
    fn verifies_rfc6962_checkpoint_note_signature() {
        let (public_key, signed_note) = signed_checkpoint_note(42, &root_hash());
        let checkpoint = parse_static_ct_checkpoint(&signed_note).unwrap();
        let trusted = TrustedCtLog::from_base64_public_key(
            ORIGIN,
            "https://example.com/log",
            base64::engine::general_purpose::STANDARD.encode(public_key),
        )
        .unwrap();

        trusted.verify_checkpoint(&checkpoint).unwrap();
    }

    #[test]
    fn rejects_tampered_checkpoint_note_signature() {
        let (public_key, signed_note) = signed_checkpoint_note(42, &root_hash());
        let tampered = signed_note.replacen("\n42\n", "\n43\n", 1);
        let checkpoint = parse_static_ct_checkpoint(&tampered).unwrap();
        let trusted = TrustedCtLog::from_base64_public_key(
            ORIGIN,
            "https://example.com/log",
            base64::engine::general_purpose::STANDARD.encode(public_key),
        )
        .unwrap();

        assert!(trusted.verify_checkpoint(&checkpoint).is_err());
    }

    fn signed_checkpoint_note(size: u64, root_hash: &str) -> (Vec<u8>, String) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        let log_id = sha2::Sha256::digest(&public_key).into();
        let key_id = note_key_id(ORIGIN, STATIC_CT_NOTE_SIGNATURE_TYPE, &log_id);
        let timestamp = 1_700_000_000_000u64;
        let root_hash_bytes: [u8; STATIC_CT_ROOT_HASH_LEN] =
            base64::engine::general_purpose::STANDARD
                .decode(root_hash)
                .unwrap()
                .try_into()
                .unwrap();
        let signature_input = rfc6962_tree_head_signature_input(timestamp, size, &root_hash_bytes);
        let signature = key_pair.sign(&rng, &signature_input).unwrap();
        let mut signature_body = Vec::new();
        signature_body.extend_from_slice(&timestamp.to_be_bytes());
        signature_body.push(TLS_HASH_SHA256);
        signature_body.push(TLS_SIGNATURE_ECDSA);
        signature_body.extend_from_slice(&(signature.as_ref().len() as u16).to_be_bytes());
        signature_body.extend_from_slice(signature.as_ref());

        let mut note_signature = Vec::with_capacity(NOTE_KEY_ID_LEN + signature_body.len());
        note_signature.extend_from_slice(&key_id);
        note_signature.extend_from_slice(&signature_body);

        let note_signature = base64::engine::general_purpose::STANDARD.encode(note_signature);
        let note = format!("{ORIGIN}\n{size}\n{root_hash}\n\n\u{2014} {ORIGIN} {note_signature}\n");

        (public_key, note)
    }
}
