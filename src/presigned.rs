use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use hmac::digest::InvalidLength;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::form_urlencoded;
use url::Url;

type HmacSha256 = Hmac<Sha256>;

const SECRET_KEY: &[u8] = b"your_secret_key";

#[derive(Debug, Error)]
pub enum PresignedUrlError {
    #[error("Time went backwards")]
    TimeError(#[from] std::time::SystemTimeError),
    #[error("Invalid HMAC key length")]
    HmacError(#[from] InvalidLength),
}

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Invalid URL")]
    UrlParseError(#[from] url::ParseError),
    #[error("Missing file parameter")]
    MissingFileParameter,
    #[error("Missing expiry parameter")]
    MissingExpiryParameter,
    #[error("Missing signature parameter")]
    MissingSignatureParameter,
    #[error("Bad signature")]
    BadSignature,
    #[error("LinkExpired")]
    LinkExpired,
    #[error("Invalid expiry time")]
    InvalidExpiryTime(#[from] std::num::ParseIntError),
    #[error("Time went backwards")]
    TimeError(#[from] std::time::SystemTimeError),
    #[error("Invalid HMAC key length")]
    HmacError(#[from] InvalidLength),
}

pub(crate) fn generate_presigned_url(
    file_path: &str,
    expiry_seconds: u64,
) -> Result<String, PresignedUrlError> {
    let expiry_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + expiry_seconds;

    let to_sign = format!("{}:{}", file_path, expiry_time);
    let mut mac = HmacSha256::new_from_slice(SECRET_KEY)?;
    mac.update(to_sign.as_bytes());
    let signature = URL_SAFE.encode(mac.finalize().into_bytes());

    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("file", file_path)
        .append_pair("expiry", &expiry_time.to_string())
        .append_pair("signature", &signature)
        .finish();

    Ok(query)
}

pub(crate) fn verify_presigned_url(params: &str) -> Result<String, VerificationError> {
    let parsed_url = Url::parse(&format!("http://example.com?{}", params))?;
    let query_pairs = parsed_url.query_pairs();

    let mut file_path = None;
    let mut expiry = None;
    let mut signature = None;

    for (key, value) in query_pairs {
        match key.as_ref() {
            "file" => file_path = Some(value.to_string()),
            "expiry" => expiry = Some(value.to_string()),
            "signature" => signature = Some(value.to_string()),
            _ => (),
        }
    }

    let file_path = file_path.ok_or(VerificationError::MissingFileParameter)?;
    let expiry = expiry.ok_or(VerificationError::MissingExpiryParameter)?;
    let signature = signature.ok_or(VerificationError::MissingSignatureParameter)?;

    let expiry_time: u64 = expiry.parse()?;

    let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    if current_time > expiry_time {
        return Err(VerificationError::LinkExpired);
    }

    let to_sign = format!("{}:{}", file_path, expiry_time);
    let mut mac = HmacSha256::new_from_slice(SECRET_KEY)?;
    mac.update(to_sign.as_bytes());
    let expected_signature = URL_SAFE.encode(mac.finalize().into_bytes());

    if (expected_signature != signature) {
        Err(VerificationError::BadSignature)
    } else {
        Ok(file_path)
    }
}
