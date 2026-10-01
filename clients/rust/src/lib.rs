use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use reqwest::blocking::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const INFO: &[u8] = b"cardkey-enc-v1";
const IV_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedCardKey {
    pub iv: String,
    pub data: String,
    pub tag: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse {
    pub code: i32,
    pub message: String,
    pub success: bool,
    pub server_time: i64,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Error)]
pub enum CardKeyError {
    #[error("CardKey API error {code}: {message}")]
    Api {
        code: i32,
        message: String,
        http_status: u16,
        response: Box<ApiResponse>,
    },
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("response signature verification failed: {0}")]
    ResponseSignature(String),
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub fn normalize_path(path: &str) -> String {
    let path = path.split(['?', '#']).next().unwrap_or("");
    if path.is_empty() {
        return "/".to_owned();
    }
    let normalized = path.split('/').filter(|part| !part.is_empty()).collect::<Vec<_>>().join("/");
    format!("/{normalized}")
}

fn sha256_hex(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn canonical_request(method: &str, path: &str, timestamp: &str, nonce: &str, raw_body: &[u8]) -> String {
    format!("{}\n{}\n{}\n{}\n{}", method.to_uppercase(), normalize_path(path), timestamp, nonce, sha256_hex(raw_body))
}

pub fn sign_request(secret: &str, method: &str, path: &str, timestamp: &str, nonce: &str, raw_body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(canonical_request(method, path, timestamp, nonce, raw_body).as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

pub fn canonical_response(timestamp: &str, nonce: &str, raw_body: &[u8]) -> String {
    format!("{}\n{}\n{}", timestamp, nonce, sha256_hex(raw_body))
}

pub fn sign_response(secret: &str, timestamp: &str, nonce: &str, raw_body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(canonical_response(timestamp, nonce, raw_body).as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

pub fn verify_signature(secret: &str, canonical: &str, supplied: &str) -> bool {
    let supplied = match decode_hex(supplied.trim()) {
        Some(value) => value,
        None => return false,
    };
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    mac.verify_slice(&supplied).is_ok()
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)? as u8;
        let low = (pair[1] as char).to_digit(16)? as u8;
        decoded.push((high << 4) | low);
    }
    Some(decoded)
}

pub fn error_message(code: i32) -> &'static str {
    match code {
        0 => "操作成功",
        1001 => "请求参数不合法",
        1002 => "AppID 不存在",
        1003 => "应用已被禁用",
        1004 => "签名验证失败",
        1005 => "请求时间戳超出允许范围",
        1006 => "随机数已被使用（疑似重放请求）",
        1007 => "IP 不在白名单内",
        1008 => "请求过于频繁，请稍后再试",
        1009 => "今日调用配额已用尽",
        1010 => "缺少必要的认证头",
        1011 => "卡密解密失败，请检查加密参数",
        2001 => "卡密不存在",
        2002 => "卡密已被禁用",
        2003 => "卡密已过期",
        2004 => "卡密尚未激活",
        2005 => "卡密次数已用完",
        2006 => "卡密已被激活",
        2007 => "设备不匹配，该卡密已绑定其他设备",
        2008 => "该卡密尚未绑定任何设备",
        2009 => "该卡密不属于当前应用",
        2010 => "当前卡密类型不支持该操作",
        2011 => "卡密已处于禁用状态",
        4004 => "接口不存在",
        4005 => "请求方法不被允许",
        4013 => "请求体过大",
        5000 => "服务器内部错误",
        5003 => "系统维护中",
        _ => "未知 API 错误",
    }
}

pub fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

pub fn derive_transport_key(secret: &str, app_id: &str) -> Result<[u8; 32], CardKeyError> {
    let hk = Hkdf::<Sha256>::new(Some(app_id.as_bytes()), secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(INFO, &mut key).map_err(|_| CardKeyError::Protocol("HKDF expansion failed".into()))?;
    Ok(key)
}

pub fn encrypt_card_key(plaintext: &str, secret: &str, app_id: &str) -> Result<EncryptedCardKey, CardKeyError> {
    let key = derive_transport_key(secret, app_id)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CardKeyError::Protocol("AES key setup failed".into()))?;
    let mut iv = [0u8; IV_LENGTH];
    OsRng.fill_bytes(&mut iv);
    let encrypted = cipher.encrypt(Nonce::from_slice(&iv), Payload { msg: plaintext.as_bytes(), aad: app_id.as_bytes() }).map_err(|_| CardKeyError::Protocol("CardKey encryption failed".into()))?;
    let split = encrypted.len() - TAG_LENGTH;
    Ok(EncryptedCardKey { iv: B64.encode(iv), data: B64.encode(&encrypted[..split]), tag: B64.encode(&encrypted[split..]) })
}

pub fn decrypt_card_key(payload: &EncryptedCardKey, secret: &str, app_id: &str) -> Result<String, CardKeyError> {
    let key = derive_transport_key(secret, app_id)?;
    let iv = B64.decode(&payload.iv).map_err(|_| CardKeyError::Protocol("invalid Base64 IV".into()))?;
    let mut encrypted = B64.decode(&payload.data).map_err(|_| CardKeyError::Protocol("invalid Base64 data".into()))?;
    let tag = B64.decode(&payload.tag).map_err(|_| CardKeyError::Protocol("invalid Base64 tag".into()))?;
    if iv.len() != IV_LENGTH || tag.len() != TAG_LENGTH {
        return Err(CardKeyError::Protocol("invalid CardKey transport payload length".into()));
    }
    encrypted.extend_from_slice(&tag);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CardKeyError::Protocol("AES key setup failed".into()))?;
    let plain = cipher.decrypt(Nonce::from_slice(&iv), Payload { msg: &encrypted, aad: app_id.as_bytes() }).map_err(|_| CardKeyError::Protocol("CardKey GCM authentication failed".into()))?;
    String::from_utf8(plain).map_err(|_| CardKeyError::Protocol("CardKey plaintext is not UTF-8".into()))
}

#[derive(Clone)]
pub struct CardKeyClient {
    base_url: String,
    app_id: String,
    app_secret: String,
    http: HttpClient,
    require_response_signature: bool,
}

impl CardKeyClient {
    pub fn new(base_url: &str, app_id: &str, app_secret: &str) -> Result<Self, CardKeyError> {
        let parsed = reqwest::Url::parse(base_url).map_err(|error| CardKeyError::Protocol(error.to_string()))?;
        let local_http = parsed.scheme() == "http" && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
        if parsed.scheme() != "https" && !local_http {
            return Err(CardKeyError::Protocol("use HTTPS in production; HTTP is allowed only for localhost examples".into()));
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').into(),
            app_id: app_id.into(),
            app_secret: app_secret.into(),
            http: HttpClient::builder().use_rustls_tls().build()?,
            require_response_signature: true,
        })
    }

    pub fn verify(&self, input: serde_json::Value) -> Result<ApiResponse, CardKeyError> { self.post("verify", input) }
    pub fn activate(&self, input: serde_json::Value) -> Result<ApiResponse, CardKeyError> { self.post("activate", input) }
    pub fn consume(&self, input: serde_json::Value) -> Result<ApiResponse, CardKeyError> { self.post("consume", input) }
    pub fn query(&self, input: serde_json::Value) -> Result<ApiResponse, CardKeyError> { self.post("query", input) }
    pub fn unbind(&self, input: serde_json::Value) -> Result<ApiResponse, CardKeyError> { self.post("unbind", input) }

    fn post(&self, method: &str, input: serde_json::Value) -> Result<ApiResponse, CardKeyError> {
        let path = format!("/api/v1/{method}");
        // Serialize once; hash, sign, and send these exact bytes.
        let raw_body = serde_json::to_vec(&input)?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|error| CardKeyError::Protocol(error.to_string()))?.as_secs().to_string();
        let nonce = generate_nonce();
        let signature = sign_request(&self.app_secret, "POST", &path, &timestamp, &nonce, &raw_body);
        let response = self.http.post(format!("{}{}", self.base_url, path)).header("Accept", "application/json").header("Content-Type", "application/json").header("X-App-Id", &self.app_id).header("X-Timestamp", &timestamp).header("X-Nonce", &nonce).header("X-Signature-Version", "v1").header("X-Signature", signature).body(raw_body).send()?;
        let status = response.status();
        let response_timestamp = response.headers().get("X-Response-Timestamp").and_then(|value| value.to_str().ok()).map(str::to_owned);
        let response_signature = response.headers().get("X-Response-Signature").and_then(|value| value.to_str().ok()).map(str::to_owned);
        let raw_response_body = response.bytes()?.to_vec();
        if let (Some(timestamp), Some(signature)) = (response_timestamp, response_signature) {
            if !verify_signature(&self.app_secret, &canonical_response(&timestamp, &nonce, &raw_response_body), &signature) {
                return Err(CardKeyError::ResponseSignature("response signature verification failed".into()));
            }
        } else if self.require_response_signature && status.is_success() {
            return Err(CardKeyError::ResponseSignature("missing response signature headers".into()));
        }
        let result: ApiResponse = serde_json::from_slice(&raw_response_body).map_err(|_| CardKeyError::Protocol("the API response is not valid JSON".into()))?;
        if !status.is_success() || result.code != 0 || !result.success {
            return Err(CardKeyError::Api { code: result.code, message: result.message.clone(), http_status: status.as_u16(), response: Box::new(result) });
        }
        Ok(result)
    }
}
