use std::fmt;
use std::io::Cursor;

use data_encoding::{BASE32, BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD};
use image::{DynamicImage, GrayImage, ImageFormat, ImageReader, Limits, Luma};
use protobuf::{CodedInputStream, CodedOutputStream};
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};
use rand::RngCore;
use rqrr::PreparedImage;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::error::AuthDeskError;
use crate::models::{
    Account, AccountType, Algorithm, ExportQrBatchDto, ExportQrResultDto, ImportSkippedItemDto,
    QrImageInputDto,
};
use crate::otp::base32::{decode_base32, normalize_base32};

pub const MAX_EXPORT_BATCH_SIZE: usize = 10;
const MAX_URI_INPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_QR_IMAGES_COUNT: usize = 32;
const MAX_QR_IMAGE_BYTES: usize = 10 * 1024 * 1024;
const MAX_QR_IMAGE_WIDTH: u32 = 4096;
const MAX_QR_IMAGE_HEIGHT: u32 = 4096;
const MAX_IMAGE_ALLOC_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MIGRATION_DATA_BYTES: usize = 512 * 1024;
const MAX_ACCOUNTS_PER_PAYLOAD: usize = 500;

#[derive(Clone, PartialEq, Eq)]
pub struct MigrationOtpParameters {
    pub secret: Zeroizing<Vec<u8>>,
    pub name: String,
    pub issuer: String,
    pub algorithm: i32,
    pub digits: i32,
    pub otp_type: i32,
    pub counter: i64,
}

impl fmt::Debug for MigrationOtpParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MigrationOtpParameters")
            .field("secret", &"[REDACTED]")
            .field("name", &self.name)
            .field("issuer", &self.issuer)
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("otp_type", &self.otp_type)
            .field("counter", &self.counter)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPayload {
    pub otp_parameters: Vec<MigrationOtpParameters>,
    pub version: i32,
    pub batch_size: i32,
    pub batch_index: i32,
    pub batch_id: i32,
}

pub struct ParsedImportBatch {
    pub accounts: Vec<Account>,
    pub skipped: Vec<ImportSkippedItemDto>,
}

pub fn encode_migration_payload(
    payload: &MigrationPayload,
) -> Result<Zeroizing<Vec<u8>>, AuthDeskError> {
    let mut out = Zeroizing::new(Vec::new());
    {
        let mut os = CodedOutputStream::vec(&mut out);
        for param in &payload.otp_parameters {
            let mut entry_buf = Zeroizing::new(Vec::new());
            {
                let mut eos = CodedOutputStream::vec(&mut entry_buf);
                if !param.secret.is_empty() {
                    eos.write_bytes(1, param.secret.as_slice()).map_err(|e| {
                        AuthDeskError::InvalidParameter(format!(
                            "Error al codificar secreto protobuf: {}",
                            e
                        ))
                    })?;
                }
                if !param.name.is_empty() {
                    eos.write_string(2, &param.name).map_err(|e| {
                        AuthDeskError::InvalidParameter(format!(
                            "Error al codificar nombre protobuf: {}",
                            e
                        ))
                    })?;
                }
                if !param.issuer.is_empty() {
                    eos.write_string(3, &param.issuer).map_err(|e| {
                        AuthDeskError::InvalidParameter(format!(
                            "Error al codificar emisor protobuf: {}",
                            e
                        ))
                    })?;
                }
                if param.algorithm != 0 {
                    eos.write_enum(4, param.algorithm).map_err(|e| {
                        AuthDeskError::InvalidParameter(format!(
                            "Error al codificar algoritmo protobuf: {}",
                            e
                        ))
                    })?;
                }
                if param.digits != 0 {
                    eos.write_enum(5, param.digits).map_err(|e| {
                        AuthDeskError::InvalidParameter(format!(
                            "Error al codificar dígitos protobuf: {}",
                            e
                        ))
                    })?;
                }
                if param.otp_type != 0 {
                    eos.write_enum(6, param.otp_type).map_err(|e| {
                        AuthDeskError::InvalidParameter(format!(
                            "Error al codificar tipo protobuf: {}",
                            e
                        ))
                    })?;
                }
                if param.counter != 0 {
                    eos.write_int64(7, param.counter).map_err(|e| {
                        AuthDeskError::InvalidParameter(format!(
                            "Error al codificar contador protobuf: {}",
                            e
                        ))
                    })?;
                }
                eos.flush().map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error al finalizar entrada protobuf: {}",
                        e
                    ))
                })?;
            }
            os.write_bytes(1, entry_buf.as_slice()).map_err(|e| {
                AuthDeskError::InvalidParameter(format!(
                    "Error al escribir entrada protobuf: {}",
                    e
                ))
            })?;
        }
        if payload.version != 0 {
            os.write_int32(2, payload.version).map_err(|e| {
                AuthDeskError::InvalidParameter(format!(
                    "Error al escribir versión protobuf: {}",
                    e
                ))
            })?;
        }
        if payload.batch_size != 0 {
            os.write_int32(3, payload.batch_size).map_err(|e| {
                AuthDeskError::InvalidParameter(format!(
                    "Error al escribir tamaño de lote protobuf: {}",
                    e
                ))
            })?;
        }
        if payload.batch_index != 0 {
            os.write_int32(4, payload.batch_index).map_err(|e| {
                AuthDeskError::InvalidParameter(format!(
                    "Error al escribir índice de lote protobuf: {}",
                    e
                ))
            })?;
        }
        if payload.batch_id != 0 {
            os.write_int32(5, payload.batch_id).map_err(|e| {
                AuthDeskError::InvalidParameter(format!(
                    "Error al escribir ID de lote protobuf: {}",
                    e
                ))
            })?;
        }
        os.flush().map_err(|e| {
            AuthDeskError::InvalidParameter(format!("Error al finalizar carga protobuf: {}", e))
        })?;
    }
    Ok(out)
}

fn decode_otp_parameters(
    is: &mut CodedInputStream<'_>,
) -> Result<MigrationOtpParameters, AuthDeskError> {
    let mut param = MigrationOtpParameters {
        secret: Zeroizing::new(Vec::new()),
        name: String::new(),
        issuer: String::new(),
        algorithm: 0,
        digits: 0,
        otp_type: 0,
        counter: 0,
    };

    while let Some(tag) = is.read_raw_tag_or_eof().map_err(|e| {
        AuthDeskError::InvalidParameter(format!("Error leyendo etiqueta protobuf: {}", e))
    })? {
        match tag {
            10 => {
                is.read_bytes_into(&mut param.secret).map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error leyendo secreto protobuf: {}",
                        e
                    ))
                })?;
            }
            18 => {
                is.read_string_into(&mut param.name).map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error leyendo nombre protobuf: {}",
                        e
                    ))
                })?;
            }
            26 => {
                is.read_string_into(&mut param.issuer).map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error leyendo emisor protobuf: {}",
                        e
                    ))
                })?;
            }
            32 => {
                param.algorithm = is.read_int32().map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error leyendo algoritmo protobuf: {}",
                        e
                    ))
                })?;
            }
            40 => {
                param.digits = is.read_int32().map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error leyendo dígitos protobuf: {}",
                        e
                    ))
                })?;
            }
            48 => {
                param.otp_type = is.read_int32().map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error leyendo tipo OTP protobuf: {}",
                        e
                    ))
                })?;
            }
            56 => {
                param.counter = is.read_int64().map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error leyendo contador protobuf: {}",
                        e
                    ))
                })?;
            }
            other => {
                let field_number = other >> 3;
                if (1..=7).contains(&field_number) {
                    return Err(AuthDeskError::InvalidParameter(
                        "Tipo de campo protobuf inválido en OtpParameters".to_string(),
                    ));
                }
                protobuf::rt::skip_field_for_tag(other, is).map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error omitiendo campo desconocido protobuf: {}",
                        e
                    ))
                })?;
            }
        }
    }

    Ok(param)
}

pub fn decode_migration_payload(bytes: &[u8]) -> Result<MigrationPayload, AuthDeskError> {
    if bytes.is_empty() {
        return Err(AuthDeskError::InvalidParameter(
            "La carga de migración protobuf está vacía".to_string(),
        ));
    }
    if bytes.len() > MAX_MIGRATION_DATA_BYTES {
        return Err(AuthDeskError::InvalidParameter(
            "La carga de migración protobuf excede el tamaño máximo permitido".to_string(),
        ));
    }

    let mut payload = MigrationPayload {
        otp_parameters: Vec::new(),
        version: 0,
        batch_size: 0,
        batch_index: 0,
        batch_id: 0,
    };

    let mut is = CodedInputStream::from_bytes(bytes);
    while let Some(tag) = is.read_raw_tag_or_eof().map_err(|e| {
        AuthDeskError::InvalidParameter(format!("Error leyendo etiqueta protobuf: {}", e))
    })? {
        match tag {
            10 => {
                if payload.otp_parameters.len() >= MAX_ACCOUNTS_PER_PAYLOAD {
                    return Err(AuthDeskError::InvalidParameter(
                        "El lote de migración excede el máximo de cuentas permitido".to_string(),
                    ));
                }
                let len = is.read_raw_varint32().map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error leyendo longitud de entrada protobuf: {}",
                        e
                    ))
                })? as u64;
                if len > is.bytes_until_limit() {
                    return Err(AuthDeskError::InvalidParameter(
                        "Longitud de entrada protobuf fuera de límites".to_string(),
                    ));
                }
                let old_limit = is.push_limit(len).map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error aplicando límite protobuf: {}",
                        e
                    ))
                })?;
                let param = decode_otp_parameters(&mut is)?;
                is.pop_limit(old_limit);
                payload.otp_parameters.push(param);
            }
            16 => {
                payload.version = is.read_int32().map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error leyendo versión protobuf: {}",
                        e
                    ))
                })?;
            }
            24 => {
                payload.batch_size = is.read_int32().map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error leyendo tamaño de lote protobuf: {}",
                        e
                    ))
                })?;
            }
            32 => {
                payload.batch_index = is.read_int32().map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error leyendo índice de lote protobuf: {}",
                        e
                    ))
                })?;
            }
            40 => {
                payload.batch_id = is.read_int32().map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error leyendo ID de lote protobuf: {}",
                        e
                    ))
                })?;
            }
            other => {
                let field_number = other >> 3;
                if (1..=5).contains(&field_number) {
                    return Err(AuthDeskError::InvalidParameter(
                        "Tipo de campo protobuf inválido en MigrationPayload".to_string(),
                    ));
                }
                protobuf::rt::skip_field_for_tag(other, &mut is).map_err(|e| {
                    AuthDeskError::InvalidParameter(format!(
                        "Error omitiendo campo desconocido protobuf: {}",
                        e
                    ))
                })?;
            }
        }
    }

    Ok(payload)
}

fn percent_decode_strict(input: &str) -> Result<Zeroizing<String>, AuthDeskError> {
    let bytes = input.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(AuthDeskError::InvalidParameter(
                    "Secuencia percent-encoding truncada".to_string(),
                ));
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).map_err(|_| {
                AuthDeskError::InvalidParameter("Percent-encoding inválido".to_string())
            })?;
            let val = u8::from_str_radix(hex, 16).map_err(|_| {
                AuthDeskError::InvalidParameter("Percent-encoding inválido".to_string())
            })?;
            out.push(val);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let decoded_str = std::str::from_utf8(&out).map_err(|_| {
        AuthDeskError::InvalidParameter("Secuencia UTF-8 inválida en parámetro URI".to_string())
    })?;
    Ok(Zeroizing::new(decoded_str.to_string()))
}

fn extract_raw_query_param(url: &Url, target_key: &str) -> Result<Option<Zeroizing<String>>, AuthDeskError> {
    let Some(query) = url.query() else {
        return Ok(None);
    };
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k_raw, v_raw) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let key_decoded = percent_decode_strict(k_raw)?;
        if key_decoded.eq_ignore_ascii_case(target_key) {
            let val_decoded = percent_decode_strict(v_raw)?;
            return Ok(Some(val_decoded));
        }
    }
    Ok(None)
}

fn decode_migration_base64(raw_data: &str) -> Result<Zeroizing<Vec<u8>>, AuthDeskError> {
    let trimmed = raw_data.trim();
    if trimmed.is_empty() {
        return Err(AuthDeskError::InvalidParameter(
            "El parámetro 'data' está vacío".to_string(),
        ));
    }
    if trimmed.len() > MAX_MIGRATION_DATA_BYTES * 2 {
        return Err(AuthDeskError::InvalidParameter(
            "El parámetro 'data' excede el tamaño máximo permitido".to_string(),
        ));
    }

    let cleaned: Zeroizing<String> = Zeroizing::new(
        trimmed
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect(),
    );

    if cleaned.is_empty() {
        return Err(AuthDeskError::InvalidParameter(
            "El parámetro 'data' está vacío".to_string(),
        ));
    }

    let has_std = cleaned.contains('+') || cleaned.contains('/');
    let has_url = cleaned.contains('-') || cleaned.contains('_');
    if has_std && has_url {
        return Err(AuthDeskError::InvalidParameter(
            "Codificación Base64 mezclada inválida".to_string(),
        ));
    }

    let bytes = if has_url {
        if cleaned.contains('=') {
            BASE64URL.decode(cleaned.as_bytes())
        } else {
            BASE64URL_NOPAD.decode(cleaned.as_bytes())
        }
    } else if cleaned.contains('=') {
        BASE64.decode(cleaned.as_bytes())
    } else {
        BASE64_NOPAD.decode(cleaned.as_bytes())
    }
    .map_err(|_| AuthDeskError::InvalidParameter("Base64 inválido en carga de migración".to_string()))?;

    Ok(Zeroizing::new(bytes))
}

fn split_issuer_and_account(raw_issuer: &str, raw_name: &str) -> (String, String) {
    let q_issuer = raw_issuer.trim();
    let label = raw_name.trim();
    if !q_issuer.is_empty() {
        if let Some((prefix, rest)) = label.split_once(':') {
            if prefix.trim().eq_ignore_ascii_case(q_issuer) {
                return (q_issuer.to_string(), rest.trim().to_string());
            }
        }
        return (q_issuer.to_string(), label.to_string());
    }
    if let Some((prefix, rest)) = label.split_once(':') {
        return (prefix.trim().to_string(), rest.trim().to_string());
    }
    (String::new(), label.to_string())
}

fn format_safe_label(issuer: &str, account: &str) -> String {
    match (issuer.trim().is_empty(), account.trim().is_empty()) {
        (false, false) => format!("{}: {}", issuer.trim(), account.trim()),
        (false, true) => issuer.trim().to_string(),
        (true, false) => account.trim().to_string(),
        (true, true) => String::new(),
    }
}

fn convert_otp_parameters_to_account(
    param: &MigrationOtpParameters,
    source_prefix: &str,
    entry_index: usize,
) -> Result<Account, ImportSkippedItemDto> {
    let (issuer, account) = split_issuer_and_account(&param.issuer, &param.name);
    let safe_label = format_safe_label(&issuer, &account);
    let entry_source = if safe_label.is_empty() {
        format!("{} (entrada #{})", source_prefix, entry_index + 1)
    } else {
        format!("{} ({})", source_prefix, safe_label)
    };

    match param.otp_type {
        0 | 2 => {}
        1 => {
            return Err(ImportSkippedItemDto {
                source: entry_source,
                reason: "HOTP no soportado (solo TOTP)".to_string(),
            });
        }
        _ => {
            return Err(ImportSkippedItemDto {
                source: entry_source,
                reason: "Tipo OTP no soportado".to_string(),
            });
        }
    }

    let algorithm = match param.algorithm {
        0 | 1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        4 => {
            return Err(ImportSkippedItemDto {
                source: entry_source,
                reason: "Algoritmo MD5 no soportado".to_string(),
            });
        }
        _ => {
            return Err(ImportSkippedItemDto {
                source: entry_source,
                reason: "Algoritmo OTP no soportado".to_string(),
            });
        }
    };

    let digits = match param.digits {
        0 | 1 => 6,
        2 => 8,
        _ => {
            return Err(ImportSkippedItemDto {
                source: entry_source,
                reason: "Cantidad de dígitos no soportada (solo 6 u 8)".to_string(),
            });
        }
    };

    if param.secret.is_empty() {
        return Err(ImportSkippedItemDto {
            source: entry_source,
            reason: "Secreto vacío".to_string(),
        });
    }

    if issuer.is_empty() && account.is_empty() {
        return Err(ImportSkippedItemDto {
            source: entry_source,
            reason: "Falta el nombre o emisor de la cuenta".to_string(),
        });
    }

    let raw_b32 = Zeroizing::new(BASE32.encode(param.secret.as_slice()));
    let norm_secret = normalize_base32(&raw_b32).map_err(|_| ImportSkippedItemDto {
        source: entry_source.clone(),
        reason: "Secreto inválido".to_string(),
    })?;

    let id = format!("staged_{}_{}", std::process::id(), rand::random::<u64>());
    Account::new(
        id,
        issuer,
        account,
        norm_secret,
        algorithm,
        digits,
        30,
        AccountType::Totp,
        None,
    )
    .map_err(|e| ImportSkippedItemDto {
        source: entry_source,
        reason: e.to_string(),
    })
}

fn parse_otpauth_totp_url(url: &Url, source_label: &str) -> Result<Account, ImportSkippedItemDto> {
    let host = url.host_str().unwrap_or("").trim().to_ascii_lowercase();
    if host == "hotp" {
        return Err(ImportSkippedItemDto {
            source: source_label.to_string(),
            reason: "HOTP no soportado (solo TOTP)".to_string(),
        });
    }
    if host != "totp" {
        return Err(ImportSkippedItemDto {
            source: source_label.to_string(),
            reason: "Tipo otpauth no soportado (solo totp)".to_string(),
        });
    }

    let raw_path = url.path().strip_prefix('/').unwrap_or(url.path());
    let decoded_label = percent_decode_strict(raw_path).map_err(|_| ImportSkippedItemDto {
        source: source_label.to_string(),
        reason: "Etiqueta de cuenta malformada".to_string(),
    })?;

    let mut raw_secret: Option<Zeroizing<String>> = None;
    let mut query_issuer = String::new();
    let mut raw_algorithm = String::new();
    let mut raw_digits = String::new();
    let mut raw_period = String::new();

    for (k, v) in url.query_pairs() {
        if k.eq_ignore_ascii_case("secret") {
            raw_secret = Some(Zeroizing::new(v.into_owned()));
        } else if k.eq_ignore_ascii_case("issuer") {
            query_issuer = v.trim().to_string();
        } else if k.eq_ignore_ascii_case("algorithm") {
            raw_algorithm = v.trim().to_string();
        } else if k.eq_ignore_ascii_case("digits") {
            raw_digits = v.trim().to_string();
        } else if k.eq_ignore_ascii_case("period") {
            raw_period = v.trim().to_string();
        }
    }

    let (issuer, account) = split_issuer_and_account(&query_issuer, &decoded_label);
    let safe_label = format_safe_label(&issuer, &account);
    let item_source = if safe_label.is_empty() {
        source_label.to_string()
    } else {
        format!("{} ({})", source_label, safe_label)
    };

    if issuer.is_empty() && account.is_empty() {
        return Err(ImportSkippedItemDto {
            source: item_source,
            reason: "Falta el nombre o emisor de la cuenta".to_string(),
        });
    }

    let secret_str = raw_secret.ok_or_else(|| ImportSkippedItemDto {
        source: item_source.clone(),
        reason: "Falta el parámetro 'secret'".to_string(),
    })?;

    let norm_secret = normalize_base32(&secret_str).map_err(|_| ImportSkippedItemDto {
        source: item_source.clone(),
        reason: "Secreto Base32 inválido".to_string(),
    })?;
    let mut decoded_secret = decode_base32(&norm_secret).map_err(|_| ImportSkippedItemDto {
        source: item_source.clone(),
        reason: "Secreto Base32 inválido".to_string(),
    })?;
    let is_empty_bytes = decoded_secret.is_empty();
    decoded_secret.zeroize();
    if is_empty_bytes {
        return Err(ImportSkippedItemDto {
            source: item_source,
            reason: "Secreto Base32 vacío".to_string(),
        });
    }

    let algorithm = if raw_algorithm.is_empty() {
        Algorithm::Sha1
    } else {
        raw_algorithm
            .parse::<Algorithm>()
            .map_err(|_| ImportSkippedItemDto {
                source: item_source.clone(),
                reason: format!("Algoritmo no soportado: {}", raw_algorithm.to_uppercase()),
            })?
    };

    let digits = if raw_digits.is_empty() {
        6
    } else {
        match raw_digits.parse::<u32>() {
            Ok(6) => 6,
            Ok(8) => 8,
            _ => {
                return Err(ImportSkippedItemDto {
                    source: item_source,
                    reason: "Cantidad de dígitos no soportada (solo 6 u 8)".to_string(),
                });
            }
        }
    };

    let period = if raw_period.is_empty() {
        30
    } else {
        match raw_period.parse::<u64>() {
            Ok(p) if p > 0 => p,
            _ => {
                return Err(ImportSkippedItemDto {
                    source: item_source,
                    reason: "Período TOTP inválido (debe ser > 0)".to_string(),
                });
            }
        }
    };

    let id = format!("staged_{}_{}", std::process::id(), rand::random::<u64>());
    Account::new(
        id,
        issuer,
        account,
        norm_secret,
        algorithm,
        digits,
        period,
        AccountType::Totp,
        None,
    )
    .map_err(|e| ImportSkippedItemDto {
        source: item_source,
        reason: e.to_string(),
    })
}

fn parse_single_import_uri(
    raw_uri: &str,
    source_label: &str,
    accounts: &mut Vec<Account>,
    skipped: &mut Vec<ImportSkippedItemDto>,
) {
    let trimmed = raw_uri.trim();
    if trimmed.is_empty() {
        return;
    }

    let url = match Url::parse(trimmed) {
        Ok(u) => u,
        Err(_) => {
            skipped.push(ImportSkippedItemDto {
                source: source_label.to_string(),
                reason: "URI inválida o malformada".to_string(),
            });
            return;
        }
    };

    match url.scheme() {
        "otpauth-migration" => {
            let host = url.host_str().unwrap_or("");
            if !host.eq_ignore_ascii_case("offline") {
                skipped.push(ImportSkippedItemDto {
                    source: source_label.to_string(),
                    reason: "URI otpauth-migration inválida (host esperado: offline)".to_string(),
                });
                return;
            }
            let data_param = match extract_raw_query_param(&url, "data") {
                Ok(Some(d)) => d,
                Ok(None) => {
                    skipped.push(ImportSkippedItemDto {
                        source: source_label.to_string(),
                        reason: "Falta el parámetro 'data' en URI de migración".to_string(),
                    });
                    return;
                }
                Err(e) => {
                    skipped.push(ImportSkippedItemDto {
                        source: source_label.to_string(),
                        reason: e.to_string(),
                    });
                    return;
                }
            };
            let decoded_bytes = match decode_migration_base64(&data_param) {
                Ok(b) => b,
                Err(e) => {
                    skipped.push(ImportSkippedItemDto {
                        source: source_label.to_string(),
                        reason: e.to_string(),
                    });
                    return;
                }
            };
            let payload = match decode_migration_payload(decoded_bytes.as_slice()) {
                Ok(p) => p,
                Err(e) => {
                    skipped.push(ImportSkippedItemDto {
                        source: source_label.to_string(),
                        reason: e.to_string(),
                    });
                    return;
                }
            };
            if payload.otp_parameters.is_empty() {
                skipped.push(ImportSkippedItemDto {
                    source: source_label.to_string(),
                    reason: "El código de migración no contiene cuentas".to_string(),
                });
                return;
            }
            for (idx, param) in payload.otp_parameters.iter().enumerate() {
                match convert_otp_parameters_to_account(param, source_label, idx) {
                    Ok(acc) => accounts.push(acc),
                    Err(skip_item) => skipped.push(skip_item),
                }
            }
        }
        "otpauth" => match parse_otpauth_totp_url(&url, source_label) {
            Ok(acc) => accounts.push(acc),
            Err(skip_item) => skipped.push(skip_item),
        },
        _ => {
            skipped.push(ImportSkippedItemDto {
                source: source_label.to_string(),
                reason: "Esquema URI no soportado (use otpauth:// o otpauth-migration://)"
                    .to_string(),
            });
        }
    }
}

pub fn parse_import_uris(uris_text: &str) -> Result<ParsedImportBatch, AuthDeskError> {
    if uris_text.len() > MAX_URI_INPUT_BYTES {
        return Err(AuthDeskError::InvalidParameter(
            "El texto de importación excede el tamaño máximo permitido".to_string(),
        ));
    }

    let lines: Vec<(usize, &str)> = uris_text
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty())
        .collect();

    if lines.is_empty() {
        return Err(AuthDeskError::InvalidParameter(
            "Debe ingresar al menos una URI otpauth:// u otpauth-migration://".to_string(),
        ));
    }

    let mut accounts = Vec::new();
    let mut skipped = Vec::new();

    for (line_num, line) in lines {
        let source_label = format!("URI #{}", line_num);
        parse_single_import_uri(line, &source_label, &mut accounts, &mut skipped);
    }

    Ok(ParsedImportBatch { accounts, skipped })
}

fn dynamic_image_to_luma(dyn_img: DynamicImage) -> GrayImage {
    if dyn_img.color().has_alpha() {
        let rgba = dyn_img.to_rgba8();
        let (width, height) = rgba.dimensions();
        GrayImage::from_fn(width, height, |x, y| {
            let p = rgba.get_pixel(x, y);
            let a = p[3] as u32;
            let inv_a = 255 - a;
            let r = (p[0] as u32 * a + 255 * inv_a) / 255;
            let g = (p[1] as u32 * a + 255 * inv_a) / 255;
            let b = (p[2] as u32 * a + 255 * inv_a) / 255;
            let y_val = (299 * r + 587 * g + 114 * b) / 1000;
            Luma([y_val as u8])
        })
    } else {
        dyn_img.to_luma8()
    }
}

fn pad_white_border(luma: &GrayImage, border: u32) -> GrayImage {
    let (w, h) = luma.dimensions();
    let new_w = w.saturating_add(border.saturating_mul(2));
    let new_h = h.saturating_add(border.saturating_mul(2));
    let mut padded = GrayImage::from_pixel(new_w, new_h, Luma([255u8]));
    for y in 0..h {
        for x in 0..w {
            padded.put_pixel(x + border, y + border, *luma.get_pixel(x, y));
        }
    }
    padded
}

fn decode_qr_payloads_from_bytes(
    bytes: &[u8],
    safe_name: &str,
    skipped: &mut Vec<ImportSkippedItemDto>,
) -> Result<Vec<Zeroizing<String>>, String> {
    if bytes.is_empty() {
        return Err("Archivo de imagen vacío".to_string());
    }
    if bytes.len() > MAX_QR_IMAGE_BYTES {
        return Err("La imagen excede el tamaño máximo permitido (10 MiB)".to_string());
    }

    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| "No se pudo leer el formato de la imagen".to_string())?;

    match reader.format() {
        Some(ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP) => {}
        _ => {
            return Err("Formato de imagen no soportado (use PNG, JPEG o WebP)".to_string());
        }
    }

    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_QR_IMAGE_WIDTH);
    limits.max_image_height = Some(MAX_QR_IMAGE_HEIGHT);
    limits.max_alloc = Some(MAX_IMAGE_ALLOC_BYTES);
    reader.limits(limits);

    let dyn_img = reader.decode().map_err(|_| {
        "No se pudo decodificar la imagen (corrupta o excede dimensiones máximas)".to_string()
    })?;

    if dyn_img.width() == 0 || dyn_img.height() == 0 {
        return Err("Dimensiones de imagen inválidas".to_string());
    }

    let luma = dynamic_image_to_luma(dyn_img);
    let mut prepared = PreparedImage::prepare(luma.clone());
    let mut decoded_contents: Vec<Zeroizing<String>> = Vec::new();
    let grids = prepared.detect_grids();

    if !grids.is_empty() {
        let total = grids.len();
        for (grid_idx, grid) in grids.into_iter().enumerate() {
            match grid.decode() {
                Ok((_meta, content)) => decoded_contents.push(Zeroizing::new(content)),
                Err(_) if total > 1 => {
                    skipped.push(ImportSkippedItemDto {
                        source: format!("{} (QR #{})", safe_name, grid_idx + 1),
                        reason: "Se detectó un patrón QR pero no pudo decodificarse".to_string(),
                    });
                }
                Err(_) => {}
            }
        }
        if decoded_contents.is_empty() && total == 1 {
            return Err("Se detectó un patrón QR pero no pudo decodificarse".to_string());
        }
        return Ok(decoded_contents);
    }

    let padded = pad_white_border(&luma, 16);
    let mut prepared_padded = PreparedImage::prepare(padded);
    let padded_grids = prepared_padded.detect_grids();
    if padded_grids.is_empty() {
        return Err("No se detectó ningún código QR en la imagen".to_string());
    }

    let total_padded = padded_grids.len();
    for (grid_idx, grid) in padded_grids.into_iter().enumerate() {
        match grid.decode() {
            Ok((_meta, content)) => decoded_contents.push(Zeroizing::new(content)),
            Err(_) if total_padded > 1 => {
                skipped.push(ImportSkippedItemDto {
                    source: format!("{} (QR #{})", safe_name, grid_idx + 1),
                    reason: "Se detectó un patrón QR pero no pudo decodificarse".to_string(),
                });
            }
            Err(_) => {}
        }
    }

    if decoded_contents.is_empty() && total_padded == 1 {
        return Err("Se detectó un patrón QR pero no pudo decodificarse".to_string());
    }

    Ok(decoded_contents)
}

pub fn parse_import_qr_images(images: &[QrImageInputDto]) -> Result<ParsedImportBatch, AuthDeskError> {
    if images.is_empty() {
        return Err(AuthDeskError::InvalidParameter(
            "Debe seleccionar al menos una imagen QR".to_string(),
        ));
    }
    if images.len() > MAX_QR_IMAGES_COUNT {
        return Err(AuthDeskError::InvalidParameter(format!(
            "Máximo {} imágenes QR por lote",
            MAX_QR_IMAGES_COUNT
        )));
    }

    let mut accounts = Vec::new();
    let mut skipped = Vec::new();

    for (idx, img_in) in images.iter().enumerate() {
        let safe_name = if img_in.name.trim().is_empty() {
            format!("Imagen #{}", idx + 1)
        } else {
            img_in.name.trim().to_string()
        };

        let payloads = match decode_qr_payloads_from_bytes(&img_in.bytes, &safe_name, &mut skipped) {
            Ok(p) => p,
            Err(reason) => {
                skipped.push(ImportSkippedItemDto {
                    source: safe_name,
                    reason,
                });
                continue;
            }
        };

        let total_grids = payloads.len();
        for (grid_idx, payload) in payloads.into_iter().enumerate() {
            let grid_source = if total_grids > 1 {
                format!("{} (QR #{})", safe_name, grid_idx + 1)
            } else {
                safe_name.clone()
            };
            let lines: Vec<&str> = payload
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect();
            if lines.is_empty() {
                skipped.push(ImportSkippedItemDto {
                    source: grid_source,
                    reason: "El código QR no contiene datos".to_string(),
                });
                continue;
            }
            for line in lines {
                parse_single_import_uri(line, &grid_source, &mut accounts, &mut skipped);
            }
        }
    }

    Ok(ParsedImportBatch { accounts, skipped })
}

fn generate_random_batch_id() -> i32 {
    let mut id_bytes = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    let id = i32::from_le_bytes(id_bytes);
    if id == 0 {
        1
    } else {
        id
    }
}

pub fn build_migration_uri_for_accounts(
    accounts: &[Account],
    batch_index: usize,
    batch_size: usize,
    batch_id: i32,
) -> Result<Zeroizing<String>, AuthDeskError> {
    let mut otp_parameters = Vec::with_capacity(accounts.len());
    for acc in accounts {
        let raw_secret = Zeroizing::new(decode_base32(&acc.secret)?);
        let issuer = acc.issuer.trim().to_string();
        let account = acc.account.trim().to_string();
        let name = if issuer.is_empty() {
            account.clone()
        } else if account.is_empty() {
            issuer.clone()
        } else {
            format!("{}:{}", issuer, account)
        };
        let algorithm = match acc.algorithm {
            Algorithm::Sha1 => 1,
            Algorithm::Sha256 => 2,
            Algorithm::Sha512 => 3,
        };
        let digits = if acc.digits == 8 { 2 } else { 1 };
        let otp_type = match acc.account_type {
            AccountType::Totp => 2,
            AccountType::Hotp => 1,
        };
        let counter = acc.counter.unwrap_or(0) as i64;

        otp_parameters.push(MigrationOtpParameters {
            secret: raw_secret,
            name,
            issuer,
            algorithm,
            digits,
            otp_type,
            counter,
        });
    }

    let payload = MigrationPayload {
        otp_parameters,
        version: 1,
        batch_size: batch_size as i32,
        batch_index: batch_index as i32,
        batch_id,
    };

    let proto_bytes = encode_migration_payload(&payload)?;
    let b64 = Zeroizing::new(BASE64.encode(proto_bytes.as_slice()));
    let mut url = Url::parse("otpauth-migration://offline").map_err(|e| {
        AuthDeskError::InvalidParameter(format!("Error construyendo URI de migración: {}", e))
    })?;
    url.query_pairs_mut().append_pair("data", b64.as_str());
    Ok(Zeroizing::new(url.into()))
}

pub fn encode_export_qr_batches(accounts: &[Account]) -> Result<ExportQrResultDto, AuthDeskError> {
    if accounts.is_empty() {
        return Err(AuthDeskError::InvalidParameter(
            "No hay cuentas en la bóveda para exportar".to_string(),
        ));
    }

    let batch_id = generate_random_batch_id();
    let chunks: Vec<&[Account]> = accounts.chunks(MAX_EXPORT_BATCH_SIZE).collect();
    let batch_size = chunks.len();
    let mut batches = Vec::with_capacity(batch_size);

    for (batch_index, chunk) in chunks.into_iter().enumerate() {
        let uri = build_migration_uri_for_accounts(chunk, batch_index, batch_size, batch_id)?;
        let qr = QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::M)
            .or_else(|_| QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::L))
            .map_err(|e| {
                AuthDeskError::InvalidParameter(format!(
                    "No se pudo codificar el lote #{} en QR: {}",
                    batch_index + 1,
                    e
                ))
            })?;

        let svg_str = qr
            .render::<svg::Color<'_>>()
            .min_dimensions(256, 256)
            .quiet_zone(true)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build();

        batches.push(ExportQrBatchDto {
            batch_index,
            batch_size,
            account_count: chunk.len(),
            svg: svg_str,
        });
    }

    Ok(ExportQrResultDto {
        batches,
        total_accounts: accounts.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb, Rgba};
    use std::io::Cursor;

    fn sample_account(i: usize, algo: Algorithm, digits: u32) -> Account {
        Account::new(
            format!("id-{}", i),
            format!("Service{}", i),
            format!("user+{}@example.com", i),
            "JBSWY3DPEHPK3PXP".to_string(),
            algo,
            digits,
            30,
            AccountType::Totp,
            None,
        )
        .unwrap()
    }

    fn render_qr_png_bytes(data: &str) -> Vec<u8> {
        let qr = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M).unwrap();
        let img = qr.render::<Luma<u8>>().min_dimensions(256, 256).quiet_zone(true).build();
        let mut out = Vec::new();
        DynamicImage::ImageLuma8(img)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn test_protobuf_migration_payload_roundtrip() {
        let payload = MigrationPayload {
            otp_parameters: vec![
                MigrationOtpParameters {
                    secret: Zeroizing::new(b"Hello!\xde\xad\xbe\xef".to_vec()),
                    name: "GitHub:octocat@github.com".to_string(),
                    issuer: "GitHub".to_string(),
                    algorithm: 1,
                    digits: 1,
                    otp_type: 2,
                    counter: 0,
                },
                MigrationOtpParameters {
                    secret: Zeroizing::new(b"12345678901234567890".to_vec()),
                    name: "Proton:sec@proton.me".to_string(),
                    issuer: "Proton".to_string(),
                    algorithm: 2,
                    digits: 2,
                    otp_type: 2,
                    counter: 0,
                },
                MigrationOtpParameters {
                    secret: Zeroizing::new(b"12345678901234567890123456789012".to_vec()),
                    name: "Cloudflare:ops@cf.com".to_string(),
                    issuer: "Cloudflare".to_string(),
                    algorithm: 3,
                    digits: 2,
                    otp_type: 2,
                    counter: 0,
                },
            ],
            version: 1,
            batch_size: 2,
            batch_index: 0,
            batch_id: 987654321,
        };

        let encoded = encode_migration_payload(&payload).unwrap();
        let decoded = decode_migration_payload(encoded.as_slice()).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_migration_uri_base64_and_url_encoding_variants() {
        let payload = MigrationPayload {
            otp_parameters: vec![MigrationOtpParameters {
                secret: Zeroizing::new(vec![0xff, 0xfe, 0xfd, 0x3e, 0x3f, 0xaa, 0xbb]),
                name: "Acme:alice+work@acme.com".to_string(),
                issuer: "Acme".to_string(),
                algorithm: 0,
                digits: 0,
                otp_type: 0,
                counter: 0,
            }],
            version: 1,
            batch_size: 1,
            batch_index: 0,
            batch_id: 42,
        };
        let proto = encode_migration_payload(&payload).unwrap();
        let std_padded = BASE64.encode(proto.as_slice());
        let std_unpadded = BASE64_NOPAD.encode(proto.as_slice());
        let url_padded = BASE64URL.encode(proto.as_slice());
        let url_unpadded = BASE64URL_NOPAD.encode(proto.as_slice());

        let mut pct_url = Url::parse("otpauth-migration://offline").unwrap();
        pct_url.query_pairs_mut().append_pair("data", &std_padded);

        let variants = [
            pct_url.to_string(),
            format!("otpauth-migration://offline?data={}", std_padded),
            format!("otpauth-migration://offline?data={}", std_unpadded),
            format!("otpauth-migration://offline?data={}", url_padded),
            format!("otpauth-migration://offline?data={}", url_unpadded),
        ];

        for uri in variants {
            let parsed = parse_import_uris(&uri).unwrap();
            assert_eq!(parsed.skipped.len(), 0, "Failed URI variant: {}", uri);
            assert_eq!(parsed.accounts.len(), 1);
            assert_eq!(parsed.accounts[0].issuer, "Acme");
            assert_eq!(parsed.accounts[0].account, "alice+work@acme.com");
            assert_eq!(parsed.accounts[0].algorithm, Algorithm::Sha1);
            assert_eq!(parsed.accounts[0].digits, 6);
            assert_eq!(
                decode_base32(&parsed.accounts[0].secret).unwrap(),
                vec![0xff, 0xfe, 0xfd, 0x3e, 0x3f, 0xaa, 0xbb]
            );
        }
    }

    #[test]
    fn test_migration_rejects_hotp_and_md5_gracefully_as_skipped() {
        let payload = MigrationPayload {
            otp_parameters: vec![
                MigrationOtpParameters {
                    secret: Zeroizing::new(b"Hello!\xde\xad\xbe\xef".to_vec()),
                    name: "Valid:user@valid.com".to_string(),
                    issuer: "Valid".to_string(),
                    algorithm: 1,
                    digits: 1,
                    otp_type: 2,
                    counter: 0,
                },
                MigrationOtpParameters {
                    secret: Zeroizing::new(b"12345678901234567890".to_vec()),
                    name: "HotpSvc:user@hotp.com".to_string(),
                    issuer: "HotpSvc".to_string(),
                    algorithm: 1,
                    digits: 1,
                    otp_type: 1,
                    counter: 5,
                },
                MigrationOtpParameters {
                    secret: Zeroizing::new(b"12345678901234567890".to_vec()),
                    name: "Md5Svc:user@md5.com".to_string(),
                    issuer: "Md5Svc".to_string(),
                    algorithm: 4,
                    digits: 1,
                    otp_type: 2,
                    counter: 0,
                },
                MigrationOtpParameters {
                    secret: Zeroizing::new(Vec::new()),
                    name: "EmptySecret:user@empty.com".to_string(),
                    issuer: "EmptySecret".to_string(),
                    algorithm: 1,
                    digits: 1,
                    otp_type: 2,
                    counter: 0,
                },
            ],
            version: 1,
            batch_size: 1,
            batch_index: 0,
            batch_id: 7,
        };
        let proto = encode_migration_payload(&payload).unwrap();
        let mut url = Url::parse("otpauth-migration://offline").unwrap();
        url.query_pairs_mut()
            .append_pair("data", &BASE64.encode(proto.as_slice()));

        let parsed = parse_import_uris(url.as_str()).unwrap();
        assert_eq!(parsed.accounts.len(), 1);
        assert_eq!(parsed.accounts[0].issuer, "Valid");
        assert_eq!(parsed.skipped.len(), 3);
        assert!(parsed.skipped[0].reason.contains("HOTP"));
        assert!(parsed.skipped[1].reason.contains("MD5"));
        assert!(parsed.skipped[2].reason.contains("vacío"));
    }

    #[test]
    fn test_standard_otpauth_totp_parsing_and_edge_cases() {
        let input = [
            "otpauth://totp/GitHub:alice%2Bdev%40github.com?secret=jbswy3dpehpk3pxp&issuer=GitHub&algorithm=SHA256&digits=8&period=60",
            "otpauth://totp/FallbackIssuer:bob@corp.io?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/solo@account.org?secret=JBSWY3DPEHPK3PXP",
            "otpauth://hotp/Legacy:user?secret=JBSWY3DPEHPK3PXP&counter=1",
            "otpauth://totp/BadMd5:user?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
            "otpauth://totp/BadDigits:user?secret=JBSWY3DPEHPK3PXP&digits=7",
            "otpauth://totp/BadPeriod:user?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth://totp/BadSecret:user?secret=NOT_BASE32_999",
            "not-a-valid-uri",
        ]
        .join("\n");

        let parsed = parse_import_uris(&input).unwrap();
        assert_eq!(parsed.accounts.len(), 3);
        assert_eq!(parsed.skipped.len(), 6);

        assert_eq!(parsed.accounts[0].issuer, "GitHub");
        assert_eq!(parsed.accounts[0].account, "alice+dev@github.com");
        assert_eq!(parsed.accounts[0].secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(parsed.accounts[0].algorithm, Algorithm::Sha256);
        assert_eq!(parsed.accounts[0].digits, 8);
        assert_eq!(parsed.accounts[0].period, 60);

        assert_eq!(parsed.accounts[1].issuer, "FallbackIssuer");
        assert_eq!(parsed.accounts[1].account, "bob@corp.io");
        assert_eq!(parsed.accounts[1].algorithm, Algorithm::Sha1);
        assert_eq!(parsed.accounts[1].digits, 6);
        assert_eq!(parsed.accounts[1].period, 30);

        assert_eq!(parsed.accounts[2].issuer, "");
        assert_eq!(parsed.accounts[2].account, "solo@account.org");

        for s in &parsed.skipped {
            assert!(!s.source.contains("JBSWY3DPEHPK3PXP"));
            assert!(!s.reason.contains("JBSWY3DPEHPK3PXP"));
            assert!(!s.source.contains("NOT_BASE32_999"));
            assert!(!s.reason.contains("NOT_BASE32_999"));
        }
    }

    #[test]
    fn test_qr_png_jpeg_webp_and_transparent_roundtrip_via_rqrr() {
        let acc = sample_account(1, Algorithm::Sha256, 8);
        let uri = build_migration_uri_for_accounts(&[acc.clone()], 0, 1, 12345).unwrap();
        let qr = QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::M).unwrap();

        let luma_img = qr.render::<Luma<u8>>().min_dimensions(256, 256).quiet_zone(true).build();
        let mut png_bytes = Vec::new();
        DynamicImage::ImageLuma8(luma_img.clone())
            .write_to(&mut Cursor::new(&mut png_bytes), ImageFormat::Png)
            .unwrap();

        let mut jpg_bytes = Vec::new();
        let rgb_img: ImageBuffer<Rgb<u8>, Vec<u8>> = DynamicImage::ImageLuma8(luma_img.clone()).to_rgb8();
        DynamicImage::ImageRgb8(rgb_img)
            .write_to(&mut Cursor::new(&mut jpg_bytes), ImageFormat::Jpeg)
            .unwrap();

        let mut webp_bytes = Vec::new();
        DynamicImage::ImageRgba8(DynamicImage::ImageLuma8(luma_img.clone()).to_rgba8())
            .write_to(&mut Cursor::new(&mut webp_bytes), ImageFormat::WebP)
            .unwrap();

        let (w, h) = luma_img.dimensions();
        let transparent_img = ImageBuffer::from_fn(w, h, |x, y| {
            if luma_img.get_pixel(x, y)[0] < 128 {
                Rgba([0u8, 0, 0, 255])
            } else {
                Rgba([0u8, 0, 0, 0])
            }
        });
        let mut transparent_png = Vec::new();
        DynamicImage::ImageRgba8(transparent_img)
            .write_to(&mut Cursor::new(&mut transparent_png), ImageFormat::Png)
            .unwrap();

        for (name, bytes) in [
            ("test.png", png_bytes),
            ("test.jpg", jpg_bytes),
            ("test.webp", webp_bytes),
            ("transparent.png", transparent_png),
        ] {
            let parsed = parse_import_qr_images(&[QrImageInputDto {
                name: name.to_string(),
                bytes,
            }])
            .unwrap();
            assert_eq!(parsed.skipped.len(), 0, "Unexpected skip for {}", name);
            assert_eq!(parsed.accounts.len(), 1, "Failed QR decode for {}", name);
            assert_eq!(parsed.accounts[0].issuer, acc.issuer);
            assert_eq!(parsed.accounts[0].account, acc.account);
            assert_eq!(parsed.accounts[0].secret, acc.secret);
            assert_eq!(parsed.accounts[0].algorithm, Algorithm::Sha256);
            assert_eq!(parsed.accounts[0].digits, 8);
        }
    }

    #[test]
    fn test_multi_qr_grids_in_single_image_and_corrupt_image_safety() {
        let uri1 = "otpauth://totp/Alpha:one@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Alpha";
        let uri2 = "otpauth://totp/Beta:two@example.com?secret=GEZDGNBVGY3TQOJQ&issuer=Beta&algorithm=SHA512&digits=8";

        let q1 = QrCode::new(uri1.as_bytes())
            .unwrap()
            .render::<Luma<u8>>()
            .min_dimensions(200, 200)
            .quiet_zone(true)
            .build();
        let q2 = QrCode::new(uri2.as_bytes())
            .unwrap()
            .render::<Luma<u8>>()
            .min_dimensions(200, 200)
            .quiet_zone(true)
            .build();

        let gap = 40u32;
        let total_w = q1.width() + gap + q2.width();
        let total_h = q1.height().max(q2.height());
        let mut combined = GrayImage::from_pixel(total_w, total_h, Luma([255u8]));
        for y in 0..q1.height() {
            for x in 0..q1.width() {
                combined.put_pixel(x, y, *q1.get_pixel(x, y));
            }
        }
        for y in 0..q2.height() {
            for x in 0..q2.width() {
                combined.put_pixel(q1.width() + gap + x, y, *q2.get_pixel(x, y));
            }
        }
        let mut combined_png = Vec::new();
        DynamicImage::ImageLuma8(combined)
            .write_to(&mut Cursor::new(&mut combined_png), ImageFormat::Png)
            .unwrap();

        let blank_img = GrayImage::from_pixel(128, 128, Luma([255u8]));
        let mut blank_png = Vec::new();
        DynamicImage::ImageLuma8(blank_img)
            .write_to(&mut Cursor::new(&mut blank_png), ImageFormat::Png)
            .unwrap();

        let inputs = vec![
            QrImageInputDto {
                name: "dual.png".to_string(),
                bytes: combined_png,
            },
            QrImageInputDto {
                name: "blank.png".to_string(),
                bytes: blank_png,
            },
            QrImageInputDto {
                name: "corrupt.png".to_string(),
                bytes: b"not-an-image".to_vec(),
            },
        ];

        let parsed = parse_import_qr_images(&inputs).unwrap();
        assert_eq!(parsed.accounts.len(), 2);
        assert_eq!(parsed.skipped.len(), 2);
        let issuers: Vec<&str> = parsed.accounts.iter().map(|a| a.issuer.as_str()).collect();
        assert!(issuers.contains(&"Alpha"));
        assert!(issuers.contains(&"Beta"));
    }

    #[test]
    fn test_multi_batch_export_over_10_accounts_and_svg_verification() {
        let accounts: Vec<Account> = (0..23)
            .map(|i| sample_account(i, if i % 2 == 0 { Algorithm::Sha1 } else { Algorithm::Sha256 }, if i % 3 == 0 { 8 } else { 6 }))
            .collect();

        let export = encode_export_qr_batches(&accounts).unwrap();
        assert_eq!(export.total_accounts, 23);
        assert_eq!(export.batches.len(), 3);
        assert_eq!(export.batches[0].batch_index, 0);
        assert_eq!(export.batches[0].batch_size, 3);
        assert_eq!(export.batches[0].account_count, 10);
        assert_eq!(export.batches[1].batch_index, 1);
        assert_eq!(export.batches[1].batch_size, 3);
        assert_eq!(export.batches[1].account_count, 10);
        assert_eq!(export.batches[2].batch_index, 2);
        assert_eq!(export.batches[2].batch_size, 3);
        assert_eq!(export.batches[2].account_count, 3);

        for b in &export.batches {
            assert!(b.svg.contains("<svg"));
            assert!(b.svg.contains("viewBox"));
        }

        let mut recovered = Vec::new();
        let mut batch_ids = Vec::new();
        for (idx, chunk) in accounts.chunks(10).enumerate() {
            let uri = build_migration_uri_for_accounts(chunk, idx, 3, 55555).unwrap();
            let png = render_qr_png_bytes(&uri);
            let parsed_qr = parse_import_qr_images(&[QrImageInputDto {
                name: format!("batch-{}.png", idx),
                bytes: png,
            }])
            .unwrap();
            assert_eq!(parsed_qr.skipped.len(), 0);
            recovered.extend(parsed_qr.accounts);

            let url = Url::parse(&uri).unwrap();
            let raw_data = extract_raw_query_param(&url, "data").unwrap().unwrap();
            let raw_bytes = decode_migration_base64(&raw_data).unwrap();
            let payload = decode_migration_payload(raw_bytes.as_slice()).unwrap();
            assert_eq!(payload.version, 1);
            assert_eq!(payload.batch_index, idx as i32);
            assert_eq!(payload.batch_size, 3);
            batch_ids.push(payload.batch_id);
        }

        assert_eq!(recovered.len(), 23);
        assert!(batch_ids.iter().all(|&id| id == 55555));
        for (orig, rec) in accounts.iter().zip(recovered.iter()) {
            assert_eq!(orig.issuer, rec.issuer);
            assert_eq!(orig.account, rec.account);
            assert_eq!(orig.secret, rec.secret);
            assert_eq!(orig.algorithm, rec.algorithm);
            assert_eq!(orig.digits, rec.digits);
        }
    }

    #[test]
    fn test_encode_export_empty_accounts_rejected() {
        assert!(matches!(
            encode_export_qr_batches(&[]),
            Err(AuthDeskError::InvalidParameter(_))
        ));
    }
}
