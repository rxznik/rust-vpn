use super::RoutingError;
use rvpn_model::RoutingProfile;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::Url;

pub const DEFAULT_GEOIP_URL: &str = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat";
pub const DEFAULT_GEOSITE_URL: &str = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat";
const GEO_LIMIT: u64 = 80 * 1024 * 1024;

pub fn geo_tags(profile: &RoutingProfile) -> (HashSet<String>, HashSet<String>) {
    let mut sites = HashSet::new();
    let mut ips = HashSet::new();
    for item in profile.direct_sites.iter().chain(&profile.proxy_sites).chain(&profile.block_sites) {
        if let Some(tag) = strip_prefix_ignore(item, "geosite:") {
            sites.insert(tag.to_ascii_lowercase());
        }
    }
    for item in profile.direct_ip.iter().chain(&profile.proxy_ip).chain(&profile.block_ip) {
        if let Some(tag) = strip_prefix_ignore(item, "geoip:") {
            ips.insert(tag.to_ascii_lowercase());
        }
    }
    (ips, sites)
}

/// Keep only the geo entries whose tag is in `tags`. Matching is case-insensitive.
pub fn trim_geo_list(bytes: &[u8], tags: &HashSet<String>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        let Some(key) = read_varint(bytes, &mut i) else { break };
        let field = key >> 3;
        let wire = key & 7;
        if wire == 2 {
            let Some(len) = read_varint(bytes, &mut i) else { break };
            let len = len as usize;
            if i + len > bytes.len() {
                break;
            }
            let message = &bytes[i..i + len];
            i += len;
            if field == 1 {
                if let Some(code) = first_string(message) {
                    if tags.contains(&code.to_ascii_lowercase()) {
                        out.extend_from_slice(&bytes[start..i]);
                    }
                }
            }
        } else if !skip_wire(bytes, &mut i, wire) {
            break;
        }
    }
    out
}

/// Result of writing geo databases. The profile is still usable when `files_missing` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeoMaterial {
    pub files_missing: bool,
}

pub fn materialize_geo(profile: &mut RoutingProfile, dir: &Path) -> Result<GeoMaterial, RoutingError> {
    let (ip_tags, site_tags) = geo_tags(profile);
    fs::create_dir_all(dir)?;
    let mut missing = false;
    if ip_tags.is_empty() {
        profile.geoip_path = None;
    } else {
        let url = geo_download_url(&profile.geoip_url, DEFAULT_GEOIP_URL)?;
        match download_cached(url, dir) {
            Ok(bytes) => {
                let trimmed = trim_geo_list(&bytes, &ip_tags);
                let path = dir.join("geoip.dat");
                fs::write(&path, trimmed)?;
                profile.geoip_path = Some(path.display().to_string());
            }
            Err(RoutingError::Geo(_)) => {
                missing = true;
                profile.geoip_path = None;
            }
            Err(err) => return Err(err),
        }
    }
    if site_tags.is_empty() {
        profile.geosite_path = None;
    } else {
        let url = geo_download_url(&profile.geosite_url, DEFAULT_GEOSITE_URL)?;
        match download_cached(url, dir) {
            Ok(bytes) => {
                let trimmed = trim_geo_list(&bytes, &site_tags);
                let path = dir.join("geosite.dat");
                fs::write(&path, trimmed)?;
                profile.geosite_path = Some(path.display().to_string());
            }
            Err(RoutingError::Geo(_)) => {
                missing = true;
                profile.geosite_path = None;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(GeoMaterial { files_missing: missing })
}

pub fn asset_dir(profile: &RoutingProfile) -> Option<PathBuf> {
    profile.geoip_path.as_ref().or(profile.geosite_path.as_ref()).and_then(|path| Path::new(path).parent().map(|p| p.to_path_buf()))
}

pub(crate) fn geo_download_url<'a>(custom: &'a str, default: &'a str) -> Result<&'a str, RoutingError> {
    if custom.is_empty() {
        return Ok(default);
    }
    if allowed_geo_url(custom) {
        Ok(custom)
    } else {
        Err(RoutingError::Geo("geo database URL is not on the allowed list".into()))
    }
}

fn allowed_geo_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https" {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    host == "github.com" || host == "cdn.jsdelivr.net" || host.ends_with(".githubusercontent.com")
}

pub(crate) fn download_cached(url: &str, dir: &Path) -> Result<Vec<u8>, RoutingError> {
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    let path = dir.join("cache").join(super::hex_encode(&hasher.finalize()));
    if let Ok(bytes) = fs::read(&path) {
        if !bytes.is_empty() {
            return Ok(bytes);
        }
    }
    let bytes = download(url)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, &bytes)?;
    Ok(bytes)
}

fn download(url: &str) -> Result<Vec<u8>, RoutingError> {
    let response = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(60))
        .build()
        .get(url)
        .call()
        .map_err(|e| RoutingError::Geo(e.to_string()))?;
    let mut limited = response.into_reader().take(GEO_LIMIT);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn strip_prefix_ignore<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let (head, tail) = value.split_at_checked(prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) { Some(tail) } else { None }
}

pub(crate) fn first_string(message: &[u8]) -> Option<String> {
    let mut i = 0;
    while i < message.len() {
        let key = read_varint(message, &mut i)?;
        let field = key >> 3;
        let wire = key & 7;
        if wire == 2 {
            let len = read_varint(message, &mut i)? as usize;
            if i + len > message.len() {
                return None;
            }
            let bytes = &message[i..i + len];
            i += len;
            if field == 1 {
                return String::from_utf8(bytes.to_vec()).ok();
            }
        } else if !skip_wire(message, &mut i, wire) {
            return None;
        }
    }
    None
}

fn skip_wire(bytes: &[u8], i: &mut usize, wire: u64) -> bool {
    match wire {
        0 => read_varint(bytes, i).is_some(),
        1 => {
            *i += 8;
            *i <= bytes.len()
        }
        2 => {
            let Some(len) = read_varint(bytes, i) else { return false };
            *i += len as usize;
            *i <= bytes.len()
        }
        5 => {
            *i += 4;
            *i <= bytes.len()
        }
        _ => false,
    }
}

fn read_varint(bytes: &[u8], i: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0;
    while *i < bytes.len() && shift < 64 {
        let byte = bytes[*i];
        *i += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}
