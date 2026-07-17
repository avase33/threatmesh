//! Line-rate parsing of access logs into structured records + features.
//!
//! Handles the Common/Combined Log Format (Apache/Nginx). String scanning like
//! this is where Rust crushes Python: regex with zero-cost abstractions, no
//! per-field allocation beyond the owned strings we keep, and a SHA-256 of the
//! raw payload for dedup/audit — all at hardware speed.

use std::collections::HashMap;

use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};

const SPECIAL: &[char] = &['\'', '"', ';', '=', '%', '<', '>', '(', ')', '|', '&', '$', '*'];

#[derive(Serialize, Clone)]
pub struct Record {
    pub ip: String,
    pub ts: String,
    pub method: String,
    pub path: String,
    pub status: u32,
    pub bytes: u64,
    pub hash: String,
    pub features: HashMap<String, f64>,
}

fn method_code(m: &str) -> f64 {
    match m {
        "GET" => 0.0,
        "POST" => 1.0,
        "PUT" => 2.0,
        "DELETE" => 3.0,
        "HEAD" => 4.0,
        "PATCH" => 5.0,
        "OPTIONS" => 6.0,
        _ => 7.0,
    }
}

fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let n = s.chars().count() as f64;
    -counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}

fn features(method: &str, path: &str, status: u32, bytes: u64) -> HashMap<String, f64> {
    let special = path.chars().filter(|c| SPECIAL.contains(c)).count() as f64;
    let mut m = HashMap::new();
    m.insert("bytes".into(), bytes as f64);
    m.insert("status".into(), status as f64);
    m.insert("method_code".into(), method_code(method));
    m.insert("path_len".into(), path.chars().count() as f64);
    m.insert("path_entropy".into(), (entropy(path) * 10000.0).round() / 10000.0);
    m.insert("special_chars".into(), special);
    m
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let out = h.finalize();
    out.iter().map(|b| format!("{:02x}", b)).collect()
}

thread_local! {
    static CLF: Regex = Regex::new(
        r#"^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-)"#,
    ).unwrap();
}

pub fn parse_line(line: &str) -> Option<Record> {
    CLF.with(|re| {
        let caps = re.captures(line)?;
        let ip = caps.get(1)?.as_str().to_string();
        let ts = caps.get(2)?.as_str().to_string();
        let method = caps.get(3)?.as_str().to_string();
        let path = caps.get(4)?.as_str().to_string();
        let status: u32 = caps.get(5)?.as_str().parse().ok()?;
        let bytes: u64 = caps.get(6)?.as_str().parse().unwrap_or(0);
        let features = features(&method, &path, status, bytes);
        Some(Record {
            hash: sha256_hex(line),
            ip,
            ts,
            method,
            path,
            status,
            bytes,
            features,
        })
    })
}

pub fn normalize(lines: &[String]) -> Vec<Record> {
    lines.iter().filter_map(|l| parse_line(l)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str =
        r#"192.168.1.10 - - [10/Oct/2026:13:55:36 +0000] "GET /api/products HTTP/1.1" 200 1024"#;

    #[test]
    fn parses_common_log_format() {
        let r = parse_line(LINE).unwrap();
        assert_eq!(r.ip, "192.168.1.10");
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/api/products");
        assert_eq!(r.status, 200);
        assert_eq!(r.bytes, 1024);
        assert_eq!(r.hash.len(), 64);
    }

    #[test]
    fn extracts_features_for_injection() {
        let line = r#"45.13.9.7 - - [x] "GET /p?id=1' UNION SELECT pw FROM users-- HTTP/1.1" 200 300"#;
        let r = parse_line(line).unwrap();
        assert!(r.features["special_chars"] >= 2.0);
        assert!(r.features["path_entropy"] > 0.0);
        assert!(r.features["path_len"] > 20.0);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_line("not a log line").is_none());
    }
}
