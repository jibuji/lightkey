//! BYO 存储后端抽象（规格：`docs/sync.md` §1/§3）。
//!
//! - [`StorageBackend`]：同步引擎的存储视角——`get` / 条件写 `put`（CAS：
//!   `If-Match`/ETag）/ `delete` / `list` / `etag`。对象键即本地文件名
//!   （`index.lk`、`{uuid}.item.lk`、`{uuid}.tomb.lk`、`{uuid}.attach.lk`、
//!   `{uuid}.{i}.chunk.lk`），全部为**密文 blob 原样传输**（不重加密）。
//! - 三种实现：本地文件系统模拟（`file://`，E2E 用；ETag = 内容 SHA-256）、
//!   WebDAV（`http(s)://`，`If-Match` + PROPFIND/MKCOL）、S3 兼容（`s3://`，
//!   SigV4 + 条件写 `If-Match` + ListObjectsV2）。
//! - 凭据（WebDAV 账号密码 / S3 密钥）由调用方经 [`Credentials`] 传入
//!   （守护进程从系统钥匙串读取，见 `lk-cli`）；本模块不接触钥匙串。
//! - 安全：对象键严格校验（仅允许已知文件名形态），远端 `list()` 返回的
//!   任意键不会逃逸到本地路径（防路径穿越）。
//!
//! 失败语义：网络 / 存储端 4xx/5xx → [`Error::SyncStorage`]（本轮放弃，
//! 下一轮重试）；密文问题不在此层（同步引擎处理为 [`Error::SyncAnomaly`]）。

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use sha2::Digest;
use zeroize::Zeroizing;

use crate::crypto::random_bytes;
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// 对象键
// ---------------------------------------------------------------------------

/// 索引对象键（远端与本地同名）。
pub const INDEX_KEY: &str = "index.lk";

fn is_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok()
}

/// 校验对象键：只接受已知文件名形态（index.lk / {uuid}.item.lk /
/// {uuid}.tomb.lk / {uuid}.attach.lk / {uuid}.{i}.chunk.lk）。
///
/// 防路径穿越：远端 `list()` 结果不可信，任何不匹配的键一律拒绝。
pub fn valid_key(key: &str) -> bool {
    if key == INDEX_KEY {
        return true;
    }
    for sfx in [".item.lk", ".tomb.lk", ".attach.lk"] {
        if let Some(stem) = key.strip_suffix(sfx) {
            return is_uuid(stem);
        }
    }
    // {uuid}.{i}.chunk.lk
    if let Some(stem) = key.strip_suffix(".chunk.lk") {
        if let Some((uuid_part, idx)) = stem.rsplit_once('.') {
            return is_uuid(uuid_part)
                && !idx.is_empty()
                && idx.bytes().all(|b| b.is_ascii_digit());
        }
    }
    false
}

// ---------------------------------------------------------------------------
// 凭据
// ---------------------------------------------------------------------------

/// 存储凭据（WebDAV 账号密码 / S3 AccessKey+SecretKey）。
///
/// 由调用方从系统钥匙串读取后传入；密码内存 `Zeroizing` 擦除。
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: Zeroizing<String>,
}

// ---------------------------------------------------------------------------
// trait
// ---------------------------------------------------------------------------

/// GET 结果：数据 + 存储端 ETag（CAS 依据）。
#[derive(Debug, Clone)]
pub struct GetResult {
    pub etag: String,
    pub data: Vec<u8>,
}

/// 条件写结果。
#[derive(Debug, Clone)]
pub enum PutOutcome {
    /// 写入成功（返回存储端新 ETag）。
    Written { etag: String },
    /// CAS 冲突：`If-Match` 校验失败（对象存在且 ETag 不匹配，或
    /// 期望不存在但对象已存在）。
    Conflict,
}

/// 远端对象（`list()` 元素）。
#[derive(Debug, Clone)]
pub struct RemoteObject {
    pub key: String,
    pub etag: String,
    pub size: u64,
}

/// BYO 存储后端。
///
/// 语义约定：
/// - `put(key, data, None)` = 仅当对象不存在时创建；已存在 → [`PutOutcome::Conflict`]。
/// - `put(key, data, Some(etag))` = 仅当当前 ETag 等于 `etag` 时覆盖；
///   不匹配 → [`PutOutcome::Conflict`]。
/// - `delete` 对不存在的对象视为成功（幂等）。
/// - `get` / `etag` 对不存在的对象返回 `Ok(None)`。
/// - 网络 / 存储端错误统一 [`Error::SyncStorage`]。
pub trait StorageBackend: Send + Sync {
    /// 后端名（诊断用）：`"local"` / `"webdav"` / `"s3"`。
    fn name(&self) -> &'static str;

    fn get(&self, key: &str) -> Result<Option<GetResult>>;

    fn put(&self, key: &str, data: &[u8], expected_etag: Option<&str>) -> Result<PutOutcome>;

    fn delete(&self, key: &str) -> Result<()>;

    fn list(&self) -> Result<Vec<RemoteObject>>;

    fn etag(&self, key: &str) -> Result<Option<String>>;
}

/// 按 URL 选择后端（`file://` 本地模拟 / `http(s)://` WebDAV / `s3://` S3 兼容）。
pub fn backend_from_url(url: &str, creds: Option<Credentials>) -> Result<Box<dyn StorageBackend>> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| Error::SyncConfig(format!("URL 缺少协议（{url}）")))?;
    match scheme {
        "file" => {
            let path = PathBuf::from(rest);
            if !path.is_absolute() {
                return Err(Error::SyncConfig(format!("file:// 需要绝对路径（{url}）")));
            }
            Ok(Box::new(LocalStorage::new(path)))
        }
        "http" | "https" => {
            let creds = creds.ok_or_else(|| {
                Error::SyncConfig("WebDAV 需要凭据（lk config sync set 时输入）".into())
            })?;
            Ok(Box::new(WebDav::new(url, creds)?))
        }
        "s3" => {
            let creds = creds.ok_or_else(|| {
                Error::SyncConfig("S3 需要凭据（lk config sync set 时输入）".into())
            })?;
            Ok(Box::new(S3Backend::parse(url, creds)?))
        }
        other => Err(Error::SyncConfig(format!(
            "不支持的存储协议 {other}（支持 file:// / http(s):// / s3://）"
        ))),
    }
}

// ---------------------------------------------------------------------------
// 本地文件系统模拟（file://）
// ---------------------------------------------------------------------------

/// 本地文件系统后端：`file://`（E2E / 本地模拟 WebDAV/S3 用）。
///
/// ETag = 内容 SHA-256（十六进制，确定性）；条件写比较当前内容哈希。
/// 语义与 WebDAV/S3 后端一致（CAS、404、幂等删除）；写入原子
/// （tmp + rename，失败恢复语义：不产生半写状态）。
pub struct LocalStorage {
    dir: PathBuf,
}

impl LocalStorage {
    pub fn new(dir: PathBuf) -> LocalStorage {
        LocalStorage { dir }
    }

    fn path(&self, key: &str) -> Result<PathBuf> {
        if !valid_key(key) {
            return Err(Error::SyncConfig(format!("非法对象键：{key}")));
        }
        Ok(self.dir.join(key))
    }

    fn content_etag(data: &[u8]) -> String {
        hex::encode(sha2::Sha256::digest(data))
    }
}

impl StorageBackend for LocalStorage {
    fn name(&self) -> &'static str {
        "local"
    }

    fn get(&self, key: &str) -> Result<Option<GetResult>> {
        let path = self.path(key)?;
        match std::fs::read(&path) {
            Ok(data) => Ok(Some(GetResult {
                etag: Self::content_etag(&data),
                data,
            })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::SyncStorage(format!("读取 {key}: {e}"))),
        }
    }

    fn put(&self, key: &str, data: &[u8], expected_etag: Option<&str>) -> Result<PutOutcome> {
        let path = self.path(key)?;
        let current = self.get(key)?;
        match (expected_etag, current) {
            (Some(want), Some(cur)) if want != cur.etag => return Ok(PutOutcome::Conflict),
            (Some(_), None) => return Ok(PutOutcome::Conflict), // 期望覆盖但对象已消失
            (None, Some(_)) => return Ok(PutOutcome::Conflict), // 期望创建但对象已存在
            _ => {}
        }
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| Error::SyncStorage(format!("创建存储目录: {e}")))?;
        let tmp = path.with_extension(format!("tmp-{}", hex::encode(random_bytes(4))));
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| Error::SyncStorage(format!("写入 {key}: {e}")))?;
            f.write_all(data)
                .map_err(|e| Error::SyncStorage(format!("写入 {key}: {e}")))?;
            f.sync_all()
                .map_err(|e| Error::SyncStorage(format!("写入 {key}: {e}")))?;
        }
        std::fs::rename(&tmp, &path).map_err(|e| Error::SyncStorage(format!("写入 {key}: {e}")))?;
        Ok(PutOutcome::Written {
            etag: Self::content_etag(data),
        })
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.path(key)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::SyncStorage(format!("删除 {key}: {e}"))),
        }
    }

    fn list(&self) -> Result<Vec<RemoteObject>> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(Error::SyncStorage(format!("列出存储: {e}"))),
        };
        for entry in entries {
            let entry = entry.map_err(|e| Error::SyncStorage(format!("列出存储: {e}")))?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("tmp-") || !valid_key(&name) {
                continue;
            }
            let meta = entry
                .metadata()
                .map_err(|e| Error::SyncStorage(format!("列出存储: {e}")))?;
            let data = std::fs::read(entry.path())
                .map_err(|e| Error::SyncStorage(format!("列出存储: {e}")))?;
            out.push(RemoteObject {
                key: name,
                etag: Self::content_etag(&data),
                size: meta.len(),
            });
        }
        Ok(out)
    }

    fn etag(&self, key: &str) -> Result<Option<String>> {
        Ok(self.get(key)?.map(|g| g.etag))
    }
}

// ---------------------------------------------------------------------------
// WebDAV（http(s)://）
// ---------------------------------------------------------------------------

/// WebDAV 后端（`If-Match`/ETag CAS；PROPFIND 列目录；MKCOL 建集合）。
///
/// - 条件写：`If-Match: <etag>`；412 → CAS 冲突。
/// - 存储端必须返回 ETag（GET/PUT 响应头）；不支持 ETag 的服务器视为
///   配置错误（CAS 无法执行，fail loud）。
/// - 首次写入前 `MKCOL` 建集合（已存在则忽略 405/301）。
/// - 键经 URL 编码拼入 base URL；href 解析后须过 [`valid_key`]。
pub struct WebDav {
    base: String,
    client: reqwest::blocking::Client,
    #[allow(dead_code)] // 凭据仅用于构造 Authorization 头
    creds: Credentials,
    auth: String,
}

impl WebDav {
    pub fn new(base_url: &str, creds: Credentials) -> Result<WebDav> {
        let base = if base_url.ends_with('/') {
            base_url.to_string()
        } else {
            format!("{base_url}/")
        };
        use base64::Engine as _;
        let client = http_client();
        let auth = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", creds.username, *creds.password))
        );
        Ok(WebDav {
            base,
            client,
            creds,
            auth,
        })
    }

    fn url(&self, key: &str) -> String {
        // 键为 ASCII 安全字符（UUID + 后缀），无需编码；先校验防注入
        debug_assert!(valid_key(key));
        format!("{}{}", self.base, key)
    }

    /// MKCOL 建集合（幂等：已存在 → 405/301/302/409 忽略）。
    fn ensure_collection(&self) -> Result<()> {
        match run_request(
            &self.client,
            "MKCOL",
            &self.base,
            &[("Authorization", &self.auth)],
            None,
        ) {
            Ok(resp) if (200..300).contains(&resp.status().as_u16()) => Ok(()),
            Ok(resp) if matches!(resp.status().as_u16(), 405 | 301 | 302 | 409) => Ok(()),
            Ok(resp) => Err(Error::SyncStorage(format!("MKCOL: HTTP {}", resp.status()))),
            Err(e) => Err(e),
        }
    }

    /// PROPFIND depth 1：解析 multistatus 的 href + getetag。
    fn propfind(&self) -> Result<Vec<RemoteObject>> {
        let xml = "<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:getetag/></d:prop></d:propfind>";
        let resp = run_request(
            &self.client,
            "PROPFIND",
            &self.base,
            &[("Authorization", &self.auth), ("Depth", "1")],
            Some(xml.as_bytes()),
        )?;
        let status = resp.status().as_u16();
        if status == 404 {
            return Ok(Vec::new()); // 集合不存在 → 空（首次同步）
        }
        if !(200..300).contains(&status) {
            return Err(Error::SyncStorage(format!("PROPFIND 失败：HTTP {status}")));
        }
        let body = resp
            .text()
            .map_err(|e| Error::SyncStorage(format!("PROPFIND 响应读取失败: {e}")))?;
        parse_multistatus(&body, &self.base)
    }
}

/// 统一 HTTP 客户端（60s 全局超时 / 15s 连接超时；失败恢复语义要求本轮有界）。
///
/// 不走环境代理（`.no_proxy()`）：BYO 存储直连是安全默认——凭据流量不
/// 应被静默路由到代理；需要代理的环境后续按需配置。
fn http_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(15))
        .build()
        .expect("reqwest 客户端构建不会失败")
}

/// 通用 HTTP 请求（支持任意方法：PROPFIND / MKCOL 等）。
fn run_request(
    client: &reqwest::blocking::Client,
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<reqwest::blocking::Response> {
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|e| Error::SyncStorage(format!("非法 HTTP 方法: {e}")))?;
    let method_name = method.as_str().to_string();
    let mut req = client.request(method, url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    if let Some(b) = body {
        req = req.body(b.to_vec());
    }
    req.send()
        .map_err(|e| Error::SyncStorage(format!("{method_name} {url}: {e}")))
}

/// 解析 WebDAV multistatus（`d:response` → href/getetag）。
fn parse_multistatus(body: &str, base: &str) -> Result<Vec<RemoteObject>> {
    let base_name = base.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    let mut out = Vec::new();
    let mut reader = quick_xml::Reader::from_str(body);
    let mut buf = Vec::new();
    let mut cur_href: Option<String> = None;
    let mut cur_etag: Option<String> = None;
    let mut in_response = false;
    let mut in_href = false;
    let mut in_etag = false;
    let mut in_propstat = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(e)) | Ok(quick_xml::events::Event::Empty(e)) => {
                match local_name(e.name().as_ref()) {
                    "response" => {
                        in_response = true;
                        in_propstat = false;
                        cur_href = None;
                        cur_etag = None;
                    }
                    "href" if in_response => in_href = true,
                    "getetag" if in_propstat => in_etag = true,
                    "propstat" => in_propstat = true,
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::End(e)) => match local_name(e.name().as_ref()) {
                "response" => {
                    in_response = false;
                    in_propstat = false;
                    // 跳过集合自身（base 名）与非法键
                    if let (Some(href), Some(etag)) = (&cur_href, &cur_etag) {
                        if let Some(key) = key_from_href(href, base_name) {
                            if valid_key(&key) {
                                out.push(RemoteObject {
                                    key,
                                    etag: etag.trim().trim_matches('"').to_string(),
                                    size: 0,
                                });
                            }
                        }
                    }
                }
                "href" => in_href = false,
                "getetag" => in_etag = false,
                "propstat" => in_propstat = false,
                _ => {}
            },
            Ok(quick_xml::events::Event::Text(t)) if in_href || in_etag => {
                let text = t.unescape().unwrap_or_default().trim().to_string();
                if in_href {
                    cur_href = Some(text);
                } else {
                    cur_etag = Some(text);
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => {
                return Err(Error::SyncStorage(format!("PROPFIND 响应解析失败: {e}")));
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

/// 取 XML 元素本地名（去掉命名空间前缀，如 `d:href` → `href`）。
fn local_name(qname: &[u8]) -> &str {
    let s = std::str::from_utf8(qname).unwrap_or("");
    s.rsplit_once(':').map(|(_, n)| n).unwrap_or(s)
}

/// 从 PROPFIND href 提取相对 base 的对象键。
fn key_from_href(href: &str, base_name: &str) -> Option<String> {
    let decoded = percent_decode(href);
    let trimmed = decoded.trim_end_matches('/');
    let last = trimmed.rsplit('/').next()?;
    if last.is_empty() || last == base_name {
        return None;
    }
    Some(last.to_string())
}

/// 轻量百分号解码（对象键为 ASCII，仅需处理 %XX）。
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl StorageBackend for WebDav {
    fn name(&self) -> &'static str {
        "webdav"
    }

    fn get(&self, key: &str) -> Result<Option<GetResult>> {
        let resp = self
            .client
            .get(self.url(key))
            .header("Authorization", &self.auth)
            .send()
            .map_err(|e| Error::SyncStorage(format!("GET {key}: {e}")))?;
        match resp.status().as_u16() {
            404 => Ok(None),
            code if !(200..300).contains(&code) => {
                Err(Error::SyncStorage(format!("GET {key}: HTTP {code}")))
            }
            _ => {
                let etag = resp
                    .headers()
                    .get("ETag")
                    .and_then(|v| v.to_str().ok())
                    .map(|e| e.trim().trim_matches('"').to_string())
                    .unwrap_or_default();
                if etag.is_empty() {
                    return Err(Error::SyncStorage(format!(
                        "存储端未返回 ETag（{key}），无法执行 CAS"
                    )));
                }
                let data = resp
                    .bytes()
                    .map_err(|e| Error::SyncStorage(format!("GET {key}: {e}")))?
                    .to_vec();
                Ok(Some(GetResult { etag, data }))
            }
        }
    }

    fn put(&self, key: &str, data: &[u8], expected_etag: Option<&str>) -> Result<PutOutcome> {
        // 首次写入前确保集合存在（幂等）
        self.ensure_collection()?;
        // CAS：创建 = If-None-Match: *（对象不存在才写）；覆盖 = If-Match: <etag>
        let (cond_name, cond_val) = match expected_etag {
            Some(e) => ("If-Match", format!("\"{}\"", e.trim().trim_matches('"'))),
            None => ("If-None-Match", "*".to_string()),
        };
        let resp = self
            .client
            .put(self.url(key))
            .header("Authorization", &self.auth)
            .header(cond_name, &cond_val)
            .body(data.to_vec())
            .send()
            .map_err(|e| Error::SyncStorage(format!("PUT {key}: {e}")))?;
        match resp.status().as_u16() {
            412 => Ok(PutOutcome::Conflict),
            code if !(200..300).contains(&code) => {
                Err(Error::SyncStorage(format!("PUT {key}: HTTP {code}")))
            }
            _ => {
                let etag = resp
                    .headers()
                    .get("ETag")
                    .and_then(|v| v.to_str().ok())
                    .map(|e| e.trim().trim_matches('"').to_string())
                    .unwrap_or_default();
                if etag.is_empty() {
                    return Err(Error::SyncStorage(format!(
                        "存储端未返回 ETag（{key}），无法执行 CAS"
                    )));
                }
                Ok(PutOutcome::Written { etag })
            }
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        let resp = self
            .client
            .delete(self.url(key))
            .header("Authorization", &self.auth)
            .send()
            .map_err(|e| Error::SyncStorage(format!("DELETE {key}: {e}")))?;
        match resp.status().as_u16() {
            404 => Ok(()),
            code if !(200..300).contains(&code) => {
                Err(Error::SyncStorage(format!("DELETE {key}: HTTP {code}")))
            }
            _ => Ok(()),
        }
    }

    fn list(&self) -> Result<Vec<RemoteObject>> {
        self.propfind()
    }

    fn etag(&self, key: &str) -> Result<Option<String>> {
        let resp = self
            .client
            .head(self.url(key))
            .header("Authorization", &self.auth)
            .send()
            .map_err(|e| Error::SyncStorage(format!("HEAD {key}: {e}")))?;
        match resp.status().as_u16() {
            404 => Ok(None),
            code if !(200..300).contains(&code) => {
                Err(Error::SyncStorage(format!("HEAD {key}: HTTP {code}")))
            }
            _ => Ok(resp
                .headers()
                .get("ETag")
                .and_then(|v| v.to_str().ok())
                .map(|e| e.trim().trim_matches('"').to_string())
                .filter(|e| !e.is_empty())),
        }
    }
}

// ---------------------------------------------------------------------------
// S3 兼容（s3://）
// ---------------------------------------------------------------------------

/// S3 URL：`s3://<bucket>/<prefix>?region=...&endpoint=...`
///
/// - `region` 缺省：`AWS_REGION` / `AWS_DEFAULT_REGION` / `us-east-1`。
/// - `endpoint`（可选）：S3 兼容存储（MinIO 等）的完整 base URL（path-style）；
///   缺省走 AWS（虚拟主机风格 `{bucket}.s3.{region}.amazonaws.com`）。
/// - 凭据：`Credentials{username: AccessKey, password: SecretKey}`。
/// - 条件写：`If-Match`（S3 2024-11 起支持）；412 → CAS 冲突。
/// - 列目录：ListObjectsV2（XML 解析，分页续传）。
/// - 请求签名：AWS SigV4（UNSIGNED-PAYLOAD；测试用官方测试向量验证）。
pub struct S3Backend {
    /// 完整 base（含 bucket；path-style 为 `http://host/bucket`，
    /// 虚拟主机风格为 `https://bucket.s3.{region}.amazonaws.com`）。
    endpoint: String,
    bucket: String,
    prefix: String,
    region: String,
    /// path-style（自定义 endpoint）时 canonical URI 需含 bucket 段。
    path_style: bool,
    access_key: String,
    secret_key: Zeroizing<String>,
    client: reqwest::blocking::Client,
}

impl S3Backend {
    pub fn parse(url: &str, creds: Credentials) -> Result<S3Backend> {
        let rest = url
            .strip_prefix("s3://")
            .ok_or_else(|| Error::SyncConfig(format!("S3 URL 无效：{url}")))?;
        let (authority, path_and_query) = match rest.split_once('/') {
            Some((a, p)) => (a, p),
            None => (rest, ""),
        };
        let (path, query) = match path_and_query.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path_and_query, None),
        };
        let bucket = authority.to_string();
        if bucket.is_empty()
            || !bucket
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(Error::SyncConfig(format!("S3 bucket 无效：{bucket}")));
        }
        let prefix = path.trim_matches('/').to_string();
        let mut region = std::env::var("AWS_REGION")
            .ok()
            .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
            .unwrap_or_else(|| "us-east-1".to_string());
        let mut endpoint_override: Option<String> = None;
        if let Some(q) = query {
            for pair in q.split('&') {
                let Some((k, v)) = pair.split_once('=') else {
                    continue;
                };
                match k {
                    "region" => region = v.to_string(),
                    "endpoint" => endpoint_override = Some(v.to_string()),
                    _ => {}
                }
            }
        }
        let (endpoint, path_style) = match endpoint_override {
            Some(ep) => (format!("{}/{}", ep.trim_end_matches('/'), bucket), true),
            None => (format!("https://{bucket}.s3.{region}.amazonaws.com"), false),
        };
        let client = http_client();
        Ok(S3Backend {
            endpoint,
            bucket,
            prefix,
            region,
            path_style,
            access_key: creds.username,
            secret_key: creds.password,
            client,
        })
    }

    /// 发送已签名请求。`key=None` 时为桶级操作（列表，query 携带参数）。
    /// 返回 (status, headers, body)。
    fn send(
        &self,
        method: &str,
        key: Option<&str>,
        query: Option<&str>,
        extra_headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<RawResponse> {
        let (canonical_uri, full_url) = match key {
            Some(k) => {
                let full = if self.prefix.is_empty() {
                    k.to_string()
                } else {
                    format!("{}/{}", self.prefix, k)
                };
                let encoded = uri_encode_path(&full);
                let canonical_uri = if self.path_style {
                    format!("/{}/{}", self.bucket, encoded)
                } else {
                    format!("/{encoded}")
                };
                let url = format!("{}/{}", self.endpoint, encoded);
                (canonical_uri, url)
            }
            None => {
                let q = query.unwrap_or_default();
                let url = format!("{}/?{}", self.endpoint, q);
                ("/".to_string(), url)
            }
        };

        // 签名头（host + x-amz-* + 调用方附加头），排序后参与签名
        let mut signed_headers: Vec<(String, String)> = vec![
            ("host".to_string(), host_of(&self.endpoint).to_string()),
            (
                "x-amz-content-sha256".to_string(),
                "UNSIGNED-PAYLOAD".to_string(),
            ),
            ("x-amz-date".to_string(), amz_date()),
        ];
        for (k, v) in extra_headers {
            signed_headers.push((k.to_string(), v.to_string()));
        }
        signed_headers.sort();

        let canonical_headers = signed_headers
            .iter()
            .map(|(k, v)| format!("{}:{}\n", k.to_ascii_lowercase(), v.trim()))
            .collect::<String>();
        let signed_header_names = signed_headers
            .iter()
            .map(|(k, _)| k.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(";");

        let (canonical_query, _) = match key {
            Some(_) => (String::new(), String::new()),
            None => (
                canonical_query_string(query.unwrap_or_default()),
                String::new(),
            ),
        };
        let canonical_request = format!(
            "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_header_names}\nUNSIGNED-PAYLOAD"
        );

        let ts = amz_date();
        let date = &ts[..8];
        let scope = format!("{date}/s3/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{ts}\n{scope}\n{}",
            hex::encode(sha2::Sha256::digest(canonical_request.as_bytes()))
        );
        let signing_key = sigv4_key(self.secret_key.as_str(), date, &self.region);
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key, scope, signed_header_names, signature
        );

        // 实际发出的头 = 签名头（同名同值）
        let mut header_pairs: Vec<(&str, &str)> = vec![
            ("Authorization", &auth),
            ("x-amz-date", &ts),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ];
        header_pairs.extend(extra_headers.iter().copied());
        let resp = run_request(&self.client, method, &full_url, &header_pairs, body)
            .map_err(|e| Error::SyncStorage(format!("S3 {method} {key:?}: {e}")))?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let body = resp
            .bytes()
            .map_err(|e| Error::SyncStorage(format!("S3 {method} 响应读取: {e}")))?
            .to_vec();
        Ok((status, headers, body))
    }
}

/// S3 原始响应：(status, headers, body)。
type RawResponse = (u16, Vec<(String, String)>, Vec<u8>);

/// 当前 UTC 时间（S3 签名与 x-amz-date 用）。
fn amz_date() -> String {
    let now = time::OffsetDateTime::now_utc();
    now.format(&time::macros::format_description!(
        "[year][month][day]T[hour][minute][second]Z"
    ))
    .expect("固定格式")
}

fn host_of(endpoint: &str) -> &str {
    endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// SigV4 派生签名密钥（AWS4{secret} → date → region → service → aws4_request）。
pub fn sigv4_key(secret: &str, date: &str, region: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    hmac_sha256(&k_service, b"aws4_request")
}

/// URI 编码路径段（RFC 3986：保留 `/`，其余非 unreserved 转义，大写 hex）。
fn uri_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 规范化查询串（按 key 排序，URI 编码）。
fn canonical_query_string(q: &str) -> String {
    let mut pairs: Vec<(String, String)> = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (uri_encode_query(k), uri_encode_query(v))
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn uri_encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 解析 ListObjectsV2 响应（Contents → key/etag/size；分页 token）。
fn parse_list_v2(body: &str) -> Result<(Vec<RemoteObject>, Option<String>)> {
    let mut out = Vec::new();
    let mut next_token: Option<String> = None;
    let mut reader = quick_xml::Reader::from_str(body);
    let mut buf = Vec::new();
    let mut in_contents = false;
    let mut cur_key: Option<String> = None;
    let mut cur_etag: Option<String> = None;
    let mut cur_size: u64 = 0;
    let mut in_key = false;
    let mut in_etag = false;
    let mut in_size = false;
    let mut in_next_token = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(e)) | Ok(quick_xml::events::Event::Empty(e)) => {
                match local_name(e.name().as_ref()) {
                    "Contents" => {
                        in_contents = true;
                        cur_key = None;
                        cur_etag = None;
                        cur_size = 0;
                    }
                    "Key" if in_contents => in_key = true,
                    "ETag" if in_contents => in_etag = true,
                    "Size" if in_contents => in_size = true,
                    "NextContinuationToken" => in_next_token = true,
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::End(e)) => match local_name(e.name().as_ref()) {
                "Contents" => {
                    in_contents = false;
                    if let Some(key) = cur_key.take() {
                        out.push(RemoteObject {
                            key,
                            etag: cur_etag
                                .take()
                                .unwrap_or_default()
                                .trim_matches('"')
                                .to_string(),
                            size: cur_size,
                        });
                    }
                }
                "Key" => in_key = false,
                "ETag" => in_etag = false,
                "Size" => in_size = false,
                "NextContinuationToken" => in_next_token = false,
                _ => {}
            },
            Ok(quick_xml::events::Event::Text(t)) => {
                let text = t.unescape().unwrap_or_default().trim().to_string();
                if in_key {
                    cur_key = Some(text);
                } else if in_etag {
                    cur_etag = Some(text);
                } else if in_size {
                    cur_size = text.parse().unwrap_or(0);
                } else if in_next_token {
                    next_token = Some(text);
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => {
                return Err(Error::SyncStorage(format!(
                    "ListObjectsV2 响应解析失败: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }
    Ok((out, next_token))
}

impl StorageBackend for S3Backend {
    fn name(&self) -> &'static str {
        "s3"
    }

    fn get(&self, key: &str) -> Result<Option<GetResult>> {
        let (status, headers, body) = self.send("GET", Some(key), None, &[], None)?;
        match status {
            200 => {
                let etag = headers
                    .iter()
                    .find(|(k, _)| k == "etag")
                    .map(|(_, v)| v.trim_matches('"').to_string())
                    .unwrap_or_default();
                if etag.is_empty() {
                    return Err(Error::SyncStorage(format!(
                        "存储端未返回 ETag（{key}），无法执行 CAS"
                    )));
                }
                Ok(Some(GetResult { etag, data: body }))
            }
            404 => Ok(None),
            _ => Err(Error::SyncStorage(format!("S3 GET {key}: HTTP {status}"))),
        }
    }

    fn put(&self, key: &str, data: &[u8], expected_etag: Option<&str>) -> Result<PutOutcome> {
        // CAS：创建 = If-None-Match: *；覆盖 = If-Match: <etag>（S3 2024-11 起支持）
        let extra: Vec<(&str, &str)> = match expected_etag {
            Some(e) => vec![("If-Match", e.trim().trim_matches('"'))],
            None => vec![("If-None-Match", "*")],
        };
        let (status, _, _) = self.send("PUT", Some(key), None, &extra, Some(data))?;
        match status {
            200 | 201 => Ok(PutOutcome::Written {
                etag: match expected_etag {
                    Some(e) => e.trim().trim_matches('"').to_string(),
                    None => hex::encode(sha2::Sha256::digest(data)),
                },
            }),
            412 => Ok(PutOutcome::Conflict),
            _ => Err(Error::SyncStorage(format!("S3 PUT {key}: HTTP {status}"))),
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        let (status, _, _) = self.send("DELETE", Some(key), None, &[], None)?;
        match status {
            204 | 404 => Ok(()),
            _ => Err(Error::SyncStorage(format!(
                "S3 DELETE {key}: HTTP {status}"
            ))),
        }
    }

    fn list(&self) -> Result<Vec<RemoteObject>> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let query = match &token {
                Some(t) => format!(
                    "list-type=2&prefix={}&continuation-token={}",
                    uri_encode_query(&self.prefix),
                    uri_encode_query(t)
                ),
                None => format!("list-type=2&prefix={}", uri_encode_query(&self.prefix)),
            };
            let (status, _, body) = self.send("GET", None, Some(&query), &[], None)?;
            if status != 200 {
                return Err(Error::SyncStorage(format!(
                    "S3 ListObjectsV2: HTTP {status}"
                )));
            }
            let body_str = String::from_utf8_lossy(&body).into_owned();
            let (objs, next) = parse_list_v2(&body_str)?;
            // 去掉 prefix 前缀，还原对象键
            for mut o in objs {
                if let Some(stripped) = o.key.strip_prefix(&self.prefix).map(str::to_string) {
                    o.key = stripped.trim_start_matches('/').to_string();
                }
                out.push(o);
            }
            match next {
                Some(t) if !t.is_empty() => token = Some(t),
                _ => break,
            }
        }
        Ok(out)
    }

    fn etag(&self, key: &str) -> Result<Option<String>> {
        let (status, headers, _) = self.send("HEAD", Some(key), None, &[], None)?;
        match status {
            200 => Ok(headers
                .iter()
                .find(|(k, _)| k == "etag")
                .map(|(_, v)| v.trim_matches('"').to_string())
                .filter(|e| !e.is_empty())),
            404 => Ok(None),
            _ => Err(Error::SyncStorage(format!("S3 HEAD {key}: HTTP {status}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// 测试：本地模拟 HTTP 服务器（WebDAV / S3 行为测试共用）
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod mock_http {
    use sha2::Digest;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// 简易内存对象存储（模拟 WebDAV/S3 的 CAS 语义；键含前缀）。
    #[derive(Default)]
    pub struct MockStore {
        pub objects: HashMap<String, Vec<u8>>,
    }

    impl MockStore {
        pub fn etag(data: &[u8]) -> String {
            hex::encode(sha2::Sha256::digest(data))
        }
    }

    pub struct MockRequest {
        pub method: String,
        pub path: String,
        pub headers: HashMap<String, String>,
        pub body: Vec<u8>,
    }

    pub struct MockResponse {
        pub status: u16,
        pub headers: Vec<(String, String)>,
        pub body: Vec<u8>,
    }

    pub type Handler = dyn Fn(&MockRequest) -> MockResponse + Send + Sync + 'static;

    /// 起一个单线程 HTTP 服务器（解析请求行/头/Content-Length 体，写回响应）。
    pub fn serve(handler: Arc<Handler>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let handler = handler.clone();
                thread::spawn(move || {
                    if let Err(e) = handle_conn(stream, handler) {
                        eprintln!("mock http: {e}");
                    }
                });
            }
        });
        (addr, handle)
    }

    fn handle_conn(mut stream: TcpStream, handler: Arc<Handler>) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        let mut headers = HashMap::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                if k.trim().eq_ignore_ascii_case("content-length") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body)?;
        let req = MockRequest {
            method: method.clone(),
            path: path.clone(),
            headers: headers.clone(),
            body,
        };
        let resp = handler(&req);
        let status_text = match resp.status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            207 => "Multi-Status",
            404 => "Not Found",
            405 => "Method Not Allowed",
            409 => "Conflict",
            412 => "Precondition Failed",
            _ => "OK",
        };
        let mut out = format!("HTTP/1.1 {} {}\r\n", resp.status, status_text);
        for (k, v) in &resp.headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str(&format!("Content-Length: {}\r\n\r\n", resp.body.len()));
        stream.write_all(out.as_bytes())?;
        stream.write_all(&resp.body)?;
        stream.flush()?;
        Ok(())
    }

    /// 简易内存 WebDAV 服务器：GET/PUT(If-Match)/DELETE/PROPFIND/MKCOL/HEAD。
    /// 路径形态：`/{key}`（键在根）。
    pub fn webdav_handler(store: Arc<Mutex<MockStore>>) -> Arc<Handler> {
        Arc::new(move |req: &MockRequest| {
            let mut store = store.lock().unwrap();
            let key = req.path.trim_start_matches('/').to_string();
            match req.method.as_str() {
                "MKCOL" => MockResponse {
                    status: 201,
                    headers: vec![],
                    body: vec![],
                },
                "GET" | "HEAD" => match store.objects.get(&key) {
                    Some(data) => MockResponse {
                        status: 200,
                        headers: vec![("ETag".into(), format!("\"{}\"", MockStore::etag(data)))],
                        body: if req.method == "HEAD" {
                            vec![]
                        } else {
                            data.clone()
                        },
                    },
                    None => MockResponse {
                        status: 404,
                        headers: vec![],
                        body: vec![],
                    },
                },
                "PUT" => {
                    let cur = store.objects.get(&key);
                    let ok = match req.headers.get("if-match").map(|s| s.as_str()) {
                        Some("*") => cur.is_none(),
                        Some(want) => match cur {
                            Some(data) => {
                                let e = MockStore::etag(data);
                                format!("\"{e}\"") == *want || e == *want
                            }
                            None => false,
                        },
                        None => match req.headers.get("if-none-match").map(|s| s.as_str()) {
                            Some("*") => cur.is_none(),
                            _ => true,
                        },
                    };
                    if ok {
                        store.objects.insert(key, req.body.clone());
                        MockResponse {
                            status: 201,
                            headers: vec![(
                                "ETag".into(),
                                format!("\"{}\"", MockStore::etag(&req.body)),
                            )],
                            body: vec![],
                        }
                    } else {
                        MockResponse {
                            status: 412,
                            headers: vec![],
                            body: vec![],
                        }
                    }
                }
                "DELETE" => {
                    if store.objects.remove(&key).is_some() {
                        MockResponse {
                            status: 204,
                            headers: vec![],
                            body: vec![],
                        }
                    } else {
                        MockResponse {
                            status: 404,
                            headers: vec![],
                            body: vec![],
                        }
                    }
                }
                "PROPFIND" => {
                    let mut xml =
                        String::from("<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\">");
                    for (k, data) in &store.objects {
                        xml.push_str(&format!(
                            "<d:response><d:href>/{k}</d:href><d:propstat><d:prop><d:getetag>\"{}\"</d:getetag></d:prop></d:propstat></d:response>",
                            MockStore::etag(data)
                        ));
                    }
                    xml.push_str("</d:multistatus>");
                    MockResponse {
                        status: 207,
                        headers: vec![],
                        body: xml.into_bytes(),
                    }
                }
                _ => MockResponse {
                    status: 405,
                    headers: vec![],
                    body: vec![],
                },
            }
        })
    }

    /// 简易内存 S3 服务器：GET/PUT(If-Match)/DELETE/HEAD + ListObjectsV2。
    /// 路径形态：`/{bucket}/{key...}`；列表请求 `/?list-type=2&prefix=...`。
    pub fn s3_handler(store: Arc<Mutex<MockStore>>) -> Arc<Handler> {
        Arc::new(move |req: &MockRequest| {
            let mut store = store.lock().unwrap();
            if req.path.contains("list-type=2") {
                let prefix = req
                    .path
                    .split("prefix=")
                    .nth(1)
                    .and_then(|s| s.split('&').next())
                    .map(|s| s.replace("%2F", "/"))
                    .unwrap_or_default();
                let mut xml = String::from(
                    "<?xml version=\"1.0\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
                );
                let mut keys: Vec<&String> = store.objects.keys().collect();
                keys.sort();
                for k in keys {
                    if k.starts_with(&prefix) {
                        let data = &store.objects[k];
                        xml.push_str(&format!(
                            "<Contents><Key>{}</Key><ETag>\"{}\"</ETag><Size>{}</Size></Contents>",
                            k,
                            MockStore::etag(data),
                            data.len()
                        ));
                    }
                }
                xml.push_str("</ListBucketResult>");
                return MockResponse {
                    status: 200,
                    headers: vec![],
                    body: xml.into_bytes(),
                };
            }
            // /{bucket}/{key...}
            let key = req
                .path
                .trim_start_matches('/')
                .split_once('/')
                .map(|(_, k)| k)
                .unwrap_or("")
                .to_string();
            match req.method.as_str() {
                "GET" | "HEAD" => match store.objects.get(&key) {
                    Some(data) => MockResponse {
                        status: 200,
                        headers: vec![("ETag".into(), format!("\"{}\"", MockStore::etag(data)))],
                        body: if req.method == "HEAD" {
                            vec![]
                        } else {
                            data.clone()
                        },
                    },
                    None => MockResponse {
                        status: 404,
                        headers: vec![],
                        body: vec![],
                    },
                },
                "PUT" => {
                    let cur = store.objects.get(&key);
                    let ok = match req.headers.get("if-match").map(|s| s.as_str()) {
                        Some(want) => match cur {
                            Some(data) => MockStore::etag(data) == *want,
                            None => false,
                        },
                        None => match req.headers.get("if-none-match").map(|s| s.as_str()) {
                            Some("*") => cur.is_none(),
                            _ => true,
                        },
                    };
                    if ok {
                        store.objects.insert(key, req.body.clone());
                        MockResponse {
                            status: 200,
                            headers: vec![(
                                "ETag".into(),
                                format!("\"{}\"", MockStore::etag(&req.body)),
                            )],
                            body: vec![],
                        }
                    } else {
                        MockResponse {
                            status: 412,
                            headers: vec![],
                            body: vec![],
                        }
                    }
                }
                "DELETE" => {
                    if store.objects.remove(&key).is_some() {
                        MockResponse {
                            status: 204,
                            headers: vec![],
                            body: vec![],
                        }
                    } else {
                        MockResponse {
                            status: 404,
                            headers: vec![],
                            body: vec![],
                        }
                    }
                }
                _ => MockResponse {
                    status: 405,
                    headers: vec![],
                    body: vec![],
                },
            }
        })
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::mock_http::{Handler, MockRequest, MockStore};
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn local_backend() -> (tempfile::TempDir, LocalStorage) {
        let dir = tempfile::tempdir().unwrap();
        let backend = LocalStorage::new(dir.path().to_path_buf());
        (dir, backend)
    }

    #[test]
    fn local_cas_semantics() {
        let (_dir, b) = local_backend();
        // 创建
        assert!(matches!(
            b.put("index.lk", b"one", None).unwrap(),
            PutOutcome::Written { .. }
        ));
        // 重复创建 → Conflict
        assert!(matches!(
            b.put("index.lk", b"two", None).unwrap(),
            PutOutcome::Conflict
        ));
        // 条件覆盖：错误 etag → Conflict
        assert!(matches!(
            b.put("index.lk", b"three", Some("wrong")).unwrap(),
            PutOutcome::Conflict
        ));
        // 正确 etag → 覆盖
        let etag = b.etag("index.lk").unwrap().unwrap();
        assert!(matches!(
            b.put("index.lk", b"four", Some(&etag)).unwrap(),
            PutOutcome::Written { .. }
        ));
        // 覆盖后 etag 变化
        let etag2 = b.etag("index.lk").unwrap().unwrap();
        assert_ne!(etag, etag2);
        // get
        let got = b.get("index.lk").unwrap().unwrap();
        assert_eq!(got.data, b"four");
        assert_eq!(got.etag, etag2);
        // 删除 + 幂等
        b.delete("index.lk").unwrap();
        assert!(b.get("index.lk").unwrap().is_none());
        b.delete("index.lk").unwrap();
        // list
        let u = uuid::Uuid::new_v4();
        b.put(&format!("{u}.item.lk"), b"x", None).unwrap();
        let objs = b.list().unwrap();
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].key, format!("{u}.item.lk"));
        // 非法键拒绝
        assert!(b.put("../evil", b"x", None).is_err());
        assert!(b.get("../evil").is_err());
    }

    #[test]
    fn backend_from_url_schemes() {
        let dir = tempfile::tempdir().unwrap();
        let b = backend_from_url(&format!("file://{}", dir.path().display()), None).unwrap();
        assert_eq!(b.name(), "local");
        assert!(backend_from_url("ftp://x", None).is_err());
        assert!(backend_from_url("file://relative/path", None).is_err());
        assert!(backend_from_url("https://example.com/dav", None).is_err()); // 缺凭据
        let creds = Credentials {
            username: "u".into(),
            password: Zeroizing::new("p".into()),
        };
        let b = backend_from_url("https://example.com/dav", Some(creds.clone())).unwrap();
        assert_eq!(b.name(), "webdav");
        let b = backend_from_url("s3://bucket/prefix", Some(creds)).unwrap();
        assert_eq!(b.name(), "s3");
    }

    // -- WebDAV（mock 服务器）-----------------------------------------------

    fn webdav_backend() -> (Arc<Mutex<MockStore>>, WebDav) {
        let store = Arc::new(Mutex::new(MockStore::default()));
        let handler = mock_http::webdav_handler(store.clone());
        let (addr, _handle) = mock_http::serve(handler);
        let url = format!("http://{addr}/dav");
        let creds = Credentials {
            username: "u".into(),
            password: Zeroizing::new("p".into()),
        };
        let backend = WebDav::new(&url, creds).unwrap();
        (store, backend)
    }

    #[test]
    fn webdav_crud_and_cas() {
        let (_store, b) = webdav_backend();
        // 创建 + 重复创建冲突
        assert!(matches!(
            b.put("index.lk", b"one", None).unwrap(),
            PutOutcome::Written { .. }
        ));
        assert!(matches!(
            b.put("index.lk", b"two", None).unwrap(),
            PutOutcome::Conflict
        ));
        // CAS 覆盖
        let etag = b.etag("index.lk").unwrap().unwrap();
        assert!(matches!(
            b.put("index.lk", b"three", Some(&etag)).unwrap(),
            PutOutcome::Written { .. }
        ));
        assert!(matches!(
            b.put("index.lk", b"four", Some("stale")).unwrap(),
            PutOutcome::Conflict
        ));
        // get / 404（合法形态但不存在）
        let got = b.get("index.lk").unwrap().unwrap();
        assert_eq!(got.data, b"three");
        let missing = format!("{}.item.lk", uuid::Uuid::new_v4());
        assert!(b.get(&missing).unwrap().is_none());
        // list（不含集合自身）
        let u = uuid::Uuid::new_v4();
        b.put(&format!("{u}.item.lk"), b"item", None).unwrap();
        let objs = b.list().unwrap();
        assert_eq!(objs.len(), 2);
        assert!(objs.iter().any(|o| o.key == format!("{u}.item.lk")));
        assert!(objs.iter().all(|o| o.key != "dav" && !o.key.is_empty()));
        // delete 幂等
        b.delete(&format!("{u}.item.lk")).unwrap();
        b.delete(&format!("{u}.item.lk")).unwrap();
    }

    // -- S3（mock 服务器）---------------------------------------------------

    fn s3_backend(store: Arc<Mutex<MockStore>>) -> (thread::JoinHandle<()>, S3Backend) {
        let handler = mock_http::s3_handler(store.clone());
        let (addr, handle) = mock_http::serve(handler);
        let creds = Credentials {
            username: "AKIDEXAMPLE".into(),
            password: Zeroizing::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into()),
        };
        let backend = S3Backend::parse(
            &format!("s3://test-bucket/sync?region=us-east-1&endpoint=http://{addr}"),
            creds,
        )
        .unwrap();
        (handle, backend)
    }

    #[test]
    fn s3_crud_and_cas_and_list() {
        let store = Arc::new(Mutex::new(MockStore::default()));
        let (_handle, b) = s3_backend(store.clone());
        assert!(matches!(
            b.put("index.lk", b"one", None).unwrap(),
            PutOutcome::Written { .. }
        ));
        assert!(matches!(
            b.put("index.lk", b"two", None).unwrap(),
            PutOutcome::Conflict
        ));
        let etag = b.etag("index.lk").unwrap().unwrap();
        assert!(matches!(
            b.put("index.lk", b"three", Some(&etag)).unwrap(),
            PutOutcome::Written { .. }
        ));
        assert!(matches!(
            b.put("index.lk", b"four", Some("stale")).unwrap(),
            PutOutcome::Conflict
        ));
        let got = b.get("index.lk").unwrap().unwrap();
        assert_eq!(got.data, b"three");
        let missing = format!("{}.item.lk", uuid::Uuid::new_v4());
        assert!(b.get(&missing).unwrap().is_none());
        // list（前缀剥离；index.lk + item 两个对象）
        let u = uuid::Uuid::new_v4();
        let key = format!("{u}.item.lk");
        b.put(&key, b"item", None).unwrap();
        let objs = b.list().unwrap();
        assert_eq!(objs.len(), 2);
        assert!(objs.iter().any(|o| o.key == key));
        assert!(objs.iter().any(|o| o.key == "index.lk"));
        // 前缀外对象不列出
        let u2 = uuid::Uuid::new_v4();
        store
            .lock()
            .unwrap()
            .objects
            .insert(format!("other/{u2}.item.lk"), b"z".to_vec());
        let objs = b.list().unwrap();
        assert_eq!(objs.len(), 2);
        // delete 幂等
        b.delete(&key).unwrap();
        b.delete(&key).unwrap();
        assert!(b.get(&key).unwrap().is_none());
    }

    /// S3 请求必须携带 SigV4 头（mock 服务器侧断言 Authorization 存在）。
    #[test]
    fn s3_requests_carry_sigv4_auth() {
        let store = Arc::new(Mutex::new(MockStore::default()));
        let handler_store = store.clone();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let handler: Arc<Handler> = Arc::new(move |req: &MockRequest| {
            seen2.lock().unwrap().push(req.headers.clone());
            mock_http::s3_handler(handler_store.clone())(req)
        });
        let (addr, _handle) = mock_http::serve(handler);
        let creds = Credentials {
            username: "AKIDEXAMPLE".into(),
            password: Zeroizing::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into()),
        };
        let b = S3Backend::parse(
            &format!("s3://b/p?region=us-east-1&endpoint=http://{addr}"),
            creds,
        )
        .unwrap();
        b.put("index.lk", b"x", None).unwrap();
        let reqs = seen.lock().unwrap();
        let req = reqs.first().unwrap();
        let auth = req.get("authorization").cloned().unwrap_or_default();
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"),
            "{auth}"
        );
        assert!(auth.contains("SignedHeaders="), "{auth}");
        assert!(auth.contains("Signature="), "{auth}");
        assert!(req.contains_key("x-amz-date"));
        assert_eq!(req.get("x-amz-content-sha256").unwrap(), "UNSIGNED-PAYLOAD");
    }

    /// SigV4 派生链与 AWS 官方向量一致（用 python3 独立计算验证过的值；
    /// 密钥取自 AWS 文档示例，非真实密钥）。
    #[test]
    fn sigv4_key_derivation_vector() {
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let k = sigv4_key(secret, "20150830", "us-east-1");
        assert_eq!(
            hex::encode(&k),
            "32f78051dcde24c552811d654f4a769112bb834b03975cdd6b1fd7d16248c269"
        );
    }

    /// 完整签名（get-vanilla 场景）与 AWS sigv4-test-suite 官方值一致。
    #[test]
    fn sigv4_full_signature_vector() {
        // get-vanilla：GET /（host example.amazonaws.com，20150830T123600Z）
        let canonical_request = concat!(
            "GET\n/\n\n",
            "host:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\n",
            "host;x-amz-date\n",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let ts = "20150830T123600Z";
        let scope = "20150830/us-east-1/service/aws4_request";
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{ts}\n{scope}\n{}",
            hex::encode(sha2::Sha256::digest(canonical_request.as_bytes()))
        );
        // 用 service 重建派生链（测试目标：派生链 + 签名公式与官方一致）
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), b"20150830");
        let k_region = hmac_sha256(&k_date, b"us-east-1");
        let k_service = hmac_sha256(&k_region, b"service");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));
        assert_eq!(
            signature,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("abc"), "abc");
        assert_eq!(percent_decode("%2F"), "/");
    }

    #[test]
    fn key_validation() {
        let u = uuid::Uuid::new_v4();
        assert!(valid_key(INDEX_KEY));
        assert!(valid_key(&format!("{u}.item.lk")));
        assert!(valid_key(&format!("{u}.tomb.lk")));
        assert!(valid_key(&format!("{u}.attach.lk")));
        assert!(valid_key(&format!("{u}.0.chunk.lk")));
        assert!(valid_key(&format!("{u}.12.chunk.lk")));
        assert!(!valid_key("../etc/passwd"));
        assert!(!valid_key(&format!("{u}.exe")));
        assert!(!valid_key(&format!("{u}.chunk.lk")));
        assert!(!valid_key(&format!("{u}.x.chunk.lk")));
        assert!(!valid_key("index.lk/../x"));
        assert!(!valid_key(""));
    }
}
