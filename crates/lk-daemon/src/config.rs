//! C 层 daemon 宿主 · config.json 读写边界（`docs/plugin-architecture.md` §3.3）。
//!
//! - `config.json`：非敏感运行时配置（空闲超时 / 同步 URL / 轮询间隔 /
//!   审批超时），明文原子写（tmp + rename）；CLI `lk config` 与守护进程
//!   热更新共用。
//! - `sync-state.json`：同步运行状态（水位 / 最近摘要 / 风暴等级），
//!   跨重启保留。
//! - 同步凭据（WebDAV/S3）：系统钥匙串（service=`lightkey-sync`），
//!   不进 vault 密文、不进审计明文、不落日志；`file://` 本地模拟无需凭据。
//!
//! 归属分界（`docs/plugin-architecture.md` §9）：敏感加密数据 → Rust vault
//! 落盘；非敏感运行时配置 → 本模块；UI 偏好（含主题） → D 层 preference-store。

use std::path::Path;

/// 配置文件名。
pub const CONFIG_FILE: &str = "config.json";
/// 同步状态文件名（水位 / 最近摘要 / 风暴等级）。
pub const SYNC_STATE_FILE: &str = "sync-state.json";
/// 钥匙串 service 名（凭据 = `{username, password}` JSON；user = 存储 URL）。
const SYNC_KEYRING_SERVICE: &str = "lightkey-sync";

/// 审批超时默认值（第 3 层弹窗 30s 超时默认拒绝；`lk-core::authz` 常量对齐）。
const DEFAULT_APPROVAL_TIMEOUT_SECS: u64 = 30;

/// 守护进程配置（`config.json`）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// 空闲自动锁定分钟数（0 = 下次请求即锁；默认 5）。
    pub auto_lock_minutes: u64,
    /// M1 同步配置（`lk config sync set` 写入；缺省 = 未配置同步）。
    #[serde(default)]
    pub sync: Option<lk_core::sync::SyncConfig>,
    /// M2 审批超时秒数（`authz.evaluate` 第 3 层弹窗等待；超时默认拒绝）。
    /// 缺省 30；测试可调小以缩短等待。
    #[serde(default = "default_approval_timeout_secs")]
    pub approval_timeout_secs: u64,
}

fn default_approval_timeout_secs() -> u64 {
    DEFAULT_APPROVAL_TIMEOUT_SECS
}

impl Default for Config {
    fn default() -> Self {
        Config {
            auto_lock_minutes: 5,
            sync: None,
            approval_timeout_secs: DEFAULT_APPROVAL_TIMEOUT_SECS,
        }
    }
}

/// 同步运行状态（持久化到 `sync-state.json`；风暴等级与摘要跨重启保留）。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncRuntime {
    pub state: lk_core::sync::SyncState,
}

impl SyncRuntime {
    pub fn load(dir: &Path) -> SyncRuntime {
        match std::fs::read(dir.join(SYNC_STATE_FILE)) {
            Ok(bytes) => serde_json::from_slice::<SyncRuntime>(&bytes).unwrap_or_default(),
            Err(_) => SyncRuntime::default(),
        }
    }

    pub fn save(&self, dir: &Path) {
        let path = dir.join(SYNC_STATE_FILE);
        let tmp = path.with_extension("json.tmp");
        if let Ok(bytes) = serde_json::to_vec(&self) {
            if std::fs::write(&tmp, &bytes).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }
}

/// 读配置（守护进程内热更新 / CLI `lk config` 共用）。
pub fn read_config(dir: &Path) -> Config {
    match std::fs::read(dir.join(CONFIG_FILE)) {
        Ok(bytes) => serde_json::from_slice::<Config>(&bytes).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

/// 写配置（原子：tmp + rename）。
pub fn write_config(dir: &Path, config: &Config) -> std::io::Result<()> {
    let path = dir.join(CONFIG_FILE);
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(config).unwrap_or_default())?;
    std::fs::rename(&tmp, &path)
}

/// 存同步凭据到系统钥匙串（service=`lightkey-sync`，user=存储 URL）。
pub fn store_sync_credentials(url: &str, username: &str, password: &str) -> Result<(), String> {
    use zeroize::Zeroizing;
    let json = serde_json::json!({ "username": username, "password": password }).to_string();
    let entry = keyring::Entry::new(SYNC_KEYRING_SERVICE, url)
        .map_err(|e| format!("无法访问系统钥匙串：{e}"))?;
    let _ = Zeroizing::new(json.clone());
    entry
        .set_password(&json)
        .map_err(|e| format!("无法写入系统钥匙串：{e}"))
}

/// 读同步凭据（守护进程轮询/触发时用）。`file://` 无需凭据 → `Ok(None)`。
pub fn load_sync_credentials(url: &str) -> Result<Option<lk_core::storage::Credentials>, String> {
    use zeroize::Zeroizing;
    if url.starts_with("file://") {
        return Ok(None);
    }
    let entry = keyring::Entry::new(SYNC_KEYRING_SERVICE, url)
        .map_err(|e| format!("无法访问系统钥匙串：{e}"))?;
    let json = entry
        .get_password()
        .map_err(|e| format!("钥匙串中无 {url} 的凭据（{e}）；请运行 lk config sync set"))?;
    let v: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| format!("钥匙串凭据格式损坏：{e}"))?;
    let username = v
        .get("username")
        .and_then(|u| u.as_str())
        .ok_or_else(|| "钥匙串凭据缺 username".to_string())?
        .to_string();
    let password = v
        .get("password")
        .and_then(|p| p.as_str())
        .ok_or_else(|| "钥匙串凭据缺 password".to_string())?
        .to_string();
    Ok(Some(lk_core::storage::Credentials {
        username,
        password: Zeroizing::new(password),
    }))
}
