//! `command[0]` → canonical 候选解析 + 内存指纹缓存（M2.98，identity-binding.md
//! §5.1/§6；identity 三拆之一，issue #152）：
//!
//! 1. **可执行解析**：按 PATH 序 + 对端真实 cwd 兜底解析（绝对路径免解析），
//!    canonicalize 得绝对路径（[`resolve_exe_path`]）；
//! 2. **指纹缓存**：stat → 元信息快照（一致复用 = O(stat)）→ 流式 SHA-256
//!    （[`FingerprintCache`]）。**缓存不落盘**（落盘可被同用户进程投毒成
//!    「自己二进制」的哈希——正是要防的冒充）。
//!
//! 解析逻辑做成纯函数 / 可注入 trait（单测：注入假 env / 假文件源做确定性
//! 断言）。姊妹模块：[`crate::peer_env`]（对端环境读取）、
//! [`crate::binding`]（绑定裁决）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use lk_core::fingerprint;
use lk_core::Result;

use crate::peer_env::PeerEnv;

// ---------------------------------------------------------------------------
// 1. 可执行解析（§5.1；只解析路径，不触碰文件内容）
// ---------------------------------------------------------------------------

/// 解析 Windows PATHEXT（`;` 分隔，形如 `.COM;.EXE;.BAT;.CMD`）：每项规范化
/// （去空白、补前导 `.`、去空项）后返回；输入为空/纯分隔符 → 空表。纯函数，
/// 跨平台可测（生产仅 Windows 使用——对端 env 无 PATHEXT 时由调用方按平台
/// 缺省处理，见 [`pathext_extensions`]）。大小写保留（Windows FS 大小写不
/// 敏感，探测与比对不受影响）。
pub fn parse_pathext(pathext: &str) -> Vec<String> {
    pathext
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s.starts_with('.') {
                s.to_string()
            } else {
                format!(".{s}")
            }
        })
        .collect()
}

/// PATH 字符串 → 目录序列（issue #139）：**空元素按 POSIX `execvp` 语义原位
/// 映射为对端 cwd**（不过滤、不丢序）——POSIX `execvp`（Rust `Command::new`
/// 对裸命令名的 Unix 语义）把空 PATH 元素视为当前位置 cwd，且位于其所在位置。
/// 解析序必须与子进程实际 exec 序一致：此前实现过滤空元素，导致
/// `PATH=":/usr/bin"`（空首元素，POSIX 惯例写法）+ cwd 同名假程序场景下，
/// daemon 解析到 `/usr/bin` 真程序（指纹命中 → Allowed），而子进程实际执行
/// cwd 假程序——指纹门被「PATH 前置假程序」绕过。Windows 上裸名解析语义
/// 不同（CreateProcess 搜索序），按 spec 权威（identity-binding.md §5.1）
/// 统一实现 POSIX 语义——空元素 → cwd 候选在解析序中前移只会更 fail-closed。
/// 纯函数，跨平台可测。
pub fn parse_path_dirs(path_str: &str, sep: char, cwd: &Path) -> Vec<PathBuf> {
    path_str
        .split(sep)
        .map(|s| {
            if s.is_empty() {
                cwd.to_path_buf()
            } else {
                PathBuf::from(s)
            }
        })
        .collect()
}

/// 解析 `command[0]` → canonical 绝对候选路径：
///
/// - 从对端真实 env 取 PATH（不可读 → fail-closed）；绝对命令免 PATH 解析；
/// - 按 PATH 序 `resolve_exe`（第一个命中即是候选，入参可执行性谓词 =
///   is_file）+ 对端真实 cwd 兜底；空元素原位映射为 cwd（POSIX execvp 语义，
///   [`parse_path_dirs`]，issue #139）；
/// - canonicalize 得绝对路径（相对候选解析符号链接）。
///
/// 返回 `None` 表示无法解析（env/cwd 缺失、候选不存在、canonical 失败）→
/// 调用方按 fail-closed（绑定规则视同未命中，见 §5.1）。
///
/// **注意**：本函数只做路径解析（不 stat/不哈希），使调用方可以先把路径与
/// 规则比对（§5.2 第 1 步，免其余 IO）。
pub fn resolve_exe_path(
    peer_env: &dyn PeerEnv,
    pid: u32,
    cwd: &str,
    command: &str,
) -> Option<PathBuf> {
    // 对端真实 env PATH（客户端自报不信任）；不可读 → fail-closed
    let path_str = peer_env.peer_path(pid)?;
    #[cfg(windows)]
    let sep = ';';
    #[cfg(not(windows))]
    let sep = ':';
    // 空元素原位映射 cwd（POSIX execvp 语义，issue #139）：解析序与子进程
    // 实际 exec 序一致；cwd 兜底候选仍由 resolve_exe 追加在末尾（PATH 全
    // 未命中时的既有 fail-closed 行为零变化；重复候选无害——取首个命中）。
    let path_dirs: Vec<PathBuf> = parse_path_dirs(&path_str, sep, Path::new(cwd));
    // resolve_exe 内置 `cwd` 兜底（PATH 全未命中时的最后一个候选）
    // issue #133：Windows 无扩展名命令（`npm`/`git`/`npx`…）按对端 PATHEXT
    // 逐后缀探测（见 [`pathext_extensions`]），解析结果 = 带后缀的真实文件；
    // 非 Windows 无后缀表 = 探测空、行为与 #132 前完全一致。
    let exts = pathext_extensions(peer_env, pid);
    let ext_refs: Vec<&str> = exts.iter().map(String::as_str).collect();
    let resolved = fingerprint::resolve_exe(command, &path_dirs, Path::new(cwd), &ext_refs, |p| {
        p.is_file()
    })?;
    std::fs::canonicalize(&resolved).ok()
}

/// 本次解析用的可执行后缀表（issue #133）：对端真实 PATHEXT 解析结果；对端
/// 未设置/读取失败 → Windows 平台缺省（cmd 缺省 PATHEXT 序，
/// [`lk_core::fingerprint::EXEC_EXTENSIONS`]），非 Windows 为空表（不探测后缀，
/// 行为与 #132 前完全一致）。
fn pathext_extensions(peer_env: &dyn PeerEnv, pid: u32) -> Vec<String> {
    match peer_env.peer_pathext(pid) {
        Some(p) => parse_pathext(&p),
        None => default_pathext_extensions(),
    }
}

fn default_pathext_extensions() -> Vec<String> {
    #[cfg(windows)]
    {
        lk_core::fingerprint::EXEC_EXTENSIONS
            .iter()
            .map(|s| s.to_string())
            .collect()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// 2. 指纹缓存（§6：内存 + 元信息失效，不落盘）
// ---------------------------------------------------------------------------

/// 文件元信息快照（**只做失效提示，不作安全依据**——安全依据始终是 SHA-256）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaSnapshot {
    pub size: u64,
    /// 修改时间（unix 纪元纳秒；跨平台归一化）。
    pub mtime_nanos: u64,
    /// 文件索引号（unix inode / Windows file index；平台不可得 → 0）。
    pub file_id: u64,
}

/// 文件源抽象（缓存评估先 stat；hash 流式重算）。注入假实现做确定性单测。
pub trait FingerprintSource: Send + Sync {
    /// stat → 元信息快照（文件不存在 / 不可读 → `None`）。
    fn stat(&self, path: &Path) -> Option<MetaSnapshot>;
    /// 流式 SHA-256（hex 小写；1 MiB 块，不高驻全量）。
    fn hash(&self, path: &Path) -> Result<String>;
}

/// 真实文件系统源。
#[derive(Default)]
pub struct FsFingerprintSource;

impl FingerprintSource for FsFingerprintSource {
    fn stat(&self, path: &Path) -> Option<MetaSnapshot> {
        let meta = std::fs::metadata(path).ok()?;
        Some(snapshot_from_meta(&meta))
    }
    fn hash(&self, path: &Path) -> Result<String> {
        fingerprint::file_sha256(path)
    }
}

/// 平台无关：`std::fs::Metadata` → [`MetaSnapshot`]。
pub(crate) fn snapshot_from_meta(meta: &std::fs::Metadata) -> MetaSnapshot {
    let mtime_nanos = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let file_id = file_index(meta);
    MetaSnapshot {
        size: meta.len(),
        mtime_nanos,
        file_id,
    }
}

/// 平台文件索引号（unix inode / Windows file index；不可得 → 0）。
#[cfg(unix)]
fn file_index(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}

#[cfg(windows)]
fn file_index(_meta: &std::fs::Metadata) -> u64 {
    // Windows `MetadataExt::file_index` 为 unstable API——本平台遥控返回 0
    // （元信息失效由 size+mtime 承担；file_id 只是失效提示、不作安全依据）。
    0
}

/// 内存指纹缓存条目（daemon 进程内；**不落盘**，§6-1）。
struct CacheEntry {
    meta: MetaSnapshot,
    sha256: String,
}

/// 指纹预计算阈值缺省值（64 MiB，identity-binding.md §6-2）：只决定**预计算
/// （缓存预热）时机**，不改变安全语义——缓存本身总是按需计算。≤ 阈值：规则
/// 创建/审批 finalize 时立即预热（[`crate::binding::recompute_fingerprint`]
/// 走缓存写入）；超过阈值：惰性到首次命中（固化哈希仍现算，缓存不预热）。
/// config.json 经 `fingerprintPrecomputeThresholdBytes` 覆盖（本常量为 serde
/// 缺省出处，见 `config.rs`）。
pub const FINGERPRINT_PRECOMPUTE_THRESHOLD: u64 = 64 * 1024 * 1024;

/// 内存指纹缓存：`exe_path → {sha256, size, mtime, file-id}`。调用方先 `stat`
/// 拿 meta（§5.2 第 2 步），再 `sha256` 复用/重算：
///
/// - `stat` 只做元信息取样计数（`stat_calls`）；
/// - `sha256(path, meta)`：`meta` 与快照一致 → 复用缓存哈希（O(stat)）；不一致
///   或冷态 → 流式全量重算（1 MiB 块）并更新快照（`hash_calls` 计数）。
///
/// 白盒计数器（stat/hash 次数）属**本缓存模块自身的观测面**（issue #152）：
/// 读取入口仅测试构建可见（`#[cfg(test)]`），宿主公共面（`Daemon`）不暴露
/// 测试钩子。
pub struct FingerprintCache {
    source: Box<dyn FingerprintSource>,
    entries: HashMap<PathBuf, CacheEntry>,
    /// stat 取样计数（测试断言「元信息一致复用 → 只 stat 不重算」）。
    stat_calls: std::sync::atomic::AtomicU64,
    /// 哈希重算计数（测试断言）。用于失配展示的摘要读取也计为 hash_calls。
    hash_calls: std::sync::atomic::AtomicU64,
}

impl FingerprintCache {
    /// 以真实文件系统源构造。
    pub fn new() -> FingerprintCache {
        FingerprintCache::with_source(Box::new(FsFingerprintSource))
    }

    /// 注入文件源（测试用；生产走真实文件系统）。
    pub fn with_source(source: Box<dyn FingerprintSource>) -> FingerprintCache {
        FingerprintCache {
            source,
            entries: HashMap::new(),
            stat_calls: std::sync::atomic::AtomicU64::new(0),
            hash_calls: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl Default for FingerprintCache {
    fn default() -> Self {
        Self::new()
    }
}

impl FingerprintCache {
    /// stat 取样 → 元信息快照（文件不存在 / 不可读 → `None` → 调用方 fail-closed）。
    /// 每次调用计数 `stat_calls`。
    pub fn stat(&mut self, path: &Path) -> Option<MetaSnapshot> {
        let meta = self.source.stat(path)?;
        self.stat_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(meta)
    }

    /// 取 `path` 的 SHA-256：传入调用方已 stat 到的 `meta`；若快照元信息与之一致
    /// → 复用缓存哈希（**不重算**）；不一致/冷态 → 流式全量重算并更新快照。
    /// 读取失败 → `None`（调用方 fail-closed）。重算计数 `hash_calls`。
    pub fn sha256(&mut self, path: &Path, meta: MetaSnapshot) -> Option<String> {
        if let Some(e) = self.entries.get(path) {
            if e.meta == meta {
                // 元信息一致 → O(stat) 复用（与文件大小无关）
                return Some(e.sha256.clone());
            }
        }
        let sha256 = self.source.hash(path).ok()?;
        self.hash_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.entries.insert(
            path.to_path_buf(),
            CacheEntry {
                meta,
                sha256: sha256.clone(),
            },
        );
        Some(sha256)
    }

    /// 现算哈希但**不写缓存**（§6-2 > 阈值惰性分支）：固化落盘所需的哈希
    /// 仍现算，缓存保持冷态——首次命中重新全量哈希。读取失败 → `None`。
    /// 重算计数 `hash_calls`。（crate 内绑定裁决模块 [`crate::binding`] 的
    /// 惰性固化路径使用。）
    pub(crate) fn hash_uncached(&mut self, path: &Path) -> Option<String> {
        let sha256 = self.source.hash(path).ok()?;
        self.hash_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(sha256)
    }

    /// 取 `path` 的 8 位 SHA-256 前缀摘要（失配展示用）。内部先 stat（计
    /// `stat_calls`）再 `sha256`（元信息一致即复用）。文件不可读 → `None`。
    pub(crate) fn resolve_sha256_short(&mut self, path: &Path) -> Option<String> {
        let meta = self.source.stat(path)?;
        self.stat_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let sha = if let Some(e) = self.entries.get(path) {
            if e.meta == meta {
                e.sha256.clone()
            } else {
                self.rehash(path, meta)?
            }
        } else {
            self.rehash(path, meta)?
        };
        Some(sha.chars().take(8).collect())
    }

    fn rehash(&mut self, path: &Path, meta: MetaSnapshot) -> Option<String> {
        let sha256 = self.hash_uncached(path)?;
        self.entries.insert(
            path.to_path_buf(),
            CacheEntry {
                meta,
                sha256: sha256.clone(),
            },
        );
        Some(sha256)
    }

    /// stat 取样次数（本模块观测面，仅测试构建；issue #152）。
    #[cfg(test)]
    pub(crate) fn stat_calls(&self) -> u64 {
        self.stat_calls.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 哈希重算次数（本模块观测面，仅测试构建；issue #152）。
    #[cfg(test)]
    pub(crate) fn hash_calls(&self) -> u64 {
        self.hash_calls.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_env::tests::FakePeerEnv;

    /// 假文件源：元信息 + 确定性哈希（测试缓存复用/失效）。
    #[derive(Clone)]
    struct FakeSource {
        meta: MetaSnapshot,
        sha: String,
    }
    impl FingerprintSource for FakeSource {
        fn stat(&self, _path: &Path) -> Option<MetaSnapshot> {
            Some(self.meta)
        }
        fn hash(&self, _path: &Path) -> Result<String> {
            Ok(self.sha.clone())
        }
    }

    fn sha64(c: char) -> String {
        c.to_string().repeat(64)
    }

    /// parse_pathext（issue #133）：PATHEXT `;` 分隔后缀表的解析与规范化。
    #[test]
    fn parse_pathext_normalizes_extension_list() {
        assert_eq!(
            parse_pathext(".COM;.EXE;.BAT;.CMD"),
            vec![".COM", ".EXE", ".BAT", ".CMD"]
        );
        // 去空白 / 补前导点 / 去空项；大小写保留（FS 大小写不敏感）
        assert_eq!(
            parse_pathext(" EXE ;cmd;;.vbs;"),
            vec![".EXE", ".cmd", ".vbs"]
        );
        assert_eq!(parse_pathext("exe;.cmd"), vec![".exe", ".cmd"]);
        // 空 / 纯分隔符 → 空表（不探测任何后缀）
        assert_eq!(parse_pathext(""), Vec::<String>::new());
        assert_eq!(parse_pathext(";; ;"), Vec::<String>::new());
    }

    /// resolve_exe_path 按对端 PATHEXT 逐后缀解析（issue #133 核心路径）：
    /// 命令 "npm publish" → command[0] "npm" 无扩展名 → 无后缀字面候选不存在
    /// → 按 PATHEXT ".EXE;.CMD" 探测到 `<bin>\npm.cmd` → canonicalize 返回
    /// 真实文件路径（含后缀）。用真实临时文件 + 注入假对端 env（PATH+PATHEXT），
    /// 跨平台可跑（Windows 形态在任意 OS 上由假 env 注入复现）。
    #[test]
    fn resolve_exe_path_probes_peer_pathext_extensions() {
        let bin = tempfile::tempdir().unwrap();
        let raw = bin.path().join("npm.cmd");
        std::fs::write(&raw, b"@echo off\r\nset FOO=bar\r\n").unwrap();
        let canonical = std::fs::canonicalize(&raw).unwrap();

        // 带 PATHEXT：无扩展名命令 → 探测到 npm.cmd（大小写敏感 FS 上用同形后缀
        // 复现顺序探测机制；真实 Windows FS 大小写不敏感，大写 `.CMD` 同样
        // 命中小写 `npm.cmd`）
        let env = FakePeerEnv {
            path: Some(bin.path().to_string_lossy().into_owned()),
            pathext: Some(".EXE;.cmd".into()),
        };
        let got = resolve_exe_path(&env, 1, "/proj", "npm publish")
            .expect("PATHEXT 探测应解析出 npm.cmd");
        assert_eq!(got, canonical, "解析结果应为带后缀的真实文件路径");

        // 控制组：对端 PATHEXT 读取失败/未设置 → **平台缺省语义**（issue #133
        // 缺省回落）：Windows 回落 cmd 缺省表（.COM;.EXE;.BAT;.CMD）→ 仍
        // 探测到 npm.cmd；非 Windows 不探测后缀 → 无扩展名命令不可解析
        // （fail-closed 审批）。
        let env2 = FakePeerEnv {
            path: Some(bin.path().to_string_lossy().into_owned()),
            pathext: None,
        };
        #[cfg(windows)]
        assert_eq!(
            resolve_exe_path(&env2, 1, "/proj", "npm publish"),
            Some(canonical),
            "Windows 缺省 PATHEXT 回落应仍解析出 npm.cmd"
        );
        #[cfg(not(windows))]
        assert_eq!(
            resolve_exe_path(&env2, 1, "/proj", "npm publish"),
            None,
            "无 PATHEXT 时无扩展名命令不可解析（fail-closed 审批）"
        );
    }

    /// PATH 解析（issue #139）：空 PATH 元素按 POSIX `execvp` 语义**原位映射
    /// 为对端 cwd**（不过滤、不丢序）——`PATH=":/usr/bin"` → `[cwd, /usr/bin]`；
    /// 中部/末尾空元素同理。解析序必须与子进程实际 exec 序一致，否则「指纹
    /// 比对命中的程序」与「实际被执行的程序」可分叉（PATH 前置假程序绕过）。
    #[test]
    fn parse_path_dirs_maps_empty_elements_to_cwd_in_place() {
        let cwd = Path::new("/proj");
        // 首位空元素（POSIX 惯例 `PATH=":/usr/bin"`）→ cwd 原位在前
        let got = parse_path_dirs(":/usr/bin", ':', cwd);
        let names: Vec<String> = got
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["/proj".to_string(), "/usr/bin".to_string()]);
        // 中部空元素 → cwd 原位居中
        let got = parse_path_dirs("/a::/b", ':', cwd);
        let names: Vec<String> = got
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["/a".to_string(), "/proj".to_string(), "/b".to_string()]
        );
        // 末尾空元素 → cwd 原位在后
        let got = parse_path_dirs("/a:", ':', cwd);
        let names: Vec<String> = got
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["/a".to_string(), "/proj".to_string()]);
        // 多重空元素 → 每个空位各自映射 cwd（`"::"` 切出 3 个空段）
        let got = parse_path_dirs("::", ':', cwd);
        let names: Vec<String> = got
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                "/proj".to_string(),
                "/proj".to_string(),
                "/proj".to_string()
            ]
        );
        // 无空元素 → 原样（零变化）
        let got = parse_path_dirs("/a:/b", ':', cwd);
        let names: Vec<String> = got
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["/a".to_string(), "/b".to_string()]);
    }

    /// issue #139 主场景（fail-closed 语义钉死）：`PATH=":<真实程序目录>"` +
    /// cwd 含同名假程序 + 另一目录含真实程序。解析必须**先命中 cwd 假程序**
    /// （与 execvp 实际执行序一致）→ 与绑定 `/…real…` 的规则路径不符 → 失配；
    /// 修复前空元素被过滤 → 解析到真实程序 → 指纹命中 → Allowed（绕过）。
    #[test]
    fn resolve_exe_path_empty_leading_element_resolves_cwd_fake_first() {
        let cwd_dir = tempfile::tempdir().unwrap();
        let real_dir = tempfile::tempdir().unwrap();
        let fake = cwd_dir.path().join("npm");
        let real = real_dir.path().join("npm");
        std::fs::write(&fake, b"fake").unwrap();
        std::fs::write(&real, b"real binary").unwrap();
        let fake_canonical = std::fs::canonicalize(&fake).unwrap();
        let sep = if cfg!(windows) { ';' } else { ':' };
        let env = FakePeerEnv {
            path: Some(format!(
                "{}{}{}",
                "",
                sep,
                real_dir.path().to_string_lossy()
            )),
            pathext: None,
        };
        let got = resolve_exe_path(
            &env,
            1,
            cwd_dir.path().to_string_lossy().as_ref(),
            "npm publish",
        )
        .expect("cwd 假程序应被解析为候选（与 execvp 序一致）");
        assert_eq!(
            got, fake_canonical,
            "空首元素必须原位映射 cwd：解析序 = 实际 exec 序"
        );
    }

    /// issue #139 控制组：空**尾**元素（`PATH="<真实目录>:"`）时真实程序在
    /// cwd 之前，仍解析到真实程序（序不变）；真实目录未命中才轮到 cwd。
    #[test]
    fn resolve_exe_path_trailing_empty_element_keeps_path_order() {
        let cwd_dir = tempfile::tempdir().unwrap();
        let real_dir = tempfile::tempdir().unwrap();
        std::fs::write(cwd_dir.path().join("npm"), b"fake").unwrap();
        let real = real_dir.path().join("npm");
        std::fs::write(&real, b"real binary").unwrap();
        let real_canonical = std::fs::canonicalize(&real).unwrap();
        let sep = if cfg!(windows) { ';' } else { ':' };
        let env = FakePeerEnv {
            path: Some(format!(
                "{}{}{}",
                real_dir.path().to_string_lossy(),
                sep,
                ""
            )),
            pathext: None,
        };
        let got = resolve_exe_path(
            &env,
            1,
            cwd_dir.path().to_string_lossy().as_ref(),
            "npm publish",
        )
        .expect("真实程序应命中");
        assert_eq!(got, real_canonical, "PATH 序不被空尾元素打乱");
    }

    /// 元信息一致 → 复用缓存哈希：同路径两次 `stat`+`sha256`，第二次只 stat
    /// （stat_calls=2）不重算（hash_calls=1），且哈希正确返回。
    #[test]
    fn cache_reuses_when_meta_unchanged() {
        let mut cache = FingerprintCache::with_source(Box::new(FakeSource {
            meta: MetaSnapshot {
                size: 100,
                mtime_nanos: 42,
                file_id: 7,
            },
            sha: sha64('a'),
        }));
        let p = PathBuf::from("/bin/node");
        let m1 = cache.stat(&p).unwrap();
        assert_eq!(cache.sha256(&p, m1), Some(sha64('a')));
        let m2 = cache.stat(&p).unwrap();
        assert_eq!(cache.sha256(&p, m2), Some(sha64('a')));
        assert_eq!(cache.hash_calls(), 1, "元信息一致应复用，不重算");
        assert_eq!(cache.stat_calls(), 2, "每次评估先 stat");
    }

    /// 内容改 + mtime/file-id 变 → 重算（hash_calls 增）+ 新哈希。
    #[test]
    fn cache_recomputes_when_meta_changes() {
        let mut cache = FingerprintCache::with_source(Box::new(FakeSource {
            meta: MetaSnapshot {
                size: 100,
                mtime_nanos: 1,
                file_id: 1,
            },
            sha: sha64('a'),
        }));
        let p = PathBuf::from("/bin/node");
        let m1 = cache.stat(&p).unwrap();
        assert_eq!(cache.sha256(&p, m1).unwrap(), sha64('a'));
        // 内容改（同 size）+ mtime 变 → 重算为新哈希
        cache.source = Box::new(FakeSource {
            meta: MetaSnapshot {
                size: 100,
                mtime_nanos: 2,
                file_id: 1,
            },
            sha: sha64('b'),
        });
        let m2 = cache.stat(&p).unwrap();
        assert_eq!(cache.sha256(&p, m2).unwrap(), sha64('b'));
        assert_eq!(cache.hash_calls(), 2, "mtime 变应触发重算");
    }
}
