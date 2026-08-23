//! Linux `lk` 传输后端选择（规格：`docs/cross-subsystem.md` §7.2）。
//!
//! `rpc()` 的后端二选一：
//!
//! - **local**（现状）：UDS 直连本机守护实例，行为完全不变；
//! - **bridge**：经 `lk.exe bridge`（跨子系统 stdio 中继，见 [`crate::bridge`]）
//!   连接 Windows 桌面守护实例。
//!
//! 配置解析优先级（§7.2 裁定）：
//!
//! 1. 显式环境变量 `LIGHTKEY_BRIDGE`：
//!    - `off` → 强制本地（逃生口）；
//!    - `<路径>` → 强制以该 exe 作中继，跳过探测（Windows 路径 `C:\...`
//!      或 WSL 形式 `/mnt/c/...` 均可）；
//! 2. 平台默认：非 WSL → 本地；WSL → 自动探测 bridge：
//!    - `/proc/sys/fs/binfmt_misc/WSLInterop` 存在，**且**能从
//!      `/mnt/<盘>/Users/<用户>/AppData/Roaming/lightkey/daemon.json` 所在的
//!      Windows 数据目录附近找到 lk.exe（已知安装位置清单
//!      [`KNOWN_EXE_DIRS`]，含 `%LOCALAPPDATA%\LightKey\`）。
//!
//! **探测失败分型（防「空库错觉」）**：
//!
//! - Windows 侧装了 LightKey（有数据目录）但 bridge 不可用（lk.exe 缺失 /
//!   interop 被禁用）→ [`Decision::Fatal`] 明确报错，**绝不静默回落本地**；
//! - Windows 侧没有 lightkey 数据目录 → 静默走本地（本来就没得连）。
//!
//! 可测试性：判定核心 [`decide_with`] 只吃注入输入（文件系统探测点全部由
//! 调用方提供），生产入口 [`decide`] 负责 /mnt 扫描与 /proc 探测后喂给它。

// 非 Linux 主机不走探测路径（decide() 恒 Local），但保留同一套可测试核心
// 与纯函数以便跨平台复用/审查——抑制死代码告警。
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::{Path, PathBuf};

/// bridge 目标（全部为 WSL 侧可用的路径形态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeTarget {
    /// lk.exe 的可执行路径（用于 interop spawn）。
    pub exe: PathBuf,
    /// Windows 侧 lightkey 数据目录（WSL 视图；读 session.token 用）。
    /// 强制路径且无法定位数据目录时为 None（此时仅解锁类命令可用，
    /// 见模块文档；建议配合 `LIGHTKEY_BRIDGE_HOME` 显式指定）。
    pub data_dir: Option<PathBuf>,
    /// 传给 `lk.exe bridge --dir` 的参数（Windows 路径形态）；None = 让
    /// bridge 用其默认解析（%APPDATA%\lightkey）。
    pub dir_arg: Option<String>,
}

/// 后端判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// 本地 UDS 守护实例（含强制 off / 非 WSL 默认 / WSL 未安装静默回落）。
    Local,
    /// 经 bridge 中继到 Windows 桌面守护实例。
    Bridge(BridgeTarget),
    /// Windows 侧装了但连不上——明确报错，绝不静默回落本地。
    Fatal(String),
}

/// 文件系统探测注入点（测试直接构造本结构；生产由 [`decide`] 填充）。
#[derive(Debug, Clone, Default)]
pub struct DetectInput<'a> {
    /// `LIGHTKEY_BRIDGE` 环境变量原值。
    pub bridge_env: Option<&'a str>,
    /// `LIGHTKEY_BRIDGE_HOME` 环境变量原值（显式数据目录，跳过扫描）。
    pub home_env: Option<&'a str>,
    /// 是否运行在 WSL（osrelease 含 microsoft/wsl）。
    pub is_wsl: bool,
    /// interop 是否可用（binfmt WSLInterop 存在）。
    pub interop_enabled: bool,
    /// 自动探测产物：Windows 侧已安装的 LightKey（有数据目录）。
    pub found: Option<FoundInstall>,
}

/// 探测到的 Windows 侧安装。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundInstall {
    /// Windows 用户主目录（`/mnt/<盘>/Users/<用户>`）。
    pub user_home: PathBuf,
    /// lightkey 数据目录（含 daemon.json）。
    pub data_dir: PathBuf,
    /// 找到的 lk.exe（None = 已知位置都没有 → Fatal 分型）。
    pub exe: Option<PathBuf>,
}

/// lk.exe 已知安装位置（相对 Windows 用户主目录；正斜杠形式，按序尝试）。
/// `%LOCALAPPDATA%\LightKey\` 为桌面包捆绑 CLI 的落地目录（规格 §9 条目 6）。
pub const KNOWN_EXE_DIRS: [&str; 3] = [
    "AppData/Local/LightKey",
    "AppData/Local/Programs/LightKey", // Tauri NSIS per-user 默认目录
    "AppData/Roaming/LightKey",
];

const EXE_NAME: &str = "lk.exe";

/// 判定核心（纯逻辑；文件系统事实全部来自注入输入）。
pub fn decide_with(input: DetectInput<'_>) -> Decision {
    // ① 显式环境变量优先
    if let Some(raw) = input.bridge_env.map(str::trim).filter(|s| !s.is_empty()) {
        if raw.eq_ignore_ascii_case("off") {
            return Decision::Local;
        }
        // <路径>：强制以该 exe 作中继，跳过探测。Windows 路径或 /mnt 形式均可。
        let exe = to_wsl_path(raw).unwrap_or_else(|| PathBuf::from(raw));
        // 数据目录：LIGHTKEY_BRIDGE_HOME 显式 > 探测产物（尽力而为）
        let data_dir = match input.home_env.map(str::trim).filter(|s| !s.is_empty()) {
            Some(h) => Some(to_wsl_path(h).unwrap_or_else(|| PathBuf::from(h))),
            None => input.found.map(|f| f.data_dir),
        };
        let dir_arg = data_dir.as_ref().and_then(|p| to_windows_path(p));
        return Decision::Bridge(BridgeTarget {
            exe,
            data_dir,
            dir_arg,
        });
    }

    // ② 平台默认：非 WSL（Linux 原生/macOS）无跨子系统概念 → 本地
    if !input.is_wsl {
        return Decision::Local;
    }

    // ③ WSL 自动探测。LIGHTKEY_BRIDGE_HOME 显式指定数据目录时视为「装了」。
    if let Some(h) = input.home_env.map(str::trim).filter(|s| !s.is_empty()) {
        let data_dir = to_wsl_path(h).unwrap_or_else(|| PathBuf::from(h));
        let user_home = data_dir
            .ancestors()
            .nth(3)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/mnt"));
        let install = FoundInstall {
            user_home: user_home.clone(),
            data_dir,
            exe: find_exe_near(&user_home),
        };
        return decide_installed(&install, input.interop_enabled);
    }

    match input.found {
        // 没装：静默走本地（本来就没得连）
        None => Decision::Local,
        Some(install) => decide_installed(&install, input.interop_enabled),
    }
}

/// 「装了但连不上」分型：interop 禁用 / lk.exe 缺失 → 明确报错。
fn decide_installed(install: &FoundInstall, interop_enabled: bool) -> Decision {
    if !interop_enabled {
        return Decision::Fatal(
            "检测到 Windows 侧已安装 LightKey（找到数据目录），但 WSLInterop 已被禁用 \
             （/proc/sys/fs/binfmt_misc/WSLInterop 不存在），无法经 bridge 连接桌面守护实例。\
             请在 /etc/wsl.conf 启用 interop 或设置 LIGHTKEY_BRIDGE=off 回退本地。"
                .to_string(),
        );
    }
    match &install.exe {
        Some(exe) => {
            let dir_arg = to_windows_path(&install.data_dir);
            Decision::Bridge(BridgeTarget {
                exe: exe.clone(),
                data_dir: Some(install.data_dir.clone()),
                dir_arg,
            })
        }
        None => Decision::Fatal(
            "检测到 Windows 侧已安装 LightKey（找到数据目录），但已知安装位置均未找到 \
             lk.exe，无法经 bridge 连接桌面守护实例。请重装桌面应用，或用 \
             LIGHTKEY_BRIDGE=<路径> 显式指定 lk.exe。绝不静默回退本地（防误操作真库）。"
                .to_string(),
        ),
    }
}

// ---------------------------------------------------------------------------
// 生产探测实现（Linux 专属；其他平台恒 Local）
// ---------------------------------------------------------------------------

/// 生产入口：读环境变量 + 真实文件系统探测后判定。
pub fn decide() -> Decision {
    #[cfg(target_os = "linux")]
    {
        let bridge_env = std::env::var("LIGHTKEY_BRIDGE").ok();
        let home_env = std::env::var("LIGHTKEY_BRIDGE_HOME").ok();
        let found = find_windows_install(Path::new("/mnt"));
        decide_with(DetectInput {
            bridge_env: bridge_env.as_deref(),
            home_env: home_env.as_deref(),
            is_wsl: detect_wsl(osrelease()),
            interop_enabled: interop_available(),
            found,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Windows/macOS 原生主机：无跨子系统桥概念（bridge 子命令本身仍可用）
        Decision::Local
    }
}

/// WSL 判定：osrelease 含 microsoft / wsl（大小写不敏感）。注意与 interop
/// 可用性解耦——企业策略禁用 interop 时仍要能给出「装了但不可用」的明确报错。
pub fn detect_wsl(osrelease: Option<String>) -> bool {
    osrelease
        .map(|r| {
            let r = r.to_ascii_lowercase();
            r.contains("microsoft") || r.contains("wsl")
        })
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn osrelease() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()
}

#[cfg(target_os = "linux")]
fn interop_available() -> bool {
    Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
}

/// 扫描 `/mnt/*` 下各 Windows 用户主目录，找第一个装有 lightkey 数据目录
/// （`AppData/Roaming/lightkey/daemon.json` 存在）的用户，并在其附近找
/// lk.exe。`mnt_root` 参数化以便测试注入临时目录树。
pub fn find_windows_install(mnt_root: &Path) -> Option<FoundInstall> {
    for drive in read_sorted_dirs(mnt_root) {
        let users = drive.join("Users");
        for user in read_sorted_dirs(&users) {
            let data_dir = user.join("AppData/Roaming/lightkey");
            if !data_dir.join("daemon.json").is_file() {
                continue;
            }
            return Some(
                FoundInstall {
                    user_home: user,
                    data_dir,
                    exe: None, // 由 find_exe_near 填充
                }
                .with_exe(),
            );
        }
    }
    None
}

impl FoundInstall {
    fn with_exe(mut self) -> FoundInstall {
        self.exe = find_exe_near(&self.user_home);
        self
    }
}

/// 在用户主目录下的已知安装位置找 lk.exe。
pub fn find_exe_near(user_home: &Path) -> Option<PathBuf> {
    KNOWN_EXE_DIRS
        .iter()
        .map(|d| user_home.join(d).join(EXE_NAME))
        .find(|p| p.is_file())
}

fn read_sorted_dirs(root: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(root) else {
        return vec![];
    };
    let mut v: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    v.sort();
    v
}

// ---------------------------------------------------------------------------
// 路径形态转换（Windows ↔ WSL /mnt 形式；纯函数，测试覆盖）
// ---------------------------------------------------------------------------

/// `C:\Users\a\lk.exe` → `/mnt/c/Users/a/lk.exe`。已是 `/` 开头则原样返回
/// （调用方按 WSL 路径处理）。无法识别盘符 → None。
pub fn to_wsl_path(win: &str) -> Option<PathBuf> {
    let s = win.trim();
    if s.starts_with('/') {
        return Some(PathBuf::from(s));
    }
    // 剥离 verbatim/UNC 前缀的宽松处理：只支持常见盘符形态 `X:\...` / `X:/...`
    let bytes = s.as_bytes();
    if bytes.len() < 2 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return None;
    }
    let drive = (bytes[0] as char).to_ascii_lowercase();
    let rest = s[2..].replace('\\', "/");
    let rest = rest.trim_start_matches('/');
    if rest.is_empty() {
        Some(PathBuf::from(format!("/mnt/{drive}")))
    } else {
        Some(PathBuf::from(format!("/mnt/{drive}/{rest}")))
    }
}

/// `/mnt/c/Users/a/lk.exe` → `C:\Users\a\lk.exe`。非 /mnt/<盘> 形式 → None。
pub fn to_windows_path(p: &Path) -> Option<String> {
    let s = p.to_str()?;
    let mut it = s.trim_start_matches('/').splitn(3, '/');
    if it.next()? != "mnt" {
        return None;
    }
    // 第二段必须是单盘符字母（防把 /mnt/wsl 等误判为盘）
    let drive = it.next()?;
    let mut chars = drive.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) if c.is_ascii_alphabetic() => {}
        _ => return None,
    }
    let d0 = drive.chars().next().unwrap().to_ascii_uppercase();
    match it.next() {
        Some(rest) => Some(format!("{d0}:\\{}", rest.replace('/', "\\"))),
        None => Some(format!("{d0}:\\")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> DetectInput<'static> {
        DetectInput {
            bridge_env: None,
            home_env: None,
            is_wsl: true,
            interop_enabled: true,
            found: None,
        }
    }

    fn installed(exe: bool) -> FoundInstall {
        FoundInstall {
            user_home: PathBuf::from("/mnt/c/Users/alice"),
            data_dir: PathBuf::from("/mnt/c/Users/alice/AppData/Roaming/lightkey"),
            exe: exe.then(|| PathBuf::from("/mnt/c/Users/alice/AppData/Local/LightKey/lk.exe")),
        }
    }

    #[test]
    fn explicit_off_forces_local_even_if_installed() {
        let mut i = input();
        i.bridge_env = Some("off");
        i.found = Some(installed(true));
        assert_eq!(decide_with(i), Decision::Local);
    }

    #[test]
    fn explicit_path_skips_probing_and_accepts_both_forms() {
        let mut i = input();
        i.bridge_env = Some(r"C:\Tools\lk.exe");
        let d = decide_with(i);
        let Decision::Bridge(t) = d else {
            panic!("应为 Bridge");
        };
        assert_eq!(t.exe, PathBuf::from("/mnt/c/Tools/lk.exe"));

        let mut j = input();
        j.bridge_env = Some("/opt/lk.exe");
        let Decision::Bridge(t) = decide_with(j) else {
            panic!("应为 Bridge");
        };
        assert_eq!(t.exe, PathBuf::from("/opt/lk.exe"));
    }

    #[test]
    fn explicit_path_uses_home_env_for_data_dir() {
        let mut i = input();
        i.bridge_env = Some("/mnt/d/Custom/lk.exe");
        i.home_env = Some(r"D:\MyData\lightkey");
        let Decision::Bridge(t) = decide_with(i) else {
            panic!("应为 Bridge");
        };
        assert_eq!(
            t.data_dir.as_deref(),
            Some(Path::new("/mnt/d/MyData/lightkey"))
        );
        assert_eq!(t.dir_arg.as_deref(), Some(r"D:\MyData\lightkey"));
    }

    #[test]
    fn non_wsl_defaults_local() {
        let mut i = input();
        i.is_wsl = false;
        assert_eq!(decide_with(i), Decision::Local);
    }

    #[test]
    fn wsl_without_install_falls_back_silently() {
        assert_eq!(decide_with(input()), Decision::Local);
    }

    #[test]
    fn wsl_installed_reachable_yields_bridge_target() {
        let mut i = input();
        i.found = Some(installed(true));
        let Decision::Bridge(t) = decide_with(i) else {
            panic!("应为 Bridge");
        };
        assert_eq!(
            t.exe,
            PathBuf::from("/mnt/c/Users/alice/AppData/Local/LightKey/lk.exe")
        );
        assert_eq!(
            t.data_dir.as_deref(),
            Some(Path::new("/mnt/c/Users/alice/AppData/Roaming/lightkey"))
        );
        assert_eq!(
            t.dir_arg.as_deref(),
            Some(r"C:\Users\alice\AppData\Roaming\lightkey")
        );
    }

    #[test]
    fn wsl_installed_but_exe_missing_is_fatal_not_silent() {
        let mut i = input();
        i.found = Some(installed(false));
        assert!(matches!(decide_with(i), Decision::Fatal(_)));
    }

    #[test]
    fn wsl_installed_but_interop_disabled_is_fatal() {
        let mut i = input();
        i.interop_enabled = false;
        i.found = Some(installed(true));
        assert!(matches!(decide_with(i), Decision::Fatal(_)));
    }

    /// `LIGHTKEY_BRIDGE_HOME` 显式指定即视为「装了」（跳过安装扫描）——即使
    /// KNOWN_EXE_DIRS 找不到 lk.exe 也 fail-closed 明确报错，绝不静默回落本地
    /// （防空库错觉）。纯逻辑、无文件系统依赖：合成路径两侧均不存在，断言确定。
    /// 真实 fs 集成（找到 exe → Bridge）见下方 `#[cfg(unix)]` 用例。
    #[test]
    fn home_env_counts_as_installed_fail_closed_without_exe() {
        let mut i = input();
        i.home_env = Some("/mnt/c/Users/lk-probe-nonexistent/AppData/Roaming/lightkey");
        assert!(
            matches!(decide_with(i), Decision::Fatal(_)),
            "home_env 显式指定后 exe 缺失应 Fatal，而非静默本地"
        );
    }

    /// 真实 WSL `/mnt/<盘>` 命名空间探测（home_env → 推导 user_home →
    /// `find_exe_near` 找到 lk.exe → Bridge）：依赖 POSIX 绝对路径与真实
    /// 文件树，Windows 原生无 `/mnt` 命名空间且 `to_wsl_path` 会把 `C:\…`
    /// 折算为不存在的虚拟路径——unix-only（与 bridge.rs 同类门控一致）。
    #[cfg(unix)]
    #[test]
    fn home_env_counts_as_installed_and_searches_exe() {
        let tmp = tempfile::tempdir().unwrap();
        // 用户主目录 = tmp/AppData 的上三层 —— 直接构造 Roaming 结构
        let user_home = tmp.path().join("c/Users/bob");
        let data_dir = user_home.join("AppData/Roaming/lightkey");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join("daemon.json"), b"{}").unwrap();
        let exe_dir = user_home.join("AppData/Local/LightKey");
        std::fs::create_dir_all(&exe_dir).unwrap();
        std::fs::write(exe_dir.join("lk.exe"), b"MZ").unwrap();

        let mut i = input();
        i.home_env = Some(data_dir.to_str().unwrap());
        let Decision::Bridge(t) = decide_with(i) else {
            panic!("应为 Bridge");
        };
        assert_eq!(t.data_dir.as_deref(), Some(data_dir.as_path()));
        assert_eq!(t.exe, exe_dir.join("lk.exe"));
    }

    #[test]
    fn scanner_finds_first_user_with_daemon_json() {
        let tmp = tempfile::tempdir().unwrap();
        let mnt = tmp.path().join("mnt");
        // 盘 C 有两个用户，bob 装了；盘 D 无 Users
        let bob_data = mnt.join("c/Users/bob/AppData/Roaming/lightkey");
        std::fs::create_dir_all(&bob_data).unwrap();
        std::fs::write(bob_data.join("daemon.json"), b"{}").unwrap();
        std::fs::create_dir_all(mnt.join("c/Users/alice")).unwrap();
        std::fs::create_dir_all(mnt.join("d/tmp")).unwrap();

        let found = find_windows_install(&mnt).expect("应找到 bob");
        assert_eq!(found.user_home, mnt.join("c/Users/bob"));
        assert_eq!(found.data_dir, bob_data);
        assert_eq!(found.exe, None); // 未放 lk.exe

        // 放入 exe 后能找到
        let exe_dir = mnt.join("c/Users/bob/AppData/Local/Programs/LightKey");
        std::fs::create_dir_all(&exe_dir).unwrap();
        std::fs::write(exe_dir.join("lk.exe"), b"MZ").unwrap();
        let found = find_windows_install(&mnt).unwrap();
        assert_eq!(found.exe, Some(exe_dir.join("lk.exe")));

        // 全空 → None（静默本地分支）
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(find_windows_install(empty.path()), None);
    }

    #[test]
    fn wsl_detection_via_osrelease() {
        assert!(detect_wsl(Some(
            "5.15.153.1-microsoft-standard-WSL2".into()
        )));
        assert!(detect_wsl(Some("4.19.128-microsoft-standard".into())));
        assert!(!detect_wsl(Some("6.8.0-45-generic".into())));
        assert!(!detect_wsl(None));
    }

    #[test]
    fn path_conversion_roundtrip() {
        assert_eq!(
            to_wsl_path(r"C:\Users\a b\lk.exe"),
            Some(PathBuf::from("/mnt/c/Users/a b/lk.exe"))
        );
        assert_eq!(to_wsl_path(r"D:\"), Some(PathBuf::from("/mnt/d")));
        assert_eq!(to_wsl_path("relative/lk.exe"), None);
        assert_eq!(
            to_windows_path(Path::new("/mnt/c/Users/a/lk.exe")),
            Some(r"C:\Users\a\lk.exe".to_string())
        );
        assert_eq!(
            to_windows_path(Path::new("/mnt/e/data")),
            Some(r"E:\data".to_string())
        );
        assert_eq!(to_windows_path(Path::new("/home/u/x")), None);
        // 往返一致
        let win = r"C:\Users\x\AppData\Roaming\lightkey";
        assert_eq!(
            to_windows_path(&to_wsl_path(win).unwrap()).as_deref(),
            Some(win)
        );
    }
}
