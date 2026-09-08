//! 对端身份面（拍板 #28 候选 4，architecture-deepening.md §5；词汇见根
//! `CONTEXT.md`「对端身份」）：一次 IPC 请求可归属的合成事实——启动者 +
//! canonical 项目目录 + 解析到的可执行文件路径——的**单一解析入口**。
//!
//! #152 把 identity 拆成 peer_env / exe_resolve / binding 三个平铺模块
//! （白盒可测），但「谁在调、从哪调」这个复合体无名无接口——四个门 begin
//! 各自手拼 `derive_starter + canonical_project_dir`，`CallerId` 归因与门内
//! 归因两条路径并立。本模块补上这层门面：唯一接口 [`resolve`]，委托既有
//! 三拆 + core starter（保留为内部缝，不合并不删除）。
//!
//! **对端观测不变量**（architecture-deepening.md §1.8，重构后原样成立）：
//! starter 与 cwd 一律取守护进程侧从 IPC 对端观测的真实值
//! （`resolve_starter(peer.pid)` / `peer.cwd`），客户端自报字段不信任、仅作
//! 提示；跨命名空间归一化（`path_ns::canonical_project_dir`，`wsl://`
//! 规范形）不变。
//!
//! **指纹裁决不并入门面**：它是消费 [`PeerIdentity::exe_path`] 的单独一步
//! （`binding::adjudicate_binding`，需 vault 绑定规则 + `&mut` 指纹缓存，
//! 锁态一体化补裁决在临时 vault 解锁后，issue #140）——保持独立调用，
//! 不吞 #140 单次裁决 gating。desktop 豁免键 = `peer.origin == Desktop`
//! （各门在 resolve 之前自查；注入通道无桌面豁免，identity-binding.md §3）。

use std::path::PathBuf;

use lk_core::path_ns;
use lk_core::starter::{self, UNKNOWN_STARTER};

use crate::peer_env::PeerEnv;
use crate::transport::PeerInfo;

/// 对端身份（CONTEXT.md「对端身份」）：四类授权裁决与审计归因共用的
/// 合成事实。字段为纯数据——一切推导（进程链回溯 / 跨命名空间归一化 /
/// PATH 解析）收敛在 [`resolve`] 单点。
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    /// 启动者（守护进程侧从 `peer.pid` 进程链回溯；失败 →
    /// [`UNKNOWN_STARTER`]，授权门第 1 层 fail-closed）。
    pub starter: String,
    /// canonical 项目目录（跨命名空间归一化，`wsl://` 规范形；对端 cwd
    /// 缺失 → 空串，调用方按 NoCwd fail-closed）。
    pub canonical_cwd: String,
    /// 解析到的可执行文件路径（canonical；`command[0]` 按对端真实 PATH 序
    /// 解析，issue #139 空元素原位映射 cwd）。仅在 [`resolve`] 给出命令串
    /// 时解析（注入门指纹裁决消费；其余门与审计归因恒 `None`）——不可
    /// 解析（env 不可读 / PATH+cwd 未命中 / canonicalize 失败）→ `None`，
    /// 调用方按 fail-closed 处置（绑定规则视同未命中）。
    pub exe_path: Option<PathBuf>,
}

/// 唯一接口：解析对端身份（单点）。
///
/// - `starter`：`peer.pid` → 进程链回溯（pid=0 / 会话不符 / 回溯失败 →
///   `unknown`，第 1 层必拒）；
/// - `canonical_cwd`：`peer.cwd`（daemon 侧观测的 canonical 真实值）→
///   `path_ns::canonical_project_dir` 归一化（`wsl://` 规范形，与
///   `rule.add` 入库基准同一函数、两侧同源）；
/// - `exe_path`：`command` 给出时按对端真实 PATH/PATHEXT（[`PeerEnv`]）
///   解析 `command[0]`（exe_resolve 内部缝）；`None` 命令串不解析
///   （非注入门没有可归属的可执行文件，白盒计数钉住零 env 读取）。
///
/// `command` 仅注入门（`authz.evaluate`）传 `Some`（审批帧的完整命令串）；
/// 读/写/规则门与 `CallerId` 审计归因传 `None`。锁态一体化的指纹补裁决
/// （issue #140）在 finalize 侧**重新调用本函数**——对端 env 按存留的
/// `PeerInfo` 在裁决时刻重读，不复用 begin 期解析产物。
pub fn resolve(peer_env: &dyn PeerEnv, peer: &PeerInfo, command: Option<&str>) -> PeerIdentity {
    PeerIdentity {
        starter: derive_starter(peer),
        canonical_cwd: path_ns::canonical_project_dir(&peer.cwd.clone().unwrap_or_default()),
        exe_path: command.and_then(|cmd| {
            // exe 解析用对端 cwd 原始形态（PATH 空元素原位映射 + 末尾兜底
            // 候选，与既有裁决口径一致）；cwd 缺失时 PATH 候选仍可解析，
            // 其裁决归宿由调用方（第 1 层 NoCwd 已拒，verdict 不消费）。
            let cwd = peer.cwd.clone().unwrap_or_default();
            crate::exe_resolve::resolve_exe_path(peer_env, peer.pid, &cwd, cmd)
        }),
    }
}

/// 启动者判定（守护进程侧，自 daemon/mod.rs 移入）：对端 PID → 进程链
/// 回溯；pid=0 / 会话不符 / 回溯失败 → fail-closed `unknown`（授权门第 1
/// 层拒绝）。客户端自报 starter 一律不信任。
fn derive_starter(peer: &PeerInfo) -> String {
    if peer.pid == 0 || !starter::peer_session_ok(peer.pid) {
        return UNKNOWN_STARTER.to_string();
    }
    starter::resolve_starter(peer.pid, starter::platform_table().as_ref())
}

// 白盒测试：对端观测不变量（§1.8）在门面层钉住——starter/cwd 取 daemon
// 侧观测、跨命名空间归一化、exe 解析委托与零命令零读取。
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::AtomicUsize;

    /// 计数 env（零读取断言用）：固定 PATH，可选 PATHEXT。
    struct CountingPeerEnv {
        path: Option<String>,
        reads: AtomicUsize,
    }
    impl PeerEnv for CountingPeerEnv {
        fn peer_path(&self, _pid: u32) -> Option<String> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.path.clone()
        }
    }

    fn peer(pid: u32, cwd: Option<&str>) -> PeerInfo {
        PeerInfo {
            pid,
            cwd: cwd.map(String::from),
            origin: crate::transport::PeerOrigin::Socket,
        }
    }

    /// §1.8：starter 取 daemon 侧进程链回溯——pid=0（无 IPC 对端可观测）
    /// → `unknown`（第 1 层必拒；客户端无可自报字段绕过：PeerInfo 不携带
    /// starter）。本进程 pid → 真实回溯出非 unknown 启动者。
    #[test]
    fn starter_is_daemon_observed_pid_backtrace() {
        let env = CountingPeerEnv {
            path: None,
            reads: AtomicUsize::new(0),
        };
        assert_eq!(
            resolve(&env, &peer(0, Some("/proj")), None).starter,
            UNKNOWN_STARTER,
            "pid=0 无对端可观测 → unknown（fail-closed）"
        );
        let own = resolve(&env, &peer(std::process::id(), Some("/proj")), None);
        assert_ne!(
            own.starter, UNKNOWN_STARTER,
            "真实进程链回溯应得非 unknown 启动者（got {:?}）",
            own.starter
        );
    }

    /// §1.8：canonical_cwd 跨命名空间归一化不变——`\\wsl.localhost\<distro>\…`
    /// 折算 `wsl://<distro>/…` 规范形（与 rule.add 入库基准同一函数）；
    /// 对端 cwd 缺失 → 空串（调用方 NoCwd fail-closed 的判据数据）。
    #[test]
    fn canonical_cwd_keeps_wsl_normalization() {
        let env = CountingPeerEnv {
            path: None,
            reads: AtomicUsize::new(0),
        };
        let id = resolve(
            &env,
            &peer(7, Some(r"\\wsl.localhost\Ubuntu\home\u\proj")),
            None,
        );
        assert_eq!(id.canonical_cwd, "wsl://Ubuntu/home/u/proj");
        // `$` 别名同形
        let id = resolve(&env, &peer(7, Some(r"\\wsl$\Ubuntu\home\u\proj")), None);
        assert_eq!(id.canonical_cwd, "wsl://Ubuntu/home/u/proj");
        // 常规路径原样（归一化不越权改写）
        let id = resolve(&env, &peer(7, Some("/home/u/proj")), None);
        assert_eq!(id.canonical_cwd, "/home/u/proj");
        // cwd 缺失 → 空串
        assert_eq!(resolve(&env, &peer(7, None), None).canonical_cwd, "");
    }

    /// exe 解析委托 exe_resolve（PATH 序 + canonicalize）；无命令串不解析、
    /// **零 env 读取**（白盒计数钉住：读/写/规则门与审计归因不为 exe 读取
    /// 对端 env）。
    #[test]
    fn exe_path_resolves_via_peer_path_and_skips_without_command() {
        let bin = tempfile::tempdir().unwrap();
        let raw = bin.path().join("tool");
        std::fs::write(&raw, b"fake exe").unwrap();
        let canonical = std::fs::canonicalize(&raw).unwrap();
        let env = CountingPeerEnv {
            path: Some(bin.path().to_string_lossy().into_owned()),
            reads: AtomicUsize::new(0),
        };
        // 有命令串 → PATH 解析出 canonical 候选
        let id = resolve(&env, &peer(9, Some("/proj")), Some("tool deploy"));
        assert_eq!(id.exe_path.as_deref(), Some(canonical.as_path()));
        assert_eq!(
            env.reads.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "命令串给出才读对端 env（一次）"
        );
        // 无命令串 → 不解析、零 env 读取
        let id = resolve(&env, &peer(9, Some("/proj")), None);
        assert_eq!(id.exe_path, None);
        assert_eq!(
            env.reads.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "无命令串不得读对端 env"
        );
        // env 不可读（fail-closed）→ exe_path None（绑定规则视同未命中）
        let unreadable = CountingPeerEnv {
            path: None,
            reads: AtomicUsize::new(0),
        };
        assert_eq!(
            resolve(&unreadable, &peer(9, Some("/proj")), Some("tool")).exe_path,
            None
        );
        // 绝对路径命令免 PATH 解析（lk-core 纯函数语义经门面透传）
        let abs = if cfg!(windows) {
            let p = Path::new(r"C:\Windows\System32\cmd.exe");
            p.is_file().then(|| p.to_path_buf())
        } else {
            Path::new("/bin/sh")
                .is_file()
                .then(|| PathBuf::from("/bin/sh"))
        };
        if let Some(expect) = abs {
            let id = resolve(
                &env,
                &peer(9, Some("/proj")),
                Some(expect.to_string_lossy().as_ref()),
            );
            assert_eq!(
                id.exe_path.as_deref(),
                Some(expect.canonicalize().unwrap().as_path()),
                "绝对路径命令免 PATH 解析，canonicalize 返回"
            );
        }
    }
}
