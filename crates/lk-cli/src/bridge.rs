//! `lk bridge`：跨子系统 stdio 中继（规格：`docs/cross-subsystem.md` §7.1/§7.3）。
//!
//! 角色：Windows 侧短命中继进程——stdin 读一帧 JSON-RPC（行 JSON），经本地
//! IPC 传输转发给同机守护实例，把响应行原样写到 stdout 后退出。**一进程
//! 一请求**（与 [`lk_daemon::transport::request`] 同构；首版不做长驻会话）。
//!
//! - **字节纪律**：stdin/stdout 全程按原始字节读写（[`std::io`] 默认即原始
//!   字节流，无任何文本模式转换）。实证 #3（cross-subsystem.md §4）：cmd 文本
//!   模式会损坏 UTF-8 与换行；Rust stdio 无此问题。帧本身必须是合法 JSON
//!   （即合法 UTF-8），非 UTF-8 字节按 `bridge.io` 报错——除此之外不做任何
//!   业务解析，决策权始终在守护进程侧。
//! - **阻塞语义**：`authz.evaluate` 第③层审批在服务端最长等 30s
//!   （`approval_timeout_secs`，默认拒绝）。本进程保持管道打开直到响应到达：
//!   单请求模式下天然成立——写完请求后阻塞读响应，不设更短的客户端超时
//!   （传输层读超时为 300s，远大于审批窗口）。
//! - **版本校验（§7.3）**：转发业务帧之前先发 `vault.status` 探测帧，校验
//!   响应 `version` 与自身 `CARGO_PKG_VERSION` 主.次一致（补丁号忽略）；
//!   不一致或响应缺失（陈旧构建对未知帧静默关闭连接，实证 #7）→
//!   `bridge.version_incompatible` 明确报错，绝不静默降级。
//! - 平台说明：本命令跨平台可用——Windows 上连 named pipe（生产路径，
//!   WSL 桥的目标端）；Linux/macOS 上连 UDS（开发调试用，行为一致）。

use std::io::{BufRead, Write};
use std::path::Path;

use lk_core::ipc::{RpcResponse, M_VAULT_STATUS};
use serde_json::{json, Value};

use crate::transport;

/// bridge 专用错误码（应用段 -320xx 延续；仅出现在 bridge 的 stdout 错误帧）。
pub const ERR_BRIDGE_NO_DAEMON: i64 = -32014;
pub const ERR_BRIDGE_VERSION_INCOMPATIBLE: i64 = -32015;
pub const ERR_BRIDGE_IO: i64 = -32016;

/// 业务失败统一退出码（cli.md §2 约定：0 成功 / 1 业务失败 / 2 用法错误）。
const EXIT_FAILURE: i32 = 1;

/// 版本校验（§7.3）：主.次一致（补丁号忽略）；任一侧缺失/不可解析 → 不兼容
/// （fail-closed，绝不静默降级）。
pub fn version_compatible(local: &str, remote: Option<&str>) -> bool {
    let Some(remote) = remote else {
        return false;
    };
    match (major_minor(local), major_minor(remote)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// 解析 "x.y.z" → (x, y)；解析失败返回 None。
fn major_minor(v: &str) -> Option<(u64, u64)> {
    let mut it = v.trim().split('.');
    let maj = it.next()?.trim().parse::<u64>().ok()?;
    let min = it.next()?.trim().parse::<u64>().ok()?;
    Some((maj, min))
}

/// 向 stdout 写单行 JSON-RPC error 帧（错误语义：stdout 单行 + 非零退出码）。
pub fn emit_error(out: &mut impl Write, id: Value, code: i64, message: &str, detail: &str) {
    let resp = RpcResponse::err(
        id,
        code,
        message,
        if detail.is_empty() {
            None
        } else {
            Some(json!({ "detail": detail }))
        },
    );
    let _ = writeln!(
        out,
        "{}",
        serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into())
    );
    let _ = out.flush();
}

/// `lk bridge` 入口：stdin 原始字节 → 守护进程 → stdout 原始字节 → 退出。
pub fn cmd_bridge(out: &mut impl Write, dir: &Path) -> i32 {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    relay_once(dir, &mut input, out)
}

/// 单次中继（可测试核心）：探测端点 → 版本校验 → 读一帧 → 转发 → 写响应行。
fn relay_once(dir: &Path, input: &mut impl BufRead, out: &mut impl Write) -> i32 {
    // ① 端点发现：daemon.json 缺失 → bridge.no_daemon（不自动拉起守护进程：
    // bridge 是被 WSL 侧按需拉起的中继，守护实例由桌面应用持有）
    let Some(ep) = transport::read_endpoint(dir) else {
        emit_error(
            out,
            Value::Null,
            ERR_BRIDGE_NO_DAEMON,
            "bridge.no_daemon",
            "缺少 daemon.json（桌面应用未运行？）",
        );
        return EXIT_FAILURE;
    };

    // ② 版本校验（§7.3）：vault.status 无需令牌，锁态也可响应。
    let probe = json!({ "jsonrpc": "2.0", "id": 0, "method": M_VAULT_STATUS, "params": {} });
    let self_version = env!("CARGO_PKG_VERSION");
    match transport::request(&ep, &probe.to_string()) {
        Err(e) => {
            // 连接失败 → 管道不可达；写入后对端关闭（EOF/RST）→ 陈旧构建的
            // 已知症状（实证 #7：静默关闭零响应），归入版本不兼容而非静默失败。
            if matches!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
            ) {
                version_fail(out);
            } else {
                emit_error(
                    out,
                    Value::Null,
                    ERR_BRIDGE_NO_DAEMON,
                    "bridge.no_daemon",
                    &format!("管道不可达：{e}"),
                );
            }
            return EXIT_FAILURE;
        }
        Ok(line) => {
            let remote = serde_json::from_str::<RpcResponse>(&line)
                .ok()
                .and_then(|r| r.result)
                .and_then(|v| v["version"].as_str().map(str::to_string));
            if !version_compatible(self_version, remote.as_deref()) {
                version_fail(out);
                return EXIT_FAILURE;
            }
            let shown = remote.unwrap_or_default();
            eprintln!("→ 经 bridge 连接 Windows 桌面守护实例（版本 {shown}）");
        }
    }

    // ③ 读业务帧（原始字节，到 \n 为止；无帧 = 无事可做，正常退出）
    let mut frame = Vec::new();
    match input.read_until(b'\n', &mut frame) {
        Ok(0) => return 0,
        Ok(_) => {}
        Err(e) => {
            emit_error(
                out,
                Value::Null,
                ERR_BRIDGE_IO,
                "bridge.io",
                &format!("{e}"),
            );
            return EXIT_FAILURE;
        }
    }
    if frame.last() == Some(&b'\n') {
        frame.pop();
    }
    let frame = match String::from_utf8(frame) {
        Ok(s) => s,
        Err(_) => {
            emit_error(
                out,
                Value::Null,
                ERR_BRIDGE_IO,
                "bridge.io",
                "请求帧不是合法 UTF-8（JSON-RPC 帧必须为 UTF-8）",
            );
            return EXIT_FAILURE;
        }
    };
    if frame.trim().is_empty() {
        return 0;
    }

    // ④ 转发并原样回写响应行。此处阻塞读直到响应到达（第③层审批窗口最长
    // 30s < 传输层 300s 读超时）；单请求模式进程存活期即管道存活期。
    match transport::request(&ep, &frame) {
        Ok(resp_line) => {
            // 原样写字节 + 行结束符；不做任何再序列化（透传保真）
            let _ = out.write_all(resp_line.as_bytes());
            let _ = out.write_all(b"\n");
            let _ = out.flush();
            0
        }
        Err(e) => {
            emit_error(
                out,
                Value::Null,
                ERR_BRIDGE_IO,
                "bridge.io",
                &format!("中继 I/O 失败：{e}"),
            );
            EXIT_FAILURE
        }
    }
}

fn version_fail(out: &mut impl Write) {
    emit_error(
        out,
        Value::Null,
        ERR_BRIDGE_VERSION_INCOMPATIBLE,
        "bridge.version_incompatible",
        &format!(
            "桌面应用协议版本与本 CLI（{}）主.次不一致或过旧，请重装 LightKey 桌面应用",
            env!("CARGO_PKG_VERSION")
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[cfg(unix)]
    use std::sync::atomic::AtomicBool;
    #[cfg(unix)]
    use std::sync::Arc;

    #[cfg(unix)]
    static SHUTDOWN: AtomicBool = AtomicBool::new(false);

    /// 进程内 mock 守护实例：vault.status 回带指定版本；其余帧原样回显
    /// （透传保真检查用）。
    #[cfg(unix)]
    fn spawn_mock_daemon(dir: &Path, status_version: Option<&str>) {
        let listener = transport::bind_server(dir).expect("bind mock server");
        let version = status_version.map(str::to_string);
        let handler: transport::Handler = Arc::new(move |line, _peer| {
            let v: Value = serde_json::from_str(line).unwrap_or(Value::Null);
            let id = v.get("id").cloned().unwrap_or(Value::Null);
            if v.get("method").and_then(|m| m.as_str()) == Some(M_VAULT_STATUS) {
                return serde_json::to_string(&RpcResponse::ok(
                    id,
                    match &version {
                        Some(ver) => json!({ "unlocked": false, "version": ver }),
                        None => json!({ "unlocked": false }),
                    },
                ))
                .unwrap();
            }
            // 回显：逐字节一致的响应行
            line.to_string()
        });
        std::thread::spawn(move || {
            let _ = transport::serve(listener, handler, None, &SHUTDOWN);
        });
    }

    #[cfg(unix)]
    fn run_relay(dir: &Path, frames: &[u8]) -> (i32, Vec<u8>) {
        let mut out = Vec::new();
        let mut input = Cursor::new(frames.to_vec());
        let code = relay_once(dir, &mut input, &mut out);
        (code, out)
    }

    #[test]
    fn version_check_three_states() {
        // 一致（补丁号忽略）
        assert!(version_compatible("0.2.3", Some("0.2.9")));
        assert!(version_compatible("0.2.0", Some("0.2.0")));
        assert!(version_compatible(
            env!("CARGO_PKG_VERSION"),
            Some(env!("CARGO_PKG_VERSION"))
        ));
        // 主.次不符
        assert!(!version_compatible("0.2.0", Some("0.3.0")));
        assert!(!version_compatible("1.0.0", Some("0.1.0")));
        // 缺 version 字段 / 不可解析
        assert!(!version_compatible("0.1.0", None));
        assert!(!version_compatible("0.1.0", Some("")));
        assert!(!version_compatible("0.1.0", Some("abc")));
        // 自身版本异常也 fail-closed
        assert!(!version_compatible("weird", Some("0.1.0")));
    }

    #[test]
    fn no_daemon_json_yields_no_daemon_error() {
        let tmp = tempfile::tempdir().unwrap();
        let mut out = Vec::new();
        let mut input = Cursor::new(b"{\"jsonrpc\":\"2.0\"}\n".to_vec());
        let code = relay_once(tmp.path(), &mut input, &mut out);
        assert_eq!(code, 1);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("bridge.no_daemon"), "got: {text}");
        assert_eq!(text.lines().count(), 1, "stdout 必须是单行 JSON-RPC error");
    }

    #[cfg(unix)]
    #[test]
    fn version_mismatch_is_rejected_not_silent() {
        let tmp = tempfile::tempdir().unwrap();
        spawn_mock_daemon(tmp.path(), Some("9.9.9"));
        let (code, out) = run_relay(tmp.path(), b"{}\n");
        assert_eq!(code, 1);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("bridge.version_incompatible"), "got: {text}");
    }

    #[cfg(unix)]
    #[test]
    fn missing_version_field_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        spawn_mock_daemon(tmp.path(), None);
        let (code, out) = run_relay(tmp.path(), b"{}\n");
        assert_eq!(code, 1);
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("bridge.version_incompatible"));
    }

    #[cfg(unix)]
    #[test]
    fn stale_build_silent_close_maps_to_version_incompatible() {
        // 实证 #7：陈旧构建对探测帧静默关闭零响应。模拟：指向一个无人监听但
        // daemon.json 存在的端点且连接立即 EOF —— 用一个立即关闭的 UDS 监听器。
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("run")).unwrap();
        let listener =
            std::os::unix::net::UnixListener::bind(tmp.path().join("run/x.sock")).unwrap();
        std::thread::spawn(move || {
            // 接受后立即丢弃连接（不读写）
            for stream in listener.incoming() {
                drop(stream);
            }
        });
        let bytes = serde_json::to_vec(&json!({
            "pid": std::process::id(),
            "address": tmp.path().join("run/x.sock").to_string_lossy(),
        }))
        .unwrap();
        std::fs::write(tmp.path().join("daemon.json"), bytes).unwrap();
        let (code, out) = run_relay(tmp.path(), b"{}\n");
        assert_eq!(code, 1);
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("bridge.version_incompatible"),
            "静默关闭必须映射为版本不兼容"
        );
    }

    #[cfg(unix)]
    #[test]
    fn frame_passthrough_byte_fidelity() {
        let tmp = tempfile::tempdir().unwrap();
        spawn_mock_daemon(tmp.path(), Some(env!("CARGO_PKG_VERSION")));
        // 多字节 UTF-8、空格、转义——mock 回显原帧，要求逐字节往返一致
        let frame = "{\"params\":{\"note\":\"中文密钥✓\",\"pad\":\"  spaced  \"}}";
        let (code, out) = run_relay(tmp.path(), format!("{frame}\n").as_bytes());
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8(out).unwrap(), format!("{frame}\n"));
    }

    #[cfg(unix)]
    #[test]
    fn empty_stdin_is_clean_exit() {
        let tmp = tempfile::tempdir().unwrap();
        spawn_mock_daemon(tmp.path(), Some(env!("CARGO_PKG_VERSION")));
        let (code, out) = run_relay(tmp.path(), b"");
        assert_eq!(code, 0);
        assert!(out.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_frame_is_io_error() {
        let tmp = tempfile::tempdir().unwrap();
        spawn_mock_daemon(tmp.path(), Some(env!("CARGO_PKG_VERSION")));
        let (code, out) = run_relay(tmp.path(), &[0xff, 0xfe, b'\n']);
        assert_eq!(code, 1);
        assert!(String::from_utf8(out).unwrap().contains("bridge.io"));
    }
}
