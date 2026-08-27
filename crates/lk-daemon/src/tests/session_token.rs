//! #68 回归：会话令牌文件权限收紧——unix 0600 / Windows 显式 DACL 仅当前
//! 用户（protected，不依赖目录继承）。

use super::*;

/// 建库 + 启动守护 + 解锁（返回数据目录）。
fn unlocked_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut audit = AuditLog::open(dir.path()).unwrap();
        init_vault_with_params(
            dir.path(),
            "pw123456",
            false,
            &mut audit,
            &test_kdf_params(),
        )
        .unwrap();
    }
    let mut daemon = Daemon::start(dir.path()).unwrap();
    let resp = daemon.handle(
        &rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw123456" }),
        ),
        &PeerInfo::unknown(),
    );
    assert!(
        rpc_result(&resp).get("token").is_some(),
        "解锁应成功：{resp}"
    );
    dir
}

#[test]
#[cfg(windows)]
fn session_token_file_user_only_dacl() {
    let dir = unlocked_dir();
    let token_path = dir.path().join(crate::SESSION_TOKEN_FILE);
    assert!(token_path.exists(), "解锁后令牌文件应存在");
    // 当前用户仍可读（守护进程/后续 CLI 进程要复用）
    assert!(std::fs::read_to_string(&token_path).is_ok());
    // 显式 DACL：无继承 ACE（icacls 的 "(I)" 标记），不含 SYSTEM/
    // Administrators 等其他主体——仅当前用户
    let out = std::process::Command::new("icacls")
        .arg(&token_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "icacls 应成功：{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains("(I)"), "不应存在继承 ACE：{text}");
    assert!(
        !text.contains("SYSTEM") && !text.contains("Administrators"),
        "DACL 应仅当前用户：{text}"
    );
}

#[test]
#[cfg(unix)]
fn session_token_file_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = unlocked_dir();
    let token_path = dir.path().join(crate::SESSION_TOKEN_FILE);
    let mode = std::fs::metadata(&token_path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "令牌文件应 0600");
}
