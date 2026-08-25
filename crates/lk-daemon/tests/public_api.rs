//! 回归测试 #55：`lk_daemon::EmbeddedDaemon` 必须是外部可命名的公共类型。
//!
//! 拆分（PR #54）后该别名落在 `daemon::lifecycle` 模块内，lib.rs 未再导出，
//! 导致 `lk_daemon::EmbeddedDaemon` 从 crate 外部不可命名（公共 API 静默破坏）。
//! 本测试以独立 crate（集成测试）身份引用该路径，作为编译期契约：路径解析
//! 失败即编译失败（红色），导出后可通过（绿色）。

/// 以类型标注引用公共路径，确认其从 crate 外部可解析（编译期断言）。
#[test]
fn embedded_daemon_is_public() {
    let _: Option<lk_daemon::EmbeddedDaemon> = None;
}
