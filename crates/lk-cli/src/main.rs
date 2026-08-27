//! LightKey 命令行工具（`lk`）。
//!
//! 命令树与完整语义见 `docs/cli.md`。M0 已实现：
//!
//! - 库生命周期：`lk init` / `lk unlock` / `lk lock` / `lk status` / `lk recover`
//! - 条目（四类 v2）：`lk item list/get/add/edit/delete/copy/export`
//! - 审计：`lk audit`（只读；`--verify` 校验 HMAC 链）
//! - 守护进程：`lk daemon`（持解锁态，密钥仅内存；客户端自动拉起）
//!
//! M1 已实现：`lk sync`（触发一轮：轮询 + CAS 上传）、`lk config sync set`
//! （配置 BYO 存储与轮询间隔；凭据交互式输入不回显，或
//! `--credentials-file` / `--stdin` 导入，存系统钥匙串）、`lk config get`。
//! M2 命令（rule/inject）保持占位（退出码 2）。
//!
//! M2 已实现：授权门（`lk rule add|list|remove`、`lk inject`）。M2.75 新增
//! 跨子系统桥（cross-subsystem.md §7）：`lk bridge`（stdio 中继）与 Linux 侧
//! 传输抽象（local / bridge 后端选择，见 `bridge_backend`）。
//!
//! 约定：
//! - 退出码 0 成功 / 1 业务失败（拒绝/超时/冲突）/ 2 用法错误或未实现。
//! - 敏感输入（主密码/恢复码）不回显（TTY 用 rpassword，脚本用 --stdin）。
//! - 所有命令经守护进程执行（自动拉起）；会话令牌由守护进程签发，
//!   经 0600 文件在进程间传递（锁定即删除）。
//! - 错误信息不区分「未解锁/令牌错」（ipc.md §3 语义）。

mod bridge;
mod bridge_backend;
mod client;
mod clipboard;

use lk_daemon as daemon;
use lk_daemon::dirs;
use lk_daemon::transport;

use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use client::{RpcClient, RpcError};
use lk_core::ipc::{M_AUTHZ_EVALUATE, M_RULE_ADD, M_RULE_LIST, M_RULE_REMOVE};
use lk_core::model::ItemDraft;
use serde_json::{json, Value};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "lk",
    version = VERSION,
    about = "轻钥 LightKey 命令行工具",
    long_about = "轻钥 LightKey：个人密钥 / 私密信息管理工具（零知识，单机闭环 M0）。\n\
                  所有命令经本地守护进程执行（自动拉起，密钥仅存守护进程内存）。"
)]
struct Cli {
    /// 数据目录（默认：$LIGHTKEY_HOME 或平台用户数据目录）
    #[arg(long, global = true)]
    dir: Option<PathBuf>,
    /// 机器可读 JSON 输出（最小字段）
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 初始化一个新库（设置主密码、生成恢复码【仅展示一次】与恢复信封）
    Init {
        /// 已存在库时强制重置（旧数据不可恢复，需二次确认）
        #[arg(long)]
        force: bool,
        /// 主密码从 stdin 读取（脚本用；交互式默认不回显）
        #[arg(long)]
        stdin: bool,
    },
    /// 解锁库（连接守护进程，签发会话令牌）
    Unlock {
        /// 主密码从 stdin 读取（脚本用）
        #[arg(long)]
        stdin: bool,
    },
    /// 锁定库（擦除内存密钥，失效令牌）
    Lock,
    /// 显示解锁态、同步水位、版本
    Status,
    /// 恢复：恢复码 + 新主密码（重置主密码，数据保留）
    Recover(Box<RecoverArgs>),
    /// 条目管理（增删改查、复制、附件导出）
    Item(Box<ItemArgs>),
    /// 查看审计日志（只读；无密钥值）
    Audit {
        /// 最近 N 条
        #[arg(long)]
        tail: Option<usize>,
        /// 校验审计 HMAC 链（需解锁）
        #[arg(long)]
        verify: bool,
    },
    /// 以守护进程方式常驻（持解锁态，密钥仅存内存；由客户端自动拉起）
    Daemon,
    /// 触发一次同步（轮询 + CAS 上传）【M1】
    Sync,
    /// Agent 授权门规则管理（add / list / remove）【M2】
    Rule(Box<RuleArgs>),
    /// 给具名命令注入被批准的环境变量【M2】
    Inject(Box<InjectArgs>),
    /// 读写本地配置【M1】
    Config(Box<ConfigArgs>),
    /// 跨子系统 stdio 中继：stdin 一帧 JSON-RPC → 守护实例 → stdout 响应行
    /// （一进程一请求；WSL 桥的 Windows 侧端点，cross-subsystem.md §7.1）
    /// 【M2.75】
    Bridge,
}

/// `lk config` 参数。
#[derive(clap::Args)]
struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

/// `lk config` 子命令。
#[derive(Subcommand)]
enum ConfigCommand {
    /// 配置 BYO 存储同步（WebDAV / S3）
    Sync {
        #[command(subcommand)]
        command: ConfigSyncCommand,
    },
    /// 读取配置（sync.url / sync.interval / sync.enabled / autoLockMinutes）
    Get { key: String },
}

/// `lk config sync` 子命令。
#[derive(Subcommand)]
enum ConfigSyncCommand {
    /// 设置 BYO 存储 URL 与轮询间隔；凭据交互式输入（不回显），
    /// 也可 --credentials-file / --stdin 导入；不接受凭据明文位置参数
    Set {
        /// 存储 URL：https://host/dav（WebDAV）/ s3://bucket/prefix（S3）
        /// / file:///abs/path（本地模拟，无需凭据）
        url: String,
        /// 轮询间隔秒数（15~3600，默认 60）
        #[arg(long)]
        interval: Option<u64>,
        /// 凭据从文件读取（第一行用户名，第二行密码）
        #[arg(long)]
        credentials_file: Option<PathBuf>,
        /// 凭据从 stdin 读取（第一行用户名，第二行密码；脚本用）
        #[arg(long)]
        stdin: bool,
    },
}

/// `lk rule` 参数。
#[derive(clap::Args)]
struct RuleArgs {
    #[command(subcommand)]
    command: RuleCommand,
}

/// `lk rule` 子命令（cli.md §4；决策 #6：规则含 name）。
#[derive(Subcommand)]
enum RuleCommand {
    /// 新增白名单规则（入库加密；projectDir 规范化后入库）
    Add {
        /// 项目目录（规范化绝对路径；须存在。以 / 开头且非现存本机路径时
        /// 按 WSL 默认发行版解析为 wsl://… 并回显确认）
        project_dir: String,
        /// 具名命令（可 glob，如 "npm *"；含空格需引号）
        command: String,
        /// 规则名（如 publish）
        #[arg(long)]
        name: String,
        /// 授权注入的 key 名（1~32 个；值不可见、名可指名）
        keys: Vec<String>,
    },
    /// 列出规则（最小字段）
    List,
    /// 删除规则（软删除，删除随同步传播）
    Remove { id: String },
}

/// `lk inject` 参数（决策 #1 A：`--keys` 指名，值不可见）。
#[derive(clap::Args)]
struct InjectArgs {
    /// 请求注入的 key 名（agent 已知名字，只是不知道值；须为 secret 类型
    /// 条目的名称——login/note/file 条目不支持注入，与不存在同样拒绝）
    #[arg(long, num_args = 1.., value_name = "NAME")]
    keys: Vec<String>,
    /// 注入 env 后执行的命令（`--` 之后）
    #[arg(last = true, required = true, value_name = "CMD")]
    command: Vec<String>,
}

/// `lk recover` 参数。
#[derive(clap::Args)]
struct RecoverArgs {
    /// 恢复码（不传则交互式输入）
    #[arg(long)]
    code: Option<String>,
    /// 新主密码从 stdin 读取（脚本用）
    #[arg(long)]
    stdin: bool,
}

/// `lk item` 参数。
#[derive(clap::Args)]
struct ItemArgs {
    #[command(subcommand)]
    command: ItemCommand,
}

/// `lk item edit` 参数。
#[derive(clap::Args)]
struct EditArgs {
    id: String,
    /// 显式指定 base revision（缺省 = 先读当前值；用于演示/脚本化 CAS 冲突）
    #[arg(long)]
    expected_revision: Option<String>,
    #[command(flatten)]
    fields: EditFields,
}

#[derive(Subcommand)]
enum ItemCommand {
    /// 列出条目（最小字段）
    List,
    /// 取单条（完整解密字段）
    Get { id: String },
    /// 新建条目（四类：login / note / secret / file）
    Add {
        #[command(subcommand)]
        kind: Box<AddKind>,
    },
    /// 编辑条目（CAS：base revision 必须与当前一致）
    Edit(Box<EditArgs>),
    /// 软删除（墓碑，30 天延迟硬删）
    Delete { id: String },
    /// 复制字段到剪贴板（30s 自动清除）
    Copy { id: String, field: String },
    /// 导出 file 条目附件到本地文件
    Export {
        id: String,
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum AddKind {
    /// 登录：账号 + 密码 + 网址 + 自定义字段
    Login {
        #[arg(long)]
        name: String,
        #[arg(long)]
        username: String,
        /// 密码（不传则交互式输入，不回显）
        #[arg(long)]
        password: Option<String>,
        /// 密码从 stdin 读取（脚本用）
        #[arg(long)]
        stdin: bool,
        /// 网址列表，逗号分隔
        #[arg(long)]
        uris: Option<String>,
    },
    /// 笔记：Markdown 内容
    Note {
        #[arg(long)]
        name: String,
        /// 内容（与 --content-file 二选一）
        #[arg(long)]
        content: Option<String>,
        /// 从文件读内容
        #[arg(long)]
        content_file: Option<PathBuf>,
    },
    /// 密钥：密钥值 + 用途/备注（可选）+ 过期时间（可选）
    Secret {
        #[arg(long)]
        name: String,
        /// 密钥值（不传则交互式输入，不回显）
        #[arg(long)]
        value: Option<String>,
        /// 密钥值从 stdin 读取（脚本用）
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        purpose: Option<String>,
        /// 过期时间 YYYY-MM-DD（可选）
        #[arg(long)]
        expires_at: Option<String>,
    },
    /// 文件：元数据 + 加密附件（≤50MB，1 MiB 分块）
    File {
        #[arg(long)]
        name: Option<String>,
        /// 附件源文件（必填）
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        note: Option<String>,
        /// MIME 类型（默认按扩展名推断，兜底 application/octet-stream）
        #[arg(long)]
        mime: Option<String>,
    },
}

/// 编辑字段（按条目类型取子集；未提供的字段保持不变）。
#[derive(clap::Args, Default)]
struct EditFields {
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    username: Option<String>,
    /// 密码（不传则保持不变；--stdin 从 stdin 读）
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    uris: Option<String>,
    #[arg(long)]
    content: Option<String>,
    #[arg(long)]
    value: Option<String>,
    #[arg(long)]
    purpose: Option<String>,
    #[arg(long)]
    expires_at: Option<String>,
    #[arg(long)]
    note: Option<String>,
    /// 替换附件（file 类型）
    #[arg(long)]
    file: Option<PathBuf>,
    /// MIME 类型（替换附件时可选）
    #[arg(long)]
    mime: Option<String>,
}

fn main() {
    // 中文提示直写 UTF-8 字节；Windows 默认控制台代码页（如 cp936）会按 GBK
    // 解码成乱码。仅对真实控制台生效，重定向到文件/管道时字节不变。
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleOutputCP(65001);
    }
    let cli = Cli::parse();
    let code = run(&cli);
    std::process::exit(code);
}

fn run(cli: &Cli) -> i32 {
    let dir = dirs::data_dir(cli.dir.as_deref());
    let out = &mut std::io::stdout();
    match &cli.command {
        Command::Init { force, stdin } => cmd_init(out, &dir, *force, *stdin, cli.json),
        Command::Unlock { stdin } => cmd_unlock(out, &dir, *stdin),
        Command::Lock => cmd_lock(out, &dir),
        Command::Status => cmd_status(out, &dir, cli.json),
        Command::Recover(args) => {
            cmd_recover(out, &dir, args.code.as_deref(), args.stdin, cli.json)
        }
        Command::Item(args) => cmd_item(out, &dir, &args.command, cli.json),
        Command::Audit { tail, verify } => cmd_audit(out, &dir, *tail, *verify, cli.json),
        Command::Daemon => cmd_daemon(&dir),
        Command::Sync => cmd_sync(out, &dir, cli.json),
        Command::Config(args) => cmd_config(out, &dir, &args.command, cli.json),
        Command::Rule(args) => cmd_rule(out, &dir, &args.command, cli.json),
        Command::Inject(args) => cmd_inject(out, &dir, &args.keys, &args.command),
        Command::Bridge => bridge::cmd_bridge(out, &dir),
    }
}

// ---------------------------------------------------------------------------
// RPC 客户端辅助（协议知识已收进 [`client`]，此处只做传输适配与错误呈现）
// ---------------------------------------------------------------------------

/// [`RpcError`] → 用户可见文案（只做呈现；措辞与重构前逐字一致）。
fn rpc_fail_text(err: &RpcError) -> String {
    match err {
        RpcError::BridgeNoDaemon { detail } => format!(
            "无法连接 Windows 桌面守护实例（bridge.no_daemon）{}",
            if detail.is_empty() { String::new() } else { format!("：{detail}") }
        ),
        RpcError::BridgeVersionIncompatible { detail } => format!(
            "Windows 桌面应用与本 CLI 协议版本不一致（bridge.version_incompatible），请重装 LightKey 桌面应用{}",
            if detail.is_empty() { String::new() } else { format!("：{detail}") }
        ),
        RpcError::BridgeIo { detail } => format!(
            "bridge 中继失败{}",
            if detail.is_empty() { String::new() } else { format!("：{detail}") }
        ),
        RpcError::VaultInvalid => "解锁失败：主密码错误或库未初始化".to_string(),
        RpcError::SessionInvalid => "库未解锁或会话已失效，请先运行 lk unlock".to_string(),
        RpcError::ItemConflict => {
            "条目已被其他设备修改（CAS 冲突），请刷新后重试".to_string()
        }
        RpcError::ItemNotFound => "条目不存在".to_string(),
        RpcError::Limit { detail } => format!("超出限制：{detail}"),
        RpcError::RateLimited { retry_after_seconds } => {
            format!("尝试过于频繁，请在 {retry_after_seconds} 秒后重试")
        }
        RpcError::VaultExists => {
            "库已存在（如需重置请使用 lk init --force，旧数据不可恢复）".to_string()
        }
        RpcError::WeakPassword => "主密码至少 8 位（建库/恢复时校验）".to_string(),
        RpcError::SyncNotConfigured { detail } => format!(
            "未配置同步存储，请先运行 lk config sync set <url>{}",
            if detail.is_empty() {
                String::new()
            } else {
                format!("（{detail}）")
            }
        ),
        RpcError::SyncStorage { detail } => format!("同步失败（存储端错误）：{detail}"),
        RpcError::SyncAnomaly { detail } => {
            format!("同步数据异常：{detail}；已放弃本轮，未覆盖本地数据")
        }
        RpcError::SyncCredentials { detail } => format!("同步凭据不可用：{detail}"),
        // 未知业务码：保留服务端 message + detail（同重构前兜底文案）
        RpcError::Other { message, detail, .. } => format!(
            "{message}{}",
            if detail.is_empty() {
                String::new()
            } else {
                format!("（{detail}）")
            }
        ),
        // 传输层 / 响应层失败的 message 已是完整文案，原样输出
        RpcError::Transport { message } | RpcError::BadResponse { message } => message.clone(),
    }
}

/// 业务失败统一出口：打印文案 + 退出码 1。
fn rpc_fail(err: &RpcError) -> i32 {
    eprintln!("lk: {}", rpc_fail_text(err));
    1
}

/// 生产传输适配（[`client::RpcClient`] 的注入点）：按探测分型分流 local /
/// bridge。会话令牌注入、bridge 的 channel 覆写都在此层完成。
///
/// 传输后端选择（cross-subsystem.md §7.2）：`LIGHTKEY_BRIDGE` 显式指定 >
/// 平台默认（WSL 自动探测 bridge，其余本地 UDS）。探测失败分型在
/// [`bridge_backend::decide`] 内完成——「装了连不上」为明确报错，绝不静默
/// 回落本地。
fn production_transport(
    dir: &std::path::Path,
) -> impl FnMut(&str, Value) -> Result<Value, RpcError> + '_ {
    move |method, params| match bridge_backend::decide() {
        bridge_backend::Decision::Local => rpc_local(dir, method, params),
        bridge_backend::Decision::Bridge(target) => rpc_via_bridge(target, method, params),
        bridge_backend::Decision::Fatal(msg) => Err(RpcError::Transport { message: msg }),
    }
}

/// 组装指向 `dir` 的 typed 客户端（每次组装重新探测传输后端，与原 `rpc()`
/// 每次调用的行为一致）。
fn client_for(
    dir: &std::path::Path,
) -> RpcClient<impl FnMut(&str, Value) -> Result<Value, RpcError> + '_> {
    RpcClient::new(production_transport(dir))
}

/// local 后端：UDS 直连本机守护实例（现状行为，自动拉起守护进程）。
fn rpc_local(dir: &std::path::Path, method: &str, params: Value) -> Result<Value, RpcError> {
    let ep = transport::ensure_daemon(dir).map_err(|e| RpcError::Transport {
        message: format!("无法连接守护进程：{e}"),
    })?;
    // 会话令牌：CLI 进程间经 0600 文件传递（守护进程锁定即删除）
    let token_path = dir.join(daemon::SESSION_TOKEN_FILE);
    let token = std::fs::read_to_string(&token_path).ok();
    let mut params = params;
    if let Some(t) = token {
        params["token"] = json!(t.trim());
    }
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let line = transport::request(&ep, &req.to_string()).map_err(|e| RpcError::Transport {
        message: format!("守护进程通信失败：{e}"),
    })?;
    client::parse_response_line(&line)
}

/// bridge 后端：把请求帧经 `lk.exe bridge` 中继到 Windows 桌面守护实例
/// （cross-subsystem.md §5/§7.2）。会话令牌仍只在进程内存/令牌文件流转：
/// Windows 侧守护实例把 token 写在其数据目录（经 drvfs 只读回读），本侧
/// 不新增任何持久化。主密码交互输入逻辑不变（read_secret 不经此路径改动）。
fn rpc_via_bridge(
    target: bridge_backend::BridgeTarget,
    method: &str,
    params: Value,
) -> Result<Value, RpcError> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut params = params;
    if let Some(dd) = &target.data_dir {
        if let Ok(t) = std::fs::read_to_string(dd.join(daemon::SESSION_TOKEN_FILE)) {
            params["token"] = json!(t.trim());
        }
    }
    // 审计 channel 如实标注桥接来源（cross-subsystem.md §7.5）：经 bridge 的
    // authz.evaluate / rule.* 必须以 `wsl-bridge` 留痕，不得记作本地 cli
    // （客户端硬编码的 "cli" 在此路径被覆写；其余方法无 channel 字段，不动）。
    if matches!(
        method,
        M_AUTHZ_EVALUATE | M_RULE_ADD | M_RULE_LIST | M_RULE_REMOVE
    ) {
        params["channel"] = json!("wsl-bridge");
    }
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });

    // 一请求一子进程：bridge 自身做版本校验并向 stderr 打连接目标提示行
    // （继承 stderr 直达用户终端）。stdin/stdout 均为原始字节管道。
    let mut cmd = Command::new(&target.exe);
    cmd.arg("bridge");
    if let Some(d) = &target.dir_arg {
        cmd.arg("--dir").arg(d);
    }
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()); // stderr 继承（可见性）
    let mut child = cmd.spawn().map_err(|e| RpcError::Transport {
        message: format!("无法启动 bridge 中继程序（{}）：{e}", target.exe.display()),
    })?;
    {
        let mut stdin = child.stdin.take().expect("stdin 已声明 piped");
        let frame = req.to_string();
        stdin
            .write_all(frame.as_bytes())
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
            .map_err(|e| RpcError::Transport {
                message: format!("写入 bridge 失败：{e}"),
            })?;
        // 显式关闭写端：bridge 读到 EOF/一帧后即处理并退出
        drop(stdin);
    }
    let mut stdout = child.stdout.take().expect("stdout 已声明 piped");
    let mut line = Vec::new();
    {
        use std::io::BufRead as _;
        let mut reader = std::io::BufReader::new(&mut stdout);
        loop {
            match reader.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) if line.ends_with(b"\n") => break,
                Ok(_) => continue,
            }
        }
    }
    let status = child.wait().map_err(|e| RpcError::Transport {
        message: format!("等待 bridge 退出失败：{e}"),
    })?;
    if !status.success() && line.is_empty() {
        return Err(RpcError::Transport {
            message: format!("bridge 中继程序异常退出（{status}）"),
        });
    }
    while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
        line.pop();
    }
    let line = String::from_utf8(line).map_err(|_| RpcError::BadResponse {
        message: "bridge 响应不是合法 UTF-8".to_string(),
    })?;
    if line.trim().is_empty() {
        return Err(RpcError::BadResponse {
            message: format!("bridge 无响应（中继程序异常退出 {status}）"),
        });
    }
    client::parse_response_line(&line)
}

/// 读取一行敏感输入（不回显；`--stdin` 时从 stdin 读）。
fn read_secret(prompt: &str, stdin: bool) -> Result<String, i32> {
    if stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).map_err(|e| {
            eprintln!("lk: 读取 stdin 失败：{e}");
            1
        })?;
        return Ok(line.trim_end_matches(['\r', '\n']).to_string());
    }
    rpassword::prompt_password(format!("{prompt}: ")).map_err(|e| {
        eprintln!("lk: 无法读取输入：{e}");
        1
    })
}

/// 交互式确认（重置等破坏性操作）。
fn confirm(prompt: &str) -> bool {
    use std::io::BufRead;
    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    line.trim().eq_ignore_ascii_case("y") || line.trim().eq_ignore_ascii_case("yes")
}

// ---------------------------------------------------------------------------
// 库生命周期
// ---------------------------------------------------------------------------

fn cmd_init(
    out: &mut impl Write,
    dir: &std::path::Path,
    force: bool,
    stdin: bool,
    json_out: bool,
) -> i32 {
    if force && !confirm("警告：将清空当前库并重建（旧数据不可恢复）。继续？")
    {
        eprintln!("lk: 已取消");
        return 1;
    }
    let pw1 = match read_secret("设置主密码", stdin) {
        Ok(p) => p,
        Err(c) => return c,
    };
    if pw1.is_empty() {
        eprintln!("lk: 主密码不能为空");
        return 1;
    }
    if !stdin {
        let pw2 = match read_secret("确认主密码", false) {
            Ok(p) => p,
            Err(c) => return c,
        };
        if pw1 != pw2 {
            eprintln!("lk: 两次输入的主密码不一致");
            return 1;
        }
    }
    match client_for(dir).vault_init(&pw1, force) {
        Ok(code) => {
            if json_out {
                let _ = writeln!(out, "{}", json!({ "recoveryCode": code }));
            } else {
                let _ = writeln!(out, "库已初始化。");
                let _ = writeln!(out);
                let _ = writeln!(out, "⚠ 恢复码（仅展示这一次，请立即抄存到安全位置）：");
                let _ = writeln!(out, "  {code}");
                let _ = writeln!(out);
                let _ = writeln!(
                    out,
                    "恢复码 + 主密码是数据恢复的唯一凭证；两者全丢则数据不可恢复。"
                );
            }
            0
        }
        Err(e) => rpc_fail(&e),
    }
}

fn cmd_unlock(out: &mut impl Write, dir: &std::path::Path, stdin: bool) -> i32 {
    let pw = match read_secret("主密码", stdin) {
        Ok(p) => p,
        Err(c) => return c,
    };
    match client_for(dir).vault_unlock(&pw) {
        Ok(_) => {
            let _ = writeln!(out, "已解锁");
            0
        }
        Err(e) => rpc_fail(&e),
    }
}

fn cmd_lock(out: &mut impl Write, dir: &std::path::Path) -> i32 {
    match client_for(dir).vault_lock() {
        Ok(_) => {
            let _ = writeln!(out, "已锁定（内存密钥已擦除）");
            0
        }
        Err(e) => rpc_fail(&e),
    }
}

fn cmd_status(out: &mut impl Write, dir: &std::path::Path, json_out: bool) -> i32 {
    // 连接目标可见性（cross-subsystem.md §7.2）：杜绝「以为在操作本地、
    // 实际连着 Windows 真库」的语义模糊。探测分型失败 → 明确报错。
    // 同步配置行与 config 命令同源（补充拍板 #14 裁定）：bridge 后端直读
    // Windows 侧数据目录的 config.json，不读本地文件（防混合来源显示）。
    let decision = bridge_backend::decide();
    let (on_bridge, cfg_dir) = match &decision {
        bridge_backend::Decision::Local => (false, dir.to_path_buf()),
        bridge_backend::Decision::Bridge(target) => match &target.data_dir {
            Some(dd) => (true, dd.clone()),
            None => {
                eprintln!(
                    "lk: bridge 模式下无法定位 Windows 侧数据目录（未指定 LIGHTKEY_BRIDGE_HOME 且探测无果），无法读取 Windows 侧同步配置"
                );
                return 1;
            }
        },
        bridge_backend::Decision::Fatal(msg) => {
            eprintln!("lk: {msg}");
            return 1;
        }
    };
    match client_for(dir).vault_status() {
        Ok(status) => {
            let unlocked = status.unlocked;
            let version = status.version;
            let watermark = status.sync_watermark;
            if json_out {
                let _ = writeln!(
                    out,
                    "{}",
                    json!({ "unlocked": unlocked, "version": version, "syncWatermark": watermark, "target": if on_bridge { "bridge" } else { "local" } })
                );
            } else {
                let mut sync_line = match daemon::read_config(&cfg_dir).sync {
                    Some(cfg) => format!(
                        "已配置 {}（每 {}s 轮询）{}",
                        cfg.url,
                        cfg.interval_secs,
                        watermark
                            .map(|w| format!("，水位 {w}"))
                            .unwrap_or_else(|| "，尚未同步".to_string())
                    ),
                    None => "未配置（lk config sync set <url> 启用）".to_string(),
                };
                if on_bridge {
                    sync_line.push_str("（Windows 桥接）");
                }
                let target_line = if on_bridge {
                    "Windows 桌面守护实例（经 bridge）"
                } else {
                    "本地守护实例"
                };
                let _ = writeln!(
                    out,
                    "状态: {} | 版本: {} | 连接: {} | 同步: {}",
                    if unlocked { "已解锁" } else { "已锁定" },
                    version,
                    target_line,
                    sync_line
                );
            }
            0
        }
        Err(e) => rpc_fail(&e),
    }
}

fn cmd_recover(
    out: &mut impl Write,
    dir: &std::path::Path,
    code: Option<&str>,
    stdin: bool,
    json_out: bool,
) -> i32 {
    // --stdin 模式：第一行恢复码、第二行新主密码（脚本用）
    use std::io::BufRead;
    let mut code_lines = std::io::stdin().lock().lines();
    let code = match code {
        Some(c) => c.to_string(),
        None if stdin => match code_lines.next() {
            Some(Ok(c)) => c.trim().to_string(),
            _ => {
                eprintln!("lk: 读取恢复码失败");
                return 1;
            }
        },
        None => match read_secret("恢复码（仅输入字符，无需分隔符）", false) {
            Ok(c) => c,
            Err(e) => return e,
        },
    };
    let pw1 = if stdin {
        match code_lines.next() {
            Some(Ok(p)) => p.trim().to_string(),
            _ => {
                eprintln!("lk: 读取新主密码失败");
                return 1;
            }
        }
    } else {
        match read_secret("设置新主密码", false) {
            Ok(p) => p,
            Err(c) => return c,
        }
    };
    if !stdin {
        let pw2 = match read_secret("确认新主密码", false) {
            Ok(p) => p,
            Err(c) => return c,
        };
        if pw1 != pw2 {
            eprintln!("lk: 两次输入的新主密码不一致");
            return 1;
        }
    }
    match client_for(dir).vault_recover(&code, &pw1) {
        Ok(new_code) => {
            if json_out {
                let _ = writeln!(out, "{}", json!({ "recoveryCode": new_code }));
            } else {
                let _ = writeln!(out, "恢复完成。");
                let _ = writeln!(out);
                let _ = writeln!(out, "⚠ 新恢复码（仅展示这一次，请立即抄存）：");
                let _ = writeln!(out, "  {new_code}");
                let _ = writeln!(out);
                let _ = writeln!(out, "请用新主密码解锁：lk unlock");
            }
            0
        }
        Err(e) => rpc_fail(&e),
    }
}

// ---------------------------------------------------------------------------
// 条目
// ---------------------------------------------------------------------------

fn cmd_item(out: &mut impl Write, dir: &std::path::Path, cmd: &ItemCommand, json_out: bool) -> i32 {
    let mut c = client_for(dir);
    match cmd {
        ItemCommand::List => match c.item_list() {
            Ok(items) => {
                if json_out {
                    let _ = writeln!(
                        out,
                        "{}",
                        serde_json::to_string_pretty(&items).unwrap_or_default()
                    );
                } else {
                    if items.is_empty() {
                        let _ =
                            writeln!(out, "（无条目。lk item add login --name ... 添加第一条）");
                    }
                    for it in &items {
                        let _ = writeln!(
                            out,
                            "{}\t{}\t{}\t{}\t{}",
                            it.id,
                            it.kind.as_str(),
                            it.name,
                            it.revision,
                            if it.deleted { "[deleted]" } else { "" }
                        );
                    }
                }
                0
            }
            Err(e) => rpc_fail(&e),
        },
        ItemCommand::Get { id } => match c.item_get(id) {
            Ok(item) => print_item(out, &item, json_out),
            Err(e) => rpc_fail(&e),
        },
        ItemCommand::Add { kind } => cmd_item_add(out, &mut c, kind),
        ItemCommand::Edit(args) => cmd_item_edit(
            out,
            &mut c,
            &args.id,
            &args.fields,
            args.expected_revision.as_deref(),
        ),
        ItemCommand::Delete { id } => match c.item_delete(id) {
            Ok(_) => {
                let _ = writeln!(out, "已删除（软删除，30 天后硬删）");
                0
            }
            Err(e) => rpc_fail(&e),
        },
        ItemCommand::Copy { id, field } => cmd_item_copy(out, &mut c, id, field),
        ItemCommand::Export { id, output } => match c.item_export(id) {
            Ok(data) => match std::fs::write(output, &data) {
                Ok(_) => {
                    let _ = writeln!(out, "已导出到 {}（{} 字节）", output.display(), data.len());
                    0
                }
                Err(e) => {
                    eprintln!("lk: 写入失败：{e}");
                    1
                }
            },
            Err(e) => rpc_fail(&e),
        },
    }
}

fn print_item(out: &mut impl Write, item: &lk_core::model::Item, json_out: bool) -> i32 {
    use lk_core::model::Item;
    if json_out {
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(item).unwrap_or_default()
        );
        return 0;
    }
    let id = item.id();
    let ty = item.kind().as_str();
    let name = item.name();
    let revision = item.revision();
    let deleted = item.deleted();
    let _ = writeln!(
        out,
        "{id}  [{ty}] {name}{}",
        if deleted { " [deleted]" } else { "" }
    );
    let _ = writeln!(out, "  revision: {revision}");
    match item {
        Item::Login {
            username,
            password,
            uris,
            custom,
            ..
        } => {
            let _ = writeln!(out, "  username: {username}");
            let _ = writeln!(out, "  password: {password}");
            for u in uris {
                let _ = writeln!(out, "  uri: {u}");
            }
            for f in custom {
                let _ = writeln!(
                    out,
                    "  custom: {} = {}{}",
                    f.name,
                    f.value,
                    if f.hidden { " (hidden)" } else { "" }
                );
            }
        }
        Item::Note { content, .. } => {
            let _ = writeln!(out, "  content: {content}");
        }
        Item::Secret {
            value,
            purpose,
            expires_at,
            ..
        } => {
            let _ = writeln!(out, "  value: {value}");
            let _ = writeln!(out, "  purpose: {purpose}");
            let _ = writeln!(
                out,
                "  expiresAt: {}",
                expires_at.clone().unwrap_or_default()
            );
        }
        Item::File {
            note,
            size,
            file_type,
            attachment,
            ..
        } => {
            let _ = writeln!(out, "  note: {note}");
            let _ = writeln!(out, "  size: {size} bytes");
            let _ = writeln!(out, "  fileType: {file_type}");
            let _ = writeln!(out, "  attachment: {attachment}");
        }
    }
    0
}

fn cmd_item_add<'a>(
    out: &mut impl Write,
    c: &mut RpcClient<impl FnMut(&str, Value) -> Result<Value, RpcError> + 'a>,
    kind: &AddKind,
) -> i32 {
    let draft = match kind {
        AddKind::Login {
            name,
            username,
            password,
            stdin,
            uris,
        } => {
            let password = match password {
                Some(p) => p.clone(),
                None => match read_secret("密码", *stdin) {
                    Ok(p) => p,
                    Err(c) => return c,
                },
            };
            let uris = uris
                .as_deref()
                .map(|u| {
                    u.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            ItemDraft::Login {
                name: name.clone(),
                username: username.clone(),
                password,
                uris,
                custom: vec![],
            }
        }
        AddKind::Note {
            name,
            content,
            content_file,
        } => {
            let content = match (content, content_file) {
                (Some(c), _) => c.clone(),
                (None, Some(f)) => match std::fs::read_to_string(f) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("lk: 读取内容文件失败：{e}");
                        return 1;
                    }
                },
                (None, None) => {
                    eprintln!("lk: note 需要 --content 或 --content-file");
                    return 2;
                }
            };
            ItemDraft::Note {
                name: name.clone(),
                content,
            }
        }
        AddKind::Secret {
            name,
            value,
            stdin,
            purpose,
            expires_at,
        } => {
            let value = match value {
                Some(v) => v.clone(),
                None => match read_secret("密钥值", *stdin) {
                    Ok(v) => v,
                    Err(c) => return c,
                },
            };
            ItemDraft::Secret {
                name: name.clone(),
                value,
                purpose: purpose.clone().unwrap_or_default(),
                expires_at: expires_at.clone(),
            }
        }
        AddKind::File {
            name,
            file,
            note,
            mime,
        } => {
            let data = match std::fs::read(file) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("lk: 读取附件失败：{e}");
                    return 1;
                }
            };
            if data.len() as u64 > 50 * 1024 * 1024 {
                eprintln!("lk: 附件超过 50MB 上限");
                return 1;
            }
            let file_name = file
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let mime = mime
                .clone()
                .or_else(|| guess_mime(&file_name))
                .unwrap_or_else(|| "application/octet-stream".to_string());
            use base64::Engine as _;
            ItemDraft::File {
                name: name.clone().unwrap_or_else(|| file_name.clone()),
                note: note.clone().unwrap_or_default(),
                size: 0,
                file_type: mime,
                attachment: file_name,
                attach_id: None,
                file_data: Some(base64::engine::general_purpose::STANDARD.encode(data)),
            }
        }
    };
    match c.item_put(&draft) {
        Ok(item) => {
            let id = item.id().to_string();
            let _ = writeln!(out, "已创建: {id}");
            if std::env::var("LK_ECHO_ITEM").is_ok() {
                let _ = writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(&item).unwrap_or_default()
                );
            }
            0
        }
        Err(e) => rpc_fail(&e),
    }
}

fn guess_mime(name: &str) -> Option<String> {
    let ext = name.rsplit('.').next()?.to_ascii_lowercase();
    let mime = match ext.as_str() {
        "txt" | "md" | "markdown" => "text/plain",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "zip" => "application/zip",
        "json" => "application/json",
        "doc" | "docx" => "application/msword",
        "xls" | "xlsx" => "application/vnd.ms-excel",
        _ => return None,
    };
    Some(mime.to_string())
}

fn cmd_item_edit<'a>(
    out: &mut impl Write,
    c: &mut RpcClient<impl FnMut(&str, Value) -> Result<Value, RpcError> + 'a>,
    id: &str,
    fields: &EditFields,
    expected_revision: Option<&str>,
) -> i32 {
    use lk_core::model::Item;
    let any = fields.name.is_some()
        || fields.username.is_some()
        || fields.password.is_some()
        || fields.uris.is_some()
        || fields.content.is_some()
        || fields.value.is_some()
        || fields.purpose.is_some()
        || fields.expires_at.is_some()
        || fields.note.is_some()
        || fields.file.is_some();
    if !any {
        eprintln!("lk: edit 至少需要一个变更字段（如 --name / --username / --content）");
        return 2;
    }
    // 拆分逗号分隔的 uri 列表（与 add 同规则）
    let split_uris = |raw: &str| -> Vec<String> {
        raw.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    // CAS：缺省先取当前条目（base revision），再整条替换
    let current = match c.item_get(id) {
        Ok(v) => v,
        Err(e) => return rpc_fail(&e),
    };
    let mut draft = match &current {
        Item::Login {
            name,
            username,
            password,
            uris,
            custom,
            ..
        } => ItemDraft::Login {
            name: fields.name.clone().unwrap_or_else(|| name.clone()),
            username: fields.username.clone().unwrap_or_else(|| username.clone()),
            password: fields.password.clone().unwrap_or_else(|| password.clone()),
            uris: fields
                .uris
                .clone()
                .map(|u| split_uris(&u))
                .unwrap_or_else(|| uris.clone()),
            custom: custom.clone(),
        },
        Item::Note { name, content, .. } => ItemDraft::Note {
            name: fields.name.clone().unwrap_or_else(|| name.clone()),
            content: fields.content.clone().unwrap_or_else(|| content.clone()),
        },
        Item::Secret {
            name,
            value,
            purpose,
            expires_at,
            ..
        } => ItemDraft::Secret {
            name: fields.name.clone().unwrap_or_else(|| name.clone()),
            value: fields.value.clone().unwrap_or_else(|| value.clone()),
            purpose: fields.purpose.clone().unwrap_or_else(|| purpose.clone()),
            expires_at: fields.expires_at.clone().or_else(|| expires_at.clone()),
        },
        Item::File {
            name,
            note,
            size,
            file_type,
            attachment,
            attach_id,
            ..
        } => {
            let file_data = match &fields.file {
                Some(path) => match std::fs::read(path) {
                    Ok(d) => {
                        if d.len() as u64 > 50 * 1024 * 1024 {
                            eprintln!("lk: 附件超过 50MB 上限");
                            return 1;
                        }
                        use base64::Engine as _;
                        Some(base64::engine::general_purpose::STANDARD.encode(d))
                    }
                    Err(e) => {
                        eprintln!("lk: 读取附件失败：{e}");
                        return 1;
                    }
                },
                None => None,
            };
            ItemDraft::File {
                name: fields.name.clone().unwrap_or_else(|| name.clone()),
                note: fields.note.clone().unwrap_or_else(|| note.clone()),
                size: *size,
                file_type: file_type.clone(),
                attachment: attachment.clone(),
                attach_id: *attach_id,
                file_data,
            }
        }
    };
    // file 替换附件时更新文件名/MIME
    if let (
        Some(path),
        ItemDraft::File {
            attachment,
            file_type,
            ..
        },
    ) = (&fields.file, &mut draft)
    {
        if let Some(name) = path.file_name() {
            *attachment = name.to_string_lossy().to_string();
        }
        if fields.mime.is_none() {
            if let Some(m) = guess_mime(&path.to_string_lossy()) {
                *file_type = m;
            }
        }
    }
    let base_revision = expected_revision.unwrap_or(current.revision()).to_string();
    match c.item_update(id, &draft, &base_revision) {
        Ok(item) => {
            let _ = writeln!(out, "已更新: {} (revision {})", item.id(), item.revision());
            0
        }
        Err(e) => rpc_fail(&e),
    }
}

fn cmd_item_copy<'a>(
    out: &mut impl Write,
    c: &mut RpcClient<impl FnMut(&str, Value) -> Result<Value, RpcError> + 'a>,
    id: &str,
    field: &str,
) -> i32 {
    use lk_core::model::Item;
    let item = match c.item_get(id) {
        Ok(v) => v,
        Err(e) => return rpc_fail(&e),
    };
    let ty = item.kind().as_str();
    let value: Option<&str> = match (&item, field) {
        (Item::Login { username, .. }, "username") => Some(username.as_str()),
        (Item::Login { password, .. }, "password") => Some(password.as_str()),
        (Item::Note { content, .. }, "content") => Some(content.as_str()),
        (Item::Secret { value, .. }, "value") => Some(value.as_str()),
        _ => None,
    };
    let Some(value) = value else {
        eprintln!(
            "lk: 字段 {field} 不适用于 {ty} 类型条目（可用: username/password/content/value）"
        );
        return 2;
    };
    if let Err(e) = clipboard::copy(value.to_string()) {
        eprintln!("lk: {e}");
        return 1;
    }
    let _ = writeln!(out, "已复制，30 秒后自动清除（期间请勿复制其他内容）");
    // 主线程驻留 30s 后同步清除（不 spawn 后台线程：process::exit 不 join
    // 会立即杀死后台线程，清除是否执行是竞态；同步执行保证 cli.md §2 语义）
    std::thread::sleep(std::time::Duration::from_secs(clipboard::CLEAR_AFTER_SECS));
    if let Err(e) = clipboard::clear() {
        eprintln!("lk: 剪贴板自动清除失败: {e}");
    }
    0
}

// ---------------------------------------------------------------------------
// 审计
// ---------------------------------------------------------------------------

fn cmd_audit(
    out: &mut impl Write,
    dir: &std::path::Path,
    tail: Option<usize>,
    verify: bool,
    json_out: bool,
) -> i32 {
    let mut c = client_for(dir);
    let page = match c.audit_list(tail) {
        Ok(v) => v,
        Err(e) => return rpc_fail(&e),
    };
    let events = &page.events;
    let total = page.total;
    if json_out {
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(events).unwrap_or_default()
        );
    } else {
        let _ = writeln!(
            out,
            "审计事件（共 {total} 条{}）",
            tail.map(|t| format!("，显示最近 {t}")).unwrap_or_default()
        );
        for e in events {
            let result = serde_json::to_string(&e.result).unwrap_or_default();
            let _ = writeln!(out, "{}  {}  {}  {}", e.ts, e.command, result, e.starter);
        }
    }
    if verify {
        match c.audit_verify() {
            Ok(verified) => {
                if json_out {
                    let _ = writeln!(out, "{}", json!({ "verified": verified }));
                } else {
                    let _ = writeln!(out, "HMAC 链校验：{} 条事件验证通过", verified);
                }
            }
            Err(e) => return rpc_fail(&e),
        }
    }
    0
}

// ---------------------------------------------------------------------------
// 同步 / 配置（M1）
// ---------------------------------------------------------------------------

/// `lk sync`：触发一轮同步（轮询 + CAS 上传），返回变更摘要。
fn cmd_sync(out: &mut impl Write, dir: &std::path::Path, json_out: bool) -> i32 {
    match client_for(dir).sync_trigger() {
        Ok(summary) => {
            if json_out {
                let _ = writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    out,
                    "已同步：拉取 {} · 推送 {} · CAS 冲突 {} · 硬删 {}",
                    summary.pulled, summary.pushed, summary.conflicts, summary.purged
                );
            }
            for w in &summary.warnings {
                eprintln!("lk: 提示：{w}");
            }
            0
        }
        Err(e) => rpc_fail(&e),
    }
}

/// 桥模式下配置命令/状态行的目标数据目录（补充拍板 #14 裁定：bridge 后端
/// 直写 Windows 侧 config.json，不走新 IPC/协议）。
/// 本地 → 原 dir（行为完全不变）；Bridge+已定位 → Windows 数据目录；
/// Bridge 但数据目录不可定位 / 探测失败 → Err（fail-closed，绝不读错目录）。
fn config_dir_for(
    decision: &bridge_backend::Decision,
    local: &std::path::Path,
) -> Result<PathBuf, String> {
    match decision {
        bridge_backend::Decision::Local => Ok(local.to_path_buf()),
        bridge_backend::Decision::Bridge(target) => match &target.data_dir {
            Some(dd) => Ok(dd.clone()),
            None => Err(
                "bridge 模式下无法定位 Windows 侧数据目录（未指定 LIGHTKEY_BRIDGE_HOME 且探测无果），无法读写 Windows 侧 config.json".to_string(),
            ),
        },
        bridge_backend::Decision::Fatal(msg) => Err(msg.clone()),
    }
}

/// `lk config` 入口。
fn cmd_config(
    out: &mut impl Write,
    dir: &std::path::Path,
    cmd: &ConfigCommand,
    json_out: bool,
) -> i32 {
    let decision = bridge_backend::decide();
    let on_bridge = matches!(decision, bridge_backend::Decision::Bridge(_));
    let cfg_dir = match config_dir_for(&decision, dir) {
        Ok(d) => d,
        Err(msg) => {
            eprintln!("lk: {msg}");
            return 1;
        }
    };
    match cmd {
        ConfigCommand::Sync { command } => match command {
            ConfigSyncCommand::Set {
                url,
                interval,
                credentials_file,
                stdin,
            } => {
                let code = cmd_config_sync_set(
                    out,
                    &cfg_dir,
                    url,
                    *interval,
                    credentials_file.as_deref(),
                    *stdin,
                    json_out,
                );
                if on_bridge && code == 0 && !url.starts_with("file://") {
                    eprintln!("lk config: 提示：凭据已存入 WSL 钥匙串，但 Windows 桌面守护实例读取的是 Windows 侧钥匙串——请在 Windows 桌面应用或 Windows 侧 lk.exe 中配置凭据");
                }
                code
            }
        },
        ConfigCommand::Get { key } => cmd_config_get(out, &cfg_dir, key, json_out),
    }
}

/// `lk config sync set <url>`：配置 BYO 存储 + 轮询间隔 + 凭据（钥匙串）。
fn cmd_config_sync_set(
    out: &mut impl Write,
    dir: &std::path::Path,
    url: &str,
    interval: Option<u64>,
    credentials_file: Option<&std::path::Path>,
    stdin: bool,
    json_out: bool,
) -> i32 {
    use lk_core::sync::{SyncConfig, DEFAULT_SYNC_INTERVAL_SECS};
    let interval_secs = interval.unwrap_or(DEFAULT_SYNC_INTERVAL_SECS);
    let cfg = SyncConfig {
        url: url.to_string(),
        interval_secs,
    };
    if let Err(e) = cfg.validate() {
        eprintln!("lk config: {e}");
        return 2;
    }
    // 凭据：仅 WebDAV/S3 需要；交互式输入（不回显）或文件/stdin 导入。
    // 位置参数只接受存储 URL，不接受凭据明文（cli.md §3 / 补充拍板 #3）。
    let scheme = url.split_once("://").map(|(s, _)| s).unwrap_or("");
    if !matches!(scheme, "file") {
        match read_sync_credentials(url, credentials_file, stdin) {
            Ok(Some((user, pass))) => {
                if let Err(e) = daemon::store_sync_credentials(url, &user, &pass) {
                    eprintln!("lk config: {e}");
                    return 1;
                }
            }
            Ok(None) => {
                eprintln!("lk config: 未提供凭据（交互式输入 / --credentials-file / --stdin）");
                return 1;
            }
            Err(code) => return code,
        }
    } else if credentials_file.is_some() || stdin {
        eprintln!("lk config: 提示：file:// 本地模拟无需凭据，已忽略凭据输入");
    }
    // 写配置（原子 tmp+rename；Windows 守护进程每轮同步热重读，下一轮生效）
    let mut config = daemon::read_config(dir);
    config.sync = Some(cfg.clone());
    if let Err(e) = daemon::write_config(dir, &config) {
        eprintln!("lk config: 写入配置失败：{e}");
        return 1;
    }
    if json_out {
        let _ = writeln!(
            out,
            "{}",
            serde_json::json!({ "url": cfg.url, "intervalSecs": cfg.interval_secs })
        );
    } else {
        let _ = writeln!(
            out,
            "已配置同步：{}（每 {}s 轮询）",
            cfg.url, cfg.interval_secs
        );
    }
    0
}

/// 读取同步凭据（username/password）：交互式（不回显）/ 文件 / stdin。
fn read_sync_credentials(
    url: &str,
    credentials_file: Option<&std::path::Path>,
    stdin: bool,
) -> Result<Option<(String, String)>, i32> {
    use std::io::BufRead;
    let read_lines =
        |mut lines: Box<dyn Iterator<Item = std::io::Result<String>>>| -> Option<(String, String)> {
            let user = lines.next()?.ok()?;
            let pass = lines.next()?.ok()?;
            Some((user.trim().to_string(), pass.trim().to_string()))
        };
    let creds = if let Some(path) = credentials_file {
        match std::fs::File::open(path) {
            Ok(f) => read_lines(Box::new(std::io::BufReader::new(f).lines())),
            Err(e) => {
                eprintln!("lk config: 读取凭据文件失败：{e}");
                return Err(1);
            }
        }
    } else if stdin {
        read_lines(Box::new(std::io::stdin().lock().lines()))
    } else {
        let user = match rpassword::prompt_password("存储用户名: ") {
            Ok(u) => u,
            Err(e) => {
                eprintln!("lk config: 无法读取输入：{e}");
                return Err(1);
            }
        };
        let pass = match rpassword::prompt_password("存储密码: ") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("lk config: 无法读取输入：{e}");
                return Err(1);
            }
        };
        Some((user.trim().to_string(), pass.trim().to_string()))
    };
    let Some((user, pass)) = creds else {
        eprintln!("lk config: 凭据需要两行：用户名 + 密码（目标：{url}）");
        return Err(2);
    };
    if user.is_empty() {
        eprintln!("lk config: 用户名不能为空");
        return Err(2);
    }
    Ok(Some((user, pass)))
}

/// `lk config get <key>`：读取配置。
fn cmd_config_get(out: &mut impl Write, dir: &std::path::Path, key: &str, json_out: bool) -> i32 {
    let config = daemon::read_config(dir);
    let value: Option<String> = match key {
        "sync.url" => config.sync.as_ref().map(|c| c.url.clone()),
        "sync.interval" => config.sync.as_ref().map(|c| c.interval_secs.to_string()),
        "sync.enabled" => Some(
            if config.sync.is_some() {
                "true"
            } else {
                "false"
            }
            .to_string(),
        ),
        "autoLockMinutes" => Some(config.auto_lock_minutes.to_string()),
        _ => {
            eprintln!(
                "lk config: 未知配置键 {key}（可用：sync.url / sync.interval / sync.enabled / autoLockMinutes）"
            );
            return 2;
        }
    };
    match value {
        Some(v) => {
            if json_out {
                let _ = writeln!(out, "{}", json!({ key: v }));
            } else {
                let _ = writeln!(out, "{v}");
            }
            0
        }
        None => {
            eprintln!("lk config: 未配置 {key}");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// 授权门：规则管理 / 注入（M2）
// ---------------------------------------------------------------------------

/// `lk rule` 入口。
fn cmd_rule(out: &mut impl Write, dir: &std::path::Path, cmd: &RuleCommand, json_out: bool) -> i32 {
    match cmd {
        RuleCommand::Add {
            project_dir,
            command,
            name,
            keys,
        } => cmd_rule_add(out, dir, project_dir, name, command, keys, json_out),
        RuleCommand::List => cmd_rule_list(out, dir, json_out),
        RuleCommand::Remove { id } => cmd_rule_remove(out, dir, id, json_out),
    }
}

/// `lk rule add <projectDir> <command> --name <name> <keys...>`：
/// projectDir 规范化（解析符号链接）后入库。跨命名空间形态
/// （cross-subsystem.md §7.4）：
/// - 显式 `wsl://<distro>/...` 规范形直接采用（守护进程侧校验）；
/// - bridge 后端下显式 Windows 绝对路径（`X:\…` / `X:/…`）直接采用
///   （Windows 侧校验入库，非交互可直录 drvfs 规则）；
/// - 以 `/` 开头且非现存本机路径 → 解析为 `wsl://<默认发行版>/…` 并回显确认；
/// - bridge 后端下解析出的 POSIX 绝对路径折算并回显确认：drvfs 目录
///   （/mnt/<盘>/…）→ Windows 绝对路径形态（与运行时 cwd 同命名空间）；
///   其余 → `wsl://<默认发行版>/…`。
fn cmd_rule_add(
    out: &mut impl Write,
    dir: &std::path::Path,
    project_dir: &str,
    name: &str,
    command: &str,
    keys: &[String],
    json_out: bool,
) -> i32 {
    use std::io::IsTerminal;
    if keys.is_empty() {
        eprintln!("lk rule add: 至少需要 1 个 key 名（值不可见、名可指名）");
        return 2;
    }
    // 显式 `wsl://<distro>/...` 规范形直接采用（守护进程侧校验形态合法性）——
    // 本函数在默认发行版解析被拒时给出的重试指引就是该形态，必须可用。
    // bridge 后端下显式 Windows 绝对路径（X:\… / X:/…）同样直通：跳过本地
    // fs canonicalize 与 wsl 解析守卫，原样送守护进程由 Windows 侧校验入库
    // （非交互可直录 drvfs 规则；本地后端行为不变）。
    let bridge_mode = matches!(
        bridge_backend::decide(),
        bridge_backend::Decision::Bridge(_)
    );
    let mut canonical = if lk_core::path_ns::is_valid_wsl_canonical(project_dir) {
        project_dir.to_string()
    } else if let Some(w) = bridge_windows_abs_passthrough(project_dir, bridge_mode) {
        w
    } else {
        match std::fs::canonicalize(project_dir) {
            Ok(c) => c.to_string_lossy().to_string(),
            Err(_)
                if project_dir.starts_with('/') && !std::path::Path::new(project_dir).exists() =>
            {
                // 以 / 开头且非现存本机路径 → 可能是 WSL 内路径：解析为
                // wsl://<默认发行版>/... 并回显确认（默认发行版歧义显式化）
                match resolve_wsl_rule_dir(
                    project_dir,
                    std::io::stdin().is_terminal(),
                    &mut std::io::stdin().lock(),
                ) {
                    Some(c) => c,
                    None => return 1,
                }
            }
            Err(e) => {
                eprintln!("lk rule add: 项目目录无法解析：{project_dir}（{e}）");
                return 1;
            }
        }
    };
    // bridge 后端下，canonicalize 成功的 POSIX 绝对路径（WSL 内现存目录，含
    // 相对路径的解析产物）属于 WSL 命名空间：Windows 守护进程无法将其视为
    // 绝对路径入库，须折算后回显确认再发送（cross-subsystem.md §7.4；本地
    // 后端不受影响，维持 POSIX 原语义）。折算规则：drvfs 目录（/mnt/<盘>/…）
    // → Windows 绝对路径形态（与 interop bridge 进程继承的 PEB cwd 同命名
    // 空间，精确匹配）；其余 WSL 原生路径 → wsl://<默认发行版>/… 规范形。
    if bridge_mode && canonical.starts_with('/') {
        let interactive = std::io::stdin().is_terminal();
        let mut input = std::io::stdin().lock();
        canonical = match drvfs_rule_windows_form(&canonical) {
            Some(win) => {
                match confirm_windows_candidate(&canonical, &win, interactive, &mut input) {
                    Some(c) => c,
                    None => return 1,
                }
            }
            None => match resolve_wsl_rule_dir(&canonical, interactive, &mut input) {
                Some(c) => c,
                None => return 1,
            },
        };
    }
    match client_for(dir).rule_add(&canonical, name, command, keys) {
        Ok(rule) => {
            if json_out {
                let _ = writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(&rule).unwrap_or_default()
                );
            } else {
                let _ = writeln!(out, "已添加规则: {}（{}）", rule.id, rule.name);
            }
            0
        }
        Err(e) => rpc_fail(&e),
    }
}

/// 解析需折算为 WSL 命名空间的项目目录（cross-subsystem.md §7.4）：
/// `<path>` → `wsl://<默认发行版><path>`，回显解析结果要求确认（默认发行版
/// 歧义显式化，防静默错配）。调用点：非现存本机路径的 `/` 开头输入、bridge
/// 后端下解析出的非 drvfs POSIX 绝对路径。
///
/// - 交互 TTY：回显 + y/N 确认；
/// - 非交互（脚本/管道）：明确报错提示改用显式路径重试；
/// - 默认发行版不可探测 → 明确报错。
fn resolve_wsl_rule_dir(
    project_dir: &str,
    interactive: bool,
    input: &mut dyn std::io::BufRead,
) -> Option<String> {
    // 默认发行版不可探测 → 明确报错（绝不静默失败/静默错配）
    let Some(distro) = detect_default_wsl_distro() else {
        eprintln!(
            "lk rule add: 无法探测 WSL 默认发行版（reg.exe 不可用或未安装 WSL）；\
             请显式指定规范形路径重试：\n  lk rule add wsl://<发行版>{project_dir} ..."
        );
        return None;
    };
    confirm_wsl_candidate(project_dir, &distro, interactive, input)
}

/// 跨命名空间折算候选的统一回显确认（探测/折算与确认分离，便于测试）：
/// 交互 TTY 回显说明行 + y/N 确认；非交互（脚本/管道）明确报错提示改用
/// 显式路径重试（防脚本静默错配）；拒绝/EOF → None。`line` 为折算说明
/// （含候选形态），`candidate` 用于确认通过后的返回值与重试提示。
fn ask_rule_confirm(
    line: &str,
    candidate: &str,
    interactive: bool,
    input: &mut dyn std::io::BufRead,
) -> Option<String> {
    if !interactive {
        eprintln!(
            "lk rule add: {line}\n\
             当前为非交互环境，无法回显确认（防脚本静默错配）；请改用显式路径重试：\n  \
             lk rule add {candidate} ..."
        );
        return None;
    }
    eprintln!("{line}");
    eprint!("确认将该目录入库？(y/N) ");
    let _ = std::io::stderr().flush();
    let mut ans = String::new();
    if input.read_line(&mut ans).ok()? == 0 {
        return None; // EOF（输入关闭）→ 视为拒绝
    }
    match ans.trim() {
        "y" | "Y" | "yes" | "Yes" => Some(candidate.to_string()),
        _ => {
            eprintln!("lk rule add: 已取消；请改用显式路径重试：\n  lk rule add {candidate} ...");
            None
        }
    }
}

/// 已知默认发行版时的候选拼装 + 回显确认（探测与确认分离，便于测试）。
fn confirm_wsl_candidate(
    project_dir: &str,
    distro: &str,
    interactive: bool,
    input: &mut dyn std::io::BufRead,
) -> Option<String> {
    let candidate = wsl_candidate(project_dir, distro)?;
    ask_rule_confirm(
        &format!("「{project_dir}」已按 WSL 默认发行版解析为：{candidate}"),
        &candidate,
        interactive,
        input,
    )
}

/// drvfs 目录折算确认：回显 `POSIX → Windows` 转换结果（与运行时 cwd 同
/// 命名空间），确认语义与 wsl 候选一致（交互 y/N；非交互明确报错）。
fn confirm_windows_candidate(
    project_dir: &str,
    win: &str,
    interactive: bool,
    input: &mut dyn std::io::BufRead,
) -> Option<String> {
    ask_rule_confirm(
        &format!("「{project_dir}」为 Windows 挂载目录（drvfs），折算为 {project_dir} → {win}"),
        win,
        interactive,
        input,
    )
}

/// 拼候选规范形 `wsl://<distro>/<rest>`（rest 取自以 `/` 开头的原始输入，
/// 去尾斜杠；根 `/` → `wsl://<distro>/`）。
fn wsl_candidate(project_dir: &str, distro: &str) -> Option<String> {
    let trimmed = project_dir.trim_end_matches('/');
    if trimmed.is_empty() {
        Some(format!("wsl://{distro}/"))
    } else {
        Some(format!("wsl://{distro}{trimmed}"))
    }
}

/// bridge 后端下 rule.add 的 drvfs 折算（cross-subsystem.md §7.4）：drvfs
/// 目录（/mnt/<单盘符>/…）→ Windows 绝对路径形态（与 interop bridge 进程
/// 继承的 PEB cwd 同命名空间，精确匹配）；其余 POSIX 路径 → None（调用方按
/// wsl:// 默认发行版折算）。
fn drvfs_rule_windows_form(posix: &str) -> Option<String> {
    bridge_backend::to_windows_path(std::path::Path::new(posix))
}

/// Windows 盘符绝对路径形态（`X:\…` / `X:/…`）判定（bridge 后端下 rule.add
/// 直通入口用；不识别相对路径、无盘符形态与 wsl:// 规范形）。
fn is_windows_abs(raw: &str) -> bool {
    let b = raw.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// bridge 后端下显式 Windows 绝对路径直通：`X:\…` / `X:/…` 输入跳过本地
/// fs canonicalize 与 wsl 解析守卫，原样返回送守护进程（Windows 侧校验入库，
/// 非交互可直录 drvfs 规则）；本地后端 / 非 Windows 形态 → None（维持既有
/// 解析路径不变）。
fn bridge_windows_abs_passthrough(project_dir: &str, bridge_mode: bool) -> Option<String> {
    if bridge_mode && is_windows_abs(project_dir) {
        Some(project_dir.to_string())
    } else {
        None
    }
}

/// 探测 WSL 默认发行版（cross-subsystem.md §7.4）。
///
/// 依据：WSL 把默认发行版登记在注册表
/// `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss` 的
/// `DefaultDistribution` 值（= 子键 GUID），该子键的 `DistributionName`
/// 即发行版名。经系统自带 `reg.exe` 查询实现（不引第三方依赖）；在 WSL 内
/// 运行时经 interop 调用同一 Windows 侧 reg.exe，同样可探测。非 Windows、
/// 未装 WSL（Lxss 键缺失）或查询失败 → `None`。
fn detect_default_wsl_distro() -> Option<String> {
    use std::process::Command;
    let lxss = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss";
    let out = Command::new("reg")
        .args(["query", lxss, "/v", "DefaultDistribution"])
        .output()
        .ok()?;
    let guid = parse_reg_value(&String::from_utf8_lossy(&out.stdout), "DefaultDistribution")?;
    let out = Command::new("reg")
        .args([
            "query",
            &format!("{lxss}\\{guid}"),
            "/v",
            "DistributionName",
        ])
        .output()
        .ok()?;
    parse_reg_value(&String::from_utf8_lossy(&out.stdout), "DistributionName")
}

/// 从 `reg query <key> /v <name>` 输出取含 `<name>` 的行的最后一个空白
/// 分隔 token（即值；容忍 reg 输出的对齐空白与 UTF-16 混排噪声行）。
fn parse_reg_value(output: &str, name: &str) -> Option<String> {
    output
        .lines()
        .find(|l| l.contains(name))?
        .split_whitespace()
        .last()
        .map(String::from)
}

/// `lk rule list`：列出规则（最小字段）。
fn cmd_rule_list(out: &mut impl Write, dir: &std::path::Path, json_out: bool) -> i32 {
    match client_for(dir).rule_list() {
        Ok(rules) => {
            if json_out {
                let _ = writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(&rules).unwrap_or_default()
                );
            } else {
                if rules.is_empty() {
                    let _ = writeln!(out, "（无规则。lk rule add <projectDir> <command> --name <name> <keys...> 添加）");
                }
                for r in &rules {
                    let _ = writeln!(
                        out,
                        "{}\t{}\t{}\t{}\t{}",
                        r.id,
                        r.name,
                        r.project_dir,
                        r.command,
                        r.keys.join(",")
                    );
                }
            }
            0
        }
        Err(e) => rpc_fail(&e),
    }
}

/// `lk rule remove <id>`：软删除（墓碑；删除随同步传播）。
fn cmd_rule_remove(out: &mut impl Write, dir: &std::path::Path, id: &str, json_out: bool) -> i32 {
    match client_for(dir).rule_remove(id) {
        Ok(_) => {
            let _ = writeln!(out, "已删除规则 {id}（软删除，30 天后硬删）");
            let _ = json_out;
            0
        }
        Err(e) => rpc_fail(&e),
    }
}

/// `lk inject --keys <name...> -- <cmd...>`：三层授权 → 注入子进程 env。
///
/// - 注入的是子进程环境变量（值只进子进程，**绝不进 lk 自身 stdout/日志/审计**）；
/// - 拒绝/超时 → 非零退出码 + 审计留痕（authorization-gate.md §5）。
fn cmd_inject(
    out: &mut impl Write,
    dir: &std::path::Path,
    keys: &[String],
    command: &[String],
) -> i32 {
    if keys.is_empty() {
        eprintln!(
            "lk inject: 需要 --keys <name...> 指名请求的 key（值不可见、名可指名；\
             仅支持 secret 类型条目，login 等其他类型条目不可注入）"
        );
        return 2;
    }
    let command_str = command.join(" ");
    // 不传 starter/cwd：守护进程以 IPC 对端真实 PID 回溯 + 真实 cwd 判定
    // （客户端自报字段一律不信任，伪造 cwd 必须失败）。
    match client_for(dir).authz_evaluate(&command_str, keys) {
        Ok(decision) => {
            if !decision.allowed {
                eprintln!("lk inject: 已拒绝（{}）", reason_text(&decision.reason));
                return 1;
            }
            // 只含被授权 key 的 env（值在此刻才离开守护进程，且只进子进程）
            let env = decision.env;
            if env.is_empty() {
                eprintln!("lk inject: 无可注入的 key（请求的 key 未被授权）");
                return 1;
            }
            let mut child = std::process::Command::new(&command[0]);
            child.args(&command[1..]);
            child.envs(&env);
            match child.status() {
                Ok(status) => {
                    let code = status.code().unwrap_or(1);
                    let _ = out;
                    code
                }
                Err(e) => {
                    eprintln!("lk inject: 启动命令失败：{e}");
                    1
                }
            }
        }
        Err(e) => rpc_fail(&e),
    }
}

/// 拒绝原因 → 用户文案（不泄露库内容；仅反馈请求无法满足）。
/// missing_keys 的指引须保持「不存在」与「存在但类型不可注入」不可区分
/// （防枚举，authz.rs 注释）；指引只描述 --keys 的通用约束。
fn reason_text(reason: &str) -> &'static str {
    match reason {
        "unknown_starter" => "无法确定启动者（进程回溯失败）",
        "no_cwd" => "无法确定工作目录",
        "missing_keys" => {
            "请求的 key 无法满足（不存在或不可注入；--keys 仅可指名 secret \
             类型条目，login/note/file 条目不支持注入，与不存在不另行区分）"
        }
        "rule_corrupt" => "规则库损坏",
        "no_ui" => "无审批界面（未命中规则且桌面端未运行）",
        "rejected" => "用户拒绝",
        "timeout" => "审批超时（默认拒绝）",
        _ => "未获授权",
    }
}

// ---------------------------------------------------------------------------
// 守护进程
// ---------------------------------------------------------------------------

fn cmd_daemon(dir: &std::path::Path) -> i32 {
    lk_daemon::run(dir)
}

// ---------------------------------------------------------------------------
// 测试（WSL 默认发行版解析辅助，cross-subsystem.md §7.4 第 4 条）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod wsl_rule_add_tests {
    use super::*;
    use std::io::BufReader;

    fn confirm_with(input: &str, interactive: bool) -> Option<String> {
        confirm_wsl_candidate(
            "/home/u/p",
            "Debian",
            interactive,
            &mut BufReader::new(input.as_bytes()),
        )
    }

    /// 候选规范形拼接：常规路径 / 尾斜杠 / 根。
    #[test]
    fn wsl_candidate_forms() {
        assert_eq!(
            wsl_candidate("/home/u/p", "Ubuntu-22.04").as_deref(),
            Some("wsl://Ubuntu-22.04/home/u/p")
        );
        assert_eq!(
            wsl_candidate("/home/u/p/", "Debian").as_deref(),
            Some("wsl://Debian/home/u/p")
        );
        assert_eq!(
            wsl_candidate("/", "Debian").as_deref(),
            Some("wsl://Debian/")
        );
    }

    /// reg.exe 输出解析：取含目标值名的行的最后一个 token；
    /// 缺失该行 → None。
    #[test]
    fn reg_value_parsing() {
        let guid_out = "\r\nHKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss\r\n    DefaultDistribution    REG_SZ    {0123abcd-4567-8901-2345-6789abcdef01}\r\n\r\n";
        assert_eq!(
            parse_reg_value(guid_out, "DefaultDistribution").as_deref(),
            Some("{0123abcd-4567-8901-2345-6789abcdef01}")
        );
        let name_out = "\nHKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss\\{0123abcd-4567-8901-2345-6789abcdef01}\n    DistributionName    REG_SZ    Ubuntu-22.04\n";
        assert_eq!(
            parse_reg_value(name_out, "DistributionName").as_deref(),
            Some("Ubuntu-22.04")
        );
        assert_eq!(parse_reg_value(guid_out, "NoSuchValue"), None);
        assert_eq!(parse_reg_value("", "DefaultDistribution"), None);
    }

    /// 交互确认：y/Y/yes 确认；n/空/EOF 拒绝（拒绝不静默入库）。
    #[test]
    fn interactive_confirm_variants() {
        assert_eq!(
            confirm_with("y\n", true).as_deref(),
            Some("wsl://Debian/home/u/p")
        );
        assert!(confirm_with("Y\n", true).is_some());
        assert!(confirm_with("yes\n", true).is_some());
        assert_eq!(confirm_with("n\n", true), None);
        assert_eq!(confirm_with("\n", true), None); // 默认拒绝
        assert_eq!(confirm_with("", true), None); // EOF
    }

    /// 非交互环境：即使输入流给出 y 也必须拒绝（防脚本静默错配）。
    #[test]
    fn non_interactive_never_confirms() {
        assert_eq!(confirm_with("y\n", false), None);
        // 探测失败的兜底（resolve 层）：detect 返回 None → 整体 None，
        // 由调用方报错退出——不产生任何候选入库。
    }

    /// drvfs 折算：/mnt/<盘>/… → Windows 绝对路径形态；非 drvfs（WSL 原生
    /// 路径 / 非盘符挂载）→ None（走 wsl:// 默认发行版折算）。
    #[test]
    fn drvfs_rule_dir_forms() {
        assert_eq!(
            drvfs_rule_windows_form("/mnt/c/Users/u/proj").as_deref(),
            Some(r"C:\Users\u\proj")
        );
        assert_eq!(
            drvfs_rule_windows_form("/mnt/d/Proj").as_deref(),
            Some(r"D:\Proj")
        );
        assert_eq!(drvfs_rule_windows_form("/mnt/c").as_deref(), Some(r"C:\"));
        // 非 drvfs：WSL 原生路径与非盘符挂载都不折算为 Windows 形态
        assert_eq!(drvfs_rule_windows_form("/home/u/p"), None);
        assert_eq!(drvfs_rule_windows_form("/mnt/wsl/docker"), None);
    }

    /// 折算产物与运行时 cwd（canonical 后）同命名空间命中：相等即命中；
    /// 子目录祖先命中与目录边界按 Path 组件语义（Windows 侧 \ 分隔；
    /// Linux 测试宿主用等价 / 写法断言同一逻辑）。
    #[test]
    fn drvfs_rule_matches_windows_cwd() {
        let win = drvfs_rule_windows_form("/mnt/c/Users/u/proj").unwrap();
        let cwd = lk_core::path_ns::canonical_project_dir(r"C:\Users\u\proj");
        assert_eq!(win, cwd);
        assert!(lk_core::authz::project_dir_matches(&win, &cwd));
        // 祖先命中（子目录内 inject）与目录边界（p2 不得命中）
        assert!(lk_core::authz::project_dir_matches(
            &win.replace('\\', "/"),
            "C:/Users/u/proj/sub"
        ));
        assert!(!lk_core::authz::project_dir_matches(
            &win.replace('\\', "/"),
            "C:/Users/u/proj2"
        ));
        // wsl 原生路径不受影响：仍走 wsl:// 规范形并可命中
        let wsl = wsl_candidate("/home/u/p", "Debian").unwrap();
        assert_eq!(wsl, "wsl://Debian/home/u/p");
        let cwd_wsl = lk_core::path_ns::canonical_project_dir(r"\\wsl.localhost\Debian\home\u\p");
        assert!(lk_core::authz::project_dir_matches(&wsl, &cwd_wsl));
    }

    /// Windows 折算确认：交互 y 确认返回 Windows 形态；n/EOF 拒绝；
    /// 非交互即使输入 y 也拒绝（与 wsl 候选语义一致）。
    #[test]
    fn windows_confirm_variants() {
        let confirm = |input: &str, interactive: bool| {
            confirm_windows_candidate(
                "/mnt/c/Users/u/proj",
                r"C:\Users\u\proj",
                interactive,
                &mut BufReader::new(input.as_bytes()),
            )
        };
        assert_eq!(confirm("y\n", true).as_deref(), Some(r"C:\Users\u\proj"));
        assert!(confirm("Y\n", true).is_some());
        assert_eq!(confirm("n\n", true), None);
        assert_eq!(confirm("", true), None); // EOF → 拒绝
        assert_eq!(confirm("y\n", false), None); // 非交互永不确认
    }

    /// Windows 盘符绝对路径形态判定（bridge 直通入口）：X:\… / X:/… 识别；
    /// 相对路径 / 无盘符 / wsl:// 规范形不识别。
    #[test]
    fn windows_abs_detection() {
        assert!(is_windows_abs(r"C:\Users\u\proj"));
        assert!(is_windows_abs(r"C:/Users/u/proj"));
        assert!(is_windows_abs(r"c:\x"));
        assert!(is_windows_abs(r"D:\"));
        assert!(!is_windows_abs("/home/u/p"));
        assert!(!is_windows_abs("relative/path"));
        assert!(!is_windows_abs("C:foo"));
        assert!(!is_windows_abs("wsl://Debian/home/u/p"));
        assert!(!is_windows_abs(""));
    }

    /// bridge 后端下显式 Windows 绝对路径直通：原样返回（跳过本地
    /// canonicalize / wsl 解析守卫，由 Windows 侧校验入库）；本地后端该输入
    /// 行为不变（None → 走既有解析路径，Linux 上 canonicalize 失败报错）。
    #[test]
    fn bridge_windows_abs_passthrough_forms() {
        assert_eq!(
            bridge_windows_abs_passthrough(r"C:\Users\u\proj", true).as_deref(),
            Some(r"C:\Users\u\proj") // 原样直通，不做本地解析
        );
        assert_eq!(
            bridge_windows_abs_passthrough(r"C:/Users/u/proj", true).as_deref(),
            Some(r"C:/Users/u/proj")
        );
        // 本地后端（bridge_mode=false）：行为不变，不直通
        assert_eq!(
            bridge_windows_abs_passthrough(r"C:\Users\u\proj", false),
            None
        );
        // 非 Windows 形态在 bridge 下也不直通
        assert_eq!(bridge_windows_abs_passthrough("/home/u/p", true), None);
        assert_eq!(
            bridge_windows_abs_passthrough("wsl://Debian/home/u/p", true),
            None
        );
    }
}

// ---------------------------------------------------------------------------
// 测试（补充拍板 #14：桥模式下配置命令直写 Windows 侧 config.json）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod config_bridge_tests {
    use super::*;
    use std::path::Path;

    fn bridge_target(data_dir: Option<PathBuf>) -> bridge_backend::BridgeTarget {
        bridge_backend::BridgeTarget {
            exe: PathBuf::from("/mnt/c/Users/alice/AppData/Local/LightKey/lk.exe"),
            data_dir,
            dir_arg: Some("C:\\Users\\alice\\AppData\\Roaming\\lightkey".into()),
        }
    }

    #[test]
    fn config_dir_local_unchanged() {
        let local = tempfile::tempdir().unwrap();
        assert_eq!(
            config_dir_for(&bridge_backend::Decision::Local, local.path())
                .unwrap()
                .as_path(),
            local.path()
        );
    }

    #[test]
    fn config_dir_bridge_uses_windows_data_dir() {
        let win = PathBuf::from("/mnt/c/Users/alice/AppData/Roaming/lightkey");
        let d = config_dir_for(
            &bridge_backend::Decision::Bridge(bridge_target(Some(win.clone()))),
            Path::new("/tmp/local"),
        )
        .unwrap();
        assert_eq!(d, win);
    }

    #[test]
    fn config_dir_bridge_without_data_dir_fails_closed() {
        let r = config_dir_for(
            &bridge_backend::Decision::Bridge(bridge_target(None)),
            Path::new("/tmp/local"),
        );
        assert!(
            r.is_err(),
            "bridge 模式数据目录不可定位必须报错，绝不读本地文件"
        );
    }

    #[test]
    fn config_dir_fatal_fails_closed() {
        assert!(config_dir_for(
            &bridge_backend::Decision::Fatal("探测失败".into()),
            Path::new("/tmp/local")
        )
        .is_err());
    }

    /// 桥模式下 config sync set 写到 Windows 目录：以 Windows 数据目录为
    /// cfg_dir 调用（映射由 config_dir_for 单测覆盖），断言配置落盘且可被
    /// 守护进程同构解析；原子写无 .tmp 残留。
    #[test]
    fn config_sync_set_writes_to_windows_dir_atomically() {
        let win = tempfile::tempdir().unwrap();
        let mut out = Vec::new();
        let code = cmd_config_sync_set(
            &mut out,
            win.path(),
            "file:///tmp/store",
            None,
            None,
            false,
            false,
        );
        assert_eq!(code, 0);
        let raw = std::fs::read_to_string(win.path().join(daemon::config::CONFIG_FILE)).unwrap();
        let parsed: daemon::Config = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.sync.expect("sync 已配置").url, "file:///tmp/store");
        assert!(
            !win.path().join("config.json.tmp").exists(),
            "原子写必须无 .tmp 残留"
        );
    }

    /// 桥模式下 get 读回与 set 一致。
    #[test]
    fn config_get_reads_back_windows_dir() {
        let win = tempfile::tempdir().unwrap();
        let mut out = Vec::new();
        assert_eq!(
            cmd_config_sync_set(
                &mut out,
                win.path(),
                "file:///tmp/store",
                None,
                None,
                false,
                false,
            ),
            0
        );
        let mut out = Vec::new();
        let code = cmd_config_get(&mut out, win.path(), "sync.url", false);
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8(out).unwrap(), "file:///tmp/store\n");
    }

    /// 本地模式不受影响：写本地目录，且不触碰其他目录。
    #[test]
    fn local_mode_writes_local_dir_unaffected() {
        let local = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let mut out = Vec::new();
        let code = cmd_config_sync_set(
            &mut out,
            local.path(),
            "file:///tmp/store",
            None,
            None,
            false,
            false,
        );
        assert_eq!(code, 0);
        assert!(local.path().join(daemon::config::CONFIG_FILE).is_file());
        assert!(!other.path().join(daemon::config::CONFIG_FILE).exists());
    }
}

// ---------------------------------------------------------------------------
// 测试（错误呈现层：RpcError 变体 → 中文文案，措辞钉死）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod rpc_fail_text_tests {
    use super::*;

    /// 业务变体 → 文案逐字一致（与重构前「错误码→文案」映射对齐）。
    #[test]
    fn business_variant_texts() {
        assert_eq!(
            rpc_fail_text(&RpcError::VaultInvalid),
            "解锁失败：主密码错误或库未初始化"
        );
        assert_eq!(
            rpc_fail_text(&RpcError::SessionInvalid),
            "库未解锁或会话已失效，请先运行 lk unlock"
        );
        assert_eq!(
            rpc_fail_text(&RpcError::ItemConflict),
            "条目已被其他设备修改（CAS 冲突），请刷新后重试"
        );
        assert_eq!(rpc_fail_text(&RpcError::ItemNotFound), "条目不存在");
        assert_eq!(
            rpc_fail_text(&RpcError::Limit {
                detail: "附件 > 50MB".into()
            }),
            "超出限制：附件 > 50MB"
        );
        assert_eq!(
            rpc_fail_text(&RpcError::RateLimited {
                retry_after_seconds: 30
            }),
            "尝试过于频繁，请在 30 秒后重试"
        );
        assert_eq!(
            rpc_fail_text(&RpcError::VaultExists),
            "库已存在（如需重置请使用 lk init --force，旧数据不可恢复）"
        );
        assert_eq!(
            rpc_fail_text(&RpcError::WeakPassword),
            "主密码至少 8 位（建库/恢复时校验）"
        );
    }

    /// 同步 / bridge 变体：detail 空与非空两种形态。
    #[test]
    fn sync_and_bridge_variant_texts() {
        assert_eq!(
            rpc_fail_text(&RpcError::SyncNotConfigured { detail: "".into() }),
            "未配置同步存储，请先运行 lk config sync set <url>"
        );
        assert_eq!(
            rpc_fail_text(&RpcError::SyncNotConfigured { detail: "x".into() }),
            "未配置同步存储，请先运行 lk config sync set <url>（x）"
        );
        assert_eq!(
            rpc_fail_text(&RpcError::SyncStorage {
                detail: "5xx".into()
            }),
            "同步失败（存储端错误）：5xx"
        );
        assert_eq!(
            rpc_fail_text(&RpcError::SyncAnomaly {
                detail: "hmac".into()
            }),
            "同步数据异常：hmac；已放弃本轮，未覆盖本地数据"
        );
        assert_eq!(
            rpc_fail_text(&RpcError::SyncCredentials {
                detail: "钥匙串".into()
            }),
            "同步凭据不可用：钥匙串"
        );
        assert_eq!(
            rpc_fail_text(&RpcError::BridgeNoDaemon { detail: "".into() }),
            "无法连接 Windows 桌面守护实例（bridge.no_daemon）"
        );
        assert_eq!(
            rpc_fail_text(&RpcError::BridgeNoDaemon {
                detail: "缺少 daemon.json（桌面应用未运行？）".into()
            }),
            "无法连接 Windows 桌面守护实例（bridge.no_daemon）：缺少 daemon.json（桌面应用未运行？）"
        );
        assert!(rpc_fail_text(&RpcError::BridgeVersionIncompatible {
            detail: "".into()
        })
        .starts_with(
            "Windows 桌面应用与本 CLI 协议版本不一致（bridge.version_incompatible），请重装 LightKey 桌面应用"
        ));
        assert_eq!(
            rpc_fail_text(&RpcError::BridgeIo {
                detail: "io".into()
            }),
            "bridge 中继失败：io"
        );
    }

    /// 兜底 / 传输 / 响应变体：message + detail 组合。
    #[test]
    fn fallback_transport_response_texts() {
        assert_eq!(
            rpc_fail_text(&RpcError::Other {
                message: "method not found".into(),
                detail: "".into()
            }),
            "method not found"
        );
        assert_eq!(
            rpc_fail_text(&RpcError::Other {
                message: "boom".into(),
                detail: "d".into()
            }),
            "boom（d）"
        );
        assert_eq!(
            rpc_fail_text(&RpcError::Transport {
                message: "无法连接守护进程：no socket".into()
            }),
            "无法连接守护进程：no socket"
        );
        assert_eq!(
            rpc_fail_text(&RpcError::BadResponse {
                message: "空响应".into()
            }),
            "空响应"
        );
    }

    /// classify → 变体 → 文案全链路：错误码 -32006 经 fake data 得到限流文案。
    #[test]
    fn classify_to_text_end_to_end() {
        let err = RpcError::classify(
            -32006,
            "rate.limited".into(),
            Some(&json!({ "retryAfterSeconds": 7 })),
        );
        assert!(matches!(
            err,
            RpcError::RateLimited {
                retry_after_seconds: 7
            }
        ));
        assert_eq!(rpc_fail_text(&err), "尝试过于频繁，请在 7 秒后重试");
    }
}
