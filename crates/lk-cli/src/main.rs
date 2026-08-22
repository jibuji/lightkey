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
mod clipboard;

use lk_daemon as daemon;
use lk_daemon::dirs;
use lk_daemon::transport;

use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use lk_core::ipc::*;
use lk_core::model::{CustomField, ItemDraft, ItemSummary};
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
    /// 请求注入的 key 名（agent 已知名字，只是不知道值）
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
// RPC 客户端辅助
// ---------------------------------------------------------------------------

/// 业务错误 → 退出码 1 的统一文案映射。
fn rpc_fail(msg: &str, code: i64, data: Option<&Value>) -> i32 {
    let detail = data
        .and_then(|d| d.get("detail"))
        .and_then(|d| d.as_str())
        .unwrap_or("");
    let text = match code {
        bridge::ERR_BRIDGE_NO_DAEMON => format!(
            "无法连接 Windows 桌面守护实例（bridge.no_daemon）{}",
            if detail.is_empty() { String::new() } else { format!("：{detail}") }
        ),
        bridge::ERR_BRIDGE_VERSION_INCOMPATIBLE => format!(
            "Windows 桌面应用与本 CLI 协议版本不一致（bridge.version_incompatible），请重装 LightKey 桌面应用{}",
            if detail.is_empty() { String::new() } else { format!("：{detail}") }
        ),
        bridge::ERR_BRIDGE_IO => format!(
            "bridge 中继失败{}",
            if detail.is_empty() { String::new() } else { format!("：{detail}") }
        ),
        ERR_VAULT_INVALID => "解锁失败：主密码错误或库未初始化".to_string(),
        ERR_SESSION_INVALID => "库未解锁或会话已失效，请先运行 lk unlock".to_string(),
        ERR_ITEM_CONFLICT => "条目已被其他设备修改（CAS 冲突），请刷新后重试".to_string(),
        ERR_ITEM_NOT_FOUND => "条目不存在".to_string(),
        ERR_LIMIT => format!("超出限制：{detail}"),
        ERR_RATE_LIMITED => {
            let secs = data
                .and_then(|d| d.get("retryAfterSeconds"))
                .and_then(|d| d.as_u64())
                .unwrap_or(0);
            format!("尝试过于频繁，请在 {secs} 秒后重试")
        }
        ERR_VAULT_EXISTS => {
            "库已存在（如需重置请使用 lk init --force，旧数据不可恢复）".to_string()
        }
        ERR_WEAK_PASSWORD => "主密码至少 8 位（建库/恢复时校验）".to_string(),
        ERR_SYNC_NOT_CONFIGURED => format!(
            "未配置同步存储，请先运行 lk config sync set <url>{}",
            if detail.is_empty() {
                String::new()
            } else {
                format!("（{detail}）")
            }
        ),
        ERR_SYNC_STORAGE => format!("同步失败（存储端错误）：{detail}"),
        ERR_SYNC_ANOMALY => {
            format!("同步数据异常：{detail}；已放弃本轮，未覆盖本地数据")
        }
        ERR_SYNC_CREDENTIALS => format!("同步凭据不可用：{detail}"),
        _ => format!(
            "{msg}{}",
            if detail.is_empty() {
                String::new()
            } else {
                format!("（{detail}）")
            }
        ),
    };
    eprintln!("lk: {text}");
    1
}

/// 发送 RPC（按传输后端分流；附带会话令牌）。
///
/// 传输后端选择（cross-subsystem.md §7.2）：`LIGHTKEY_BRIDGE` 显式指定 >
/// 平台默认（WSL 自动探测 bridge，其余本地 UDS）。探测失败分型在
/// [`bridge_backend::decide`] 内完成——「装了连不上」为明确报错，绝不静默
/// 回落本地。
fn rpc(dir: &std::path::Path, method: &str, params: Value) -> Result<Value, i32> {
    match bridge_backend::decide() {
        bridge_backend::Decision::Local => rpc_local(dir, method, params),
        bridge_backend::Decision::Bridge(target) => rpc_via_bridge(target, method, params),
        bridge_backend::Decision::Fatal(msg) => {
            eprintln!("lk: {msg}");
            Err(1)
        }
    }
}

/// local 后端：UDS 直连本机守护实例（现状行为，自动拉起守护进程）。
fn rpc_local(dir: &std::path::Path, method: &str, params: Value) -> Result<Value, i32> {
    let ep = transport::ensure_daemon(dir).map_err(|e| {
        eprintln!("lk: 无法连接守护进程：{e}");
        1
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
    let line = transport::request(&ep, &req.to_string()).map_err(|e| {
        eprintln!("lk: 守护进程通信失败：{e}");
        1
    })?;
    parse_rpc_line(&line)
}

/// bridge 后端：把请求帧经 `lk.exe bridge` 中继到 Windows 桌面守护实例
/// （cross-subsystem.md §5/§7.2）。会话令牌仍只在进程内存/令牌文件流转：
/// Windows 侧守护实例把 token 写在其数据目录（经 drvfs 只读回读），本侧
/// 不新增任何持久化。主密码交互输入逻辑不变（read_secret 不经此路径改动）。
fn rpc_via_bridge(
    target: bridge_backend::BridgeTarget,
    method: &str,
    params: Value,
) -> Result<Value, i32> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut params = params;
    if let Some(dd) = &target.data_dir {
        if let Ok(t) = std::fs::read_to_string(dd.join(daemon::SESSION_TOKEN_FILE)) {
            params["token"] = json!(t.trim());
        }
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
    let mut child = cmd.spawn().map_err(|e| {
        eprintln!(
            "lk: 无法启动 bridge 中继程序（{}）：{e}",
            target.exe.display()
        );
        1
    })?;
    {
        let mut stdin = child.stdin.take().expect("stdin 已声明 piped");
        let frame = req.to_string();
        stdin
            .write_all(frame.as_bytes())
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
            .map_err(|e| {
                eprintln!("lk: 写入 bridge 失败：{e}");
                1i32
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
    let status = child.wait().map_err(|e| {
        eprintln!("lk: 等待 bridge 退出失败：{e}");
        1i32
    })?;
    if !status.success() && line.is_empty() {
        eprintln!("lk: bridge 中继程序异常退出（{}）", status);
        return Err(1);
    }
    while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
        line.pop();
    }
    let line = String::from_utf8(line).map_err(|_| {
        eprintln!("lk: bridge 响应不是合法 UTF-8");
        1
    })?;
    if line.trim().is_empty() {
        eprintln!("lk: bridge 无响应（中继程序异常退出 {}）", status);
        return Err(1);
    }
    parse_rpc_line(&line)
}

/// 解析响应行 → result / 业务错误文案（local 与 bridge 共用）。
fn parse_rpc_line(line: &str) -> Result<Value, i32> {
    let resp: RpcResponse = serde_json::from_str(line).unwrap_or(RpcResponse {
        jsonrpc: "2.0".into(),
        id: Value::Null,
        result: None,
        error: Some(RpcError {
            code: ERR_PARSE,
            message: "响应解析失败".into(),
            data: None,
        }),
    });
    match (resp.result, resp.error) {
        (Some(result), _) => Ok(result),
        (None, Some(err)) => Err(rpc_fail(&err.message, err.code, err.data.as_ref())),
        (None, None) => {
            eprintln!("lk: 空响应");
            Err(1)
        }
    }
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
    match rpc(
        dir,
        M_VAULT_INIT,
        json!({ "masterPassword": pw1, "force": force }),
    ) {
        Ok(res) => {
            let code = res["recoveryCode"].as_str().unwrap_or_default().to_string();
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
        Err(c) => c,
    }
}

fn cmd_unlock(out: &mut impl Write, dir: &std::path::Path, stdin: bool) -> i32 {
    let pw = match read_secret("主密码", stdin) {
        Ok(p) => p,
        Err(c) => return c,
    };
    match rpc(dir, M_VAULT_UNLOCK, json!({ "masterPassword": pw })) {
        Ok(_) => {
            let _ = writeln!(out, "已解锁");
            0
        }
        Err(c) => c,
    }
}

fn cmd_lock(out: &mut impl Write, dir: &std::path::Path) -> i32 {
    match rpc(dir, M_VAULT_LOCK, json!({})) {
        Ok(_) => {
            let _ = writeln!(out, "已锁定（内存密钥已擦除）");
            0
        }
        Err(c) => c,
    }
}

fn cmd_status(out: &mut impl Write, dir: &std::path::Path, json_out: bool) -> i32 {
    // 连接目标可见性（cross-subsystem.md §7.2）：杜绝「以为在操作本地、
    // 实际连着 Windows 真库」的语义模糊。探测分型失败 → 明确报错。
    let on_bridge = match bridge_backend::decide() {
        bridge_backend::Decision::Local => false,
        bridge_backend::Decision::Bridge(_) => true,
        bridge_backend::Decision::Fatal(msg) => {
            eprintln!("lk: {msg}");
            return 1;
        }
    };
    match rpc(dir, M_VAULT_STATUS, json!({})) {
        Ok(res) => {
            let unlocked = res["unlocked"].as_bool().unwrap_or(false);
            let version = res["version"].as_str().unwrap_or_default().to_string();
            let watermark = res["syncWatermark"].as_str().map(|s| s.to_string());
            if json_out {
                let _ = writeln!(
                    out,
                    "{}",
                    json!({ "unlocked": unlocked, "version": version, "syncWatermark": watermark, "target": if on_bridge { "bridge" } else { "local" } })
                );
            } else {
                let sync_line = match daemon::read_config(dir).sync {
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
        Err(c) => c,
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
    match rpc(
        dir,
        M_VAULT_RECOVER,
        json!({ "recoveryCode": code, "newPassword": pw1 }),
    ) {
        Ok(res) => {
            let new_code = res["recoveryCode"].as_str().unwrap_or_default().to_string();
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
        Err(c) => c,
    }
}

// ---------------------------------------------------------------------------
// 条目
// ---------------------------------------------------------------------------

fn cmd_item(out: &mut impl Write, dir: &std::path::Path, cmd: &ItemCommand, json_out: bool) -> i32 {
    match cmd {
        ItemCommand::List => match rpc(dir, M_ITEM_LIST, json!({})) {
            Ok(res) => {
                let items: Vec<ItemSummary> =
                    serde_json::from_value(res["items"].clone()).unwrap_or_default();
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
            Err(c) => c,
        },
        ItemCommand::Get { id } => match rpc(dir, M_ITEM_GET, json!({ "id": id })) {
            Ok(item) => print_item(out, &item, json_out),
            Err(c) => c,
        },
        ItemCommand::Add { kind } => cmd_item_add(out, dir, kind),
        ItemCommand::Edit(args) => cmd_item_edit(
            out,
            dir,
            &args.id,
            &args.fields,
            args.expected_revision.as_deref(),
        ),
        ItemCommand::Delete { id } => match rpc(dir, M_ITEM_DELETE, json!({ "id": id })) {
            Ok(_) => {
                let _ = writeln!(out, "已删除（软删除，30 天后硬删）");
                0
            }
            Err(c) => c,
        },
        ItemCommand::Copy { id, field } => cmd_item_copy(out, dir, id, field),
        ItemCommand::Export { id, output } => match rpc(dir, M_ITEM_EXPORT, json!({ "id": id })) {
            Ok(res) => {
                use base64::Engine as _;
                let data = match res["data"].as_str() {
                    Some(b64) => match base64::engine::general_purpose::STANDARD.decode(b64) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("lk: 附件数据解码失败：{e}");
                            return 1;
                        }
                    },
                    None => {
                        eprintln!("lk: 附件数据缺失");
                        return 1;
                    }
                };
                match std::fs::write(output, &data) {
                    Ok(_) => {
                        let _ =
                            writeln!(out, "已导出到 {}（{} 字节）", output.display(), data.len());
                        0
                    }
                    Err(e) => {
                        eprintln!("lk: 写入失败：{e}");
                        1
                    }
                }
            }
            Err(c) => c,
        },
    }
}

fn print_item(out: &mut impl Write, item: &Value, json_out: bool) -> i32 {
    if json_out {
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(item).unwrap_or_default()
        );
        return 0;
    }
    let id = item["id"].as_str().unwrap_or_default();
    let ty = item["type"].as_str().unwrap_or_default();
    let name = item["name"].as_str().unwrap_or_default();
    let revision = item["revision"].as_str().unwrap_or_default();
    let deleted = item["deleted"].as_bool().unwrap_or(false);
    let _ = writeln!(
        out,
        "{id}  [{ty}] {name}{}",
        if deleted { " [deleted]" } else { "" }
    );
    let _ = writeln!(out, "  revision: {revision}");
    match ty {
        "login" => {
            let _ = writeln!(
                out,
                "  username: {}",
                item["username"].as_str().unwrap_or("")
            );
            let _ = writeln!(
                out,
                "  password: {}",
                item["password"].as_str().unwrap_or("")
            );
            for u in item["uris"].as_array().unwrap_or(&vec![]) {
                let _ = writeln!(out, "  uri: {}", u.as_str().unwrap_or(""));
            }
            for f in item["custom"].as_array().unwrap_or(&vec![]) {
                let _ = writeln!(
                    out,
                    "  custom: {} = {}{}",
                    f["name"].as_str().unwrap_or(""),
                    f["value"].as_str().unwrap_or(""),
                    if f["hidden"].as_bool().unwrap_or(false) {
                        " (hidden)"
                    } else {
                        ""
                    }
                );
            }
        }
        "note" => {
            let _ = writeln!(out, "  content: {}", item["content"].as_str().unwrap_or(""));
        }
        "secret" => {
            let _ = writeln!(out, "  value: {}", item["value"].as_str().unwrap_or(""));
            let _ = writeln!(out, "  purpose: {}", item["purpose"].as_str().unwrap_or(""));
            let _ = writeln!(
                out,
                "  expiresAt: {}",
                item["expiresAt"].as_str().unwrap_or("")
            );
        }
        "file" => {
            let _ = writeln!(out, "  note: {}", item["note"].as_str().unwrap_or(""));
            let _ = writeln!(out, "  size: {} bytes", item["size"].as_u64().unwrap_or(0));
            let _ = writeln!(
                out,
                "  fileType: {}",
                item["fileType"].as_str().unwrap_or("")
            );
            let _ = writeln!(
                out,
                "  attachment: {}",
                item["attachment"].as_str().unwrap_or("")
            );
        }
        _ => {}
    }
    0
}

fn cmd_item_add(out: &mut impl Write, dir: &std::path::Path, kind: &AddKind) -> i32 {
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
    match rpc(dir, M_ITEM_PUT, json!({ "item": draft })) {
        Ok(res) => {
            let item: Value = res["item"].clone();
            let id = item["id"].as_str().unwrap_or_default().to_string();
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
        Err(c) => c,
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

fn cmd_item_edit(
    out: &mut impl Write,
    dir: &std::path::Path,
    id: &str,
    fields: &EditFields,
    expected_revision: Option<&str>,
) -> i32 {
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
    // CAS：缺省先取当前条目（base revision），再整条替换
    let current = match rpc(dir, M_ITEM_GET, json!({ "id": id })) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let ty = current["type"].as_str().unwrap_or_default().to_string();
    let mut draft =
        match ty.as_str() {
            "login" => {
                let custom: Vec<CustomField> =
                    serde_json::from_value(current["custom"].clone()).unwrap_or_default();
                ItemDraft::Login {
                    name: fields.name.clone().unwrap_or_else(|| {
                        current["name"].as_str().unwrap_or_default().to_string()
                    }),
                    username: fields.username.clone().unwrap_or_else(|| {
                        current["username"].as_str().unwrap_or_default().to_string()
                    }),
                    password: fields.password.clone().unwrap_or_else(|| {
                        current["password"].as_str().unwrap_or_default().to_string()
                    }),
                    uris: fields
                        .uris
                        .clone()
                        .map(|u| {
                            u.split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        })
                        .unwrap_or_else(|| {
                            serde_json::from_value(current["uris"].clone()).unwrap_or_default()
                        }),
                    custom,
                }
            }
            "note" => {
                ItemDraft::Note {
                    name: fields.name.clone().unwrap_or_else(|| {
                        current["name"].as_str().unwrap_or_default().to_string()
                    }),
                    content: fields.content.clone().unwrap_or_else(|| {
                        current["content"].as_str().unwrap_or_default().to_string()
                    }),
                }
            }
            "secret" => {
                ItemDraft::Secret {
                    name: fields.name.clone().unwrap_or_else(|| {
                        current["name"].as_str().unwrap_or_default().to_string()
                    }),
                    value: fields.value.clone().unwrap_or_else(|| {
                        current["value"].as_str().unwrap_or_default().to_string()
                    }),
                    purpose: fields.purpose.clone().unwrap_or_else(|| {
                        current["purpose"].as_str().unwrap_or_default().to_string()
                    }),
                    expires_at: fields.expires_at.clone().or_else(|| {
                        serde_json::from_value(current["expiresAt"].clone()).unwrap_or(None)
                    }),
                }
            }
            "file" => {
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
                let attach_id: Option<uuid::Uuid> =
                    serde_json::from_value(current["attachmentId"].clone()).unwrap_or(None);
                ItemDraft::File {
                    name: fields.name.clone().unwrap_or_else(|| {
                        current["name"].as_str().unwrap_or_default().to_string()
                    }),
                    note: fields.note.clone().unwrap_or_else(|| {
                        current["note"].as_str().unwrap_or_default().to_string()
                    }),
                    size: current["size"].as_u64().unwrap_or(0),
                    file_type: current["fileType"].as_str().unwrap_or_default().to_string(),
                    attachment: current["attachment"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    attach_id,
                    file_data,
                }
            }
            _ => {
                eprintln!("lk: 未知条目类型：{ty}");
                return 1;
            }
        };
    // file 替换附件时更新文件名/MIME
    if ty == "file" {
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
    }
    let base_revision = expected_revision
        .map(|r| r.to_string())
        .unwrap_or_else(|| current["revision"].as_str().unwrap_or_default().to_string());
    match rpc(
        dir,
        M_ITEM_PUT,
        json!({ "id": id, "item": draft, "expectedRevision": base_revision }),
    ) {
        Ok(res) => {
            let item: Value = res["item"].clone();
            let _ = writeln!(
                out,
                "已更新: {} (revision {})",
                item["id"].as_str().unwrap_or_default(),
                item["revision"].as_str().unwrap_or_default()
            );
            0
        }
        Err(c) => c,
    }
}

fn cmd_item_copy(out: &mut impl Write, dir: &std::path::Path, id: &str, field: &str) -> i32 {
    let item = match rpc(dir, M_ITEM_GET, json!({ "id": id })) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let ty = item["type"].as_str().unwrap_or_default();
    let value = match (ty, field) {
        ("login", "username") => item["username"].as_str(),
        ("login", "password") => item["password"].as_str(),
        ("note", "content") => item["content"].as_str(),
        ("secret", "value") => item["value"].as_str(),
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
    let res = match rpc(dir, M_AUDIT_LIST, json!({ "limit": tail })) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let events: Vec<lk_core::audit::AuditEvent> =
        serde_json::from_value(res["events"].clone()).unwrap_or_default();
    let total = res["total"].as_u64().unwrap_or(0);
    if json_out {
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&events).unwrap_or_default()
        );
    } else {
        let _ = writeln!(
            out,
            "审计事件（共 {total} 条{}）",
            tail.map(|t| format!("，显示最近 {t}")).unwrap_or_default()
        );
        for e in &events {
            let result = serde_json::to_string(&e.result).unwrap_or_default();
            let _ = writeln!(out, "{}  {}  {}  {}", e.ts, e.command, result, e.starter);
        }
    }
    if verify {
        match rpc(dir, M_AUDIT_VERIFY, json!({})) {
            Ok(res) => {
                let verified = res["verified"].as_u64().unwrap_or(0);
                if json_out {
                    let _ = writeln!(out, "{}", json!({ "verified": verified }));
                } else {
                    let _ = writeln!(out, "HMAC 链校验：{} 条事件验证通过", verified);
                }
            }
            Err(c) => return c,
        }
    }
    0
}

// ---------------------------------------------------------------------------
// 同步 / 配置（M1）
// ---------------------------------------------------------------------------

/// `lk sync`：触发一轮同步（轮询 + CAS 上传），返回变更摘要。
fn cmd_sync(out: &mut impl Write, dir: &std::path::Path, json_out: bool) -> i32 {
    match rpc(dir, M_SYNC_TRIGGER, json!({})) {
        Ok(res) => {
            let summary: lk_core::sync::SyncSummary =
                serde_json::from_value(res).unwrap_or_default();
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
        Err(c) => c,
    }
}

/// `lk config` 入口。
fn cmd_config(
    out: &mut impl Write,
    dir: &std::path::Path,
    cmd: &ConfigCommand,
    json_out: bool,
) -> i32 {
    match cmd {
        ConfigCommand::Sync { command } => match command {
            ConfigSyncCommand::Set {
                url,
                interval,
                credentials_file,
                stdin,
            } => cmd_config_sync_set(
                out,
                dir,
                url,
                *interval,
                credentials_file.as_deref(),
                *stdin,
                json_out,
            ),
        },
        ConfigCommand::Get { key } => cmd_config_get(out, dir, key, json_out),
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
    // 写配置（原子；守护进程下一轮自动热更新）
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
/// projectDir 规范化（解析符号链接）后入库；以 `/` 开头且非现存本机路径时
/// 解析为 `wsl://<默认发行版>/…` 并回显确认（cross-subsystem.md §7.4）。
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
    let canonical = match std::fs::canonicalize(project_dir) {
        Ok(c) => c.to_string_lossy().to_string(),
        Err(_) if project_dir.starts_with('/') && !std::path::Path::new(project_dir).exists() => {
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
    };
    match rpc(
        dir,
        M_RULE_ADD,
        json!({
            "projectDir": canonical,
            "name": name,
            "command": command,
            "keys": keys,
            "channel": "cli",
        }),
    ) {
        Ok(res) => {
            let rule: lk_core::model::Rule = serde_json::from_value(res["rule"].clone())
                .unwrap_or_else(|_| lk_core::model::Rule {
                    id: uuid::Uuid::nil(),
                    project_dir: canonical,
                    name: name.to_string(),
                    command: command.to_string(),
                    keys: keys.to_vec(),
                    created: String::new(),
                });
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
        Err(c) => c,
    }
}

/// 解析「以 `/` 开头且非现存本机路径」的 WSL 项目目录（cross-subsystem.md
/// §7.4 第 4 条）：`<path>` → `wsl://<默认发行版><path>`，回显解析结果要求
/// 确认（默认发行版歧义显式化，防静默错配）。
///
/// - 交互 TTY：回显 + y/N 确认；
/// - 非交互（脚本/管道）：明确报错提示改用显式路径重试；
/// - 默认发行版不可探测 → 明确报错。
fn resolve_wsl_rule_dir(
    project_dir: &str,
    interactive: bool,
    input: &mut dyn std::io::BufRead,
) -> Option<String> {
    let distro = detect_default_wsl_distro()?;
    confirm_wsl_candidate(project_dir, &distro, interactive, input)
}

/// 已知默认发行版时的候选拼装 + 回显确认（探测与确认分离，便于测试）。
fn confirm_wsl_candidate(
    project_dir: &str,
    distro: &str,
    interactive: bool,
    input: &mut dyn std::io::BufRead,
) -> Option<String> {
    let candidate = wsl_candidate(project_dir, distro)?;
    if !interactive {
        eprintln!(
            "lk rule add: 「{project_dir}」不是现存本机路径，按 WSL 默认发行版解析为 {candidate}。\n\
             当前为非交互环境，无法回显确认（防脚本静默错配）；请改用显式路径重试：\n  \
             lk rule add {candidate} ..."
        );
        return None;
    }
    eprintln!("「{project_dir}」不是现存本机路径，已按 WSL 默认发行版解析为：{candidate}");
    eprint!("确认将该目录入库？(y/N) ");
    let _ = std::io::stderr().flush();
    let mut ans = String::new();
    if input.read_line(&mut ans).ok()? == 0 {
        return None; // EOF（输入关闭）→ 视为拒绝
    }
    match ans.trim() {
        "y" | "Y" | "yes" | "Yes" => Some(candidate),
        _ => {
            eprintln!("lk rule add: 已取消；请改用显式路径重试：\n  lk rule add {candidate} ...");
            None
        }
    }
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
    match rpc(dir, M_RULE_LIST, json!({ "channel": "cli" })) {
        Ok(res) => {
            let rules: Vec<lk_core::model::Rule> =
                serde_json::from_value(res["rules"].clone()).unwrap_or_default();
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
        Err(c) => c,
    }
}

/// `lk rule remove <id>`：软删除（墓碑；删除随同步传播）。
fn cmd_rule_remove(out: &mut impl Write, dir: &std::path::Path, id: &str, json_out: bool) -> i32 {
    match rpc(dir, M_RULE_REMOVE, json!({ "id": id, "channel": "cli" })) {
        Ok(_) => {
            let _ = writeln!(out, "已删除规则 {id}（软删除，30 天后硬删）");
            let _ = json_out;
            0
        }
        Err(c) => c,
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
        eprintln!("lk inject: 需要 --keys <name...> 指名请求的 key（值不可见、名可指名）");
        return 2;
    }
    let command_str = command.join(" ");
    // 不传 starter/cwd：守护进程以 IPC 对端真实 PID 回溯 + 真实 cwd 判定
    // （客户端自报字段一律不信任，伪造 cwd 必须失败）。
    match rpc(
        dir,
        M_AUTHZ_EVALUATE,
        json!({ "command": command_str, "keys": keys, "channel": "cli" }),
    ) {
        Ok(res) => {
            let allowed = res["allowed"].as_bool().unwrap_or(false);
            if !allowed {
                let reason = res["reason"].as_str().unwrap_or("denied");
                eprintln!("lk inject: 已拒绝（{}）", reason_text(reason));
                return 1;
            }
            // 只含被授权 key 的 env（值在此刻才离开守护进程，且只进子进程）
            let env: std::collections::BTreeMap<String, String> =
                serde_json::from_value(res["env"].clone()).unwrap_or_default();
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
        Err(c) => c,
    }
}

/// 拒绝原因 → 用户文案（不泄露库内容；仅反馈请求无法满足）。
fn reason_text(reason: &str) -> &'static str {
    match reason {
        "unknown_starter" => "无法确定启动者（进程回溯失败）",
        "no_cwd" => "无法确定工作目录",
        "missing_keys" => "请求的 key 无法满足（部分 key 不存在或不可注入）",
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
}
