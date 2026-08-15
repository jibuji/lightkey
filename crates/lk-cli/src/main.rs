//! LightKey 命令行工具（`lk`）。
//!
//! 命令树与完整语义见 `docs/cli.md`；命令清单：
//!
//! - `lk init` / `lk unlock` / `lk lock` —— 库生命周期与解锁态
//! - `lk item` —— 条目 CRUD（M0）
//! - `lk sync` —— 同步（M1）
//! - `lk rule` / `lk inject` —— Agent 授权门（M2）
//! - `lk audit` —— 审计日志
//! - `lk daemon` —— 常驻守护进程（持解锁态，密钥仅存内存）
//! - `lk status` / `lk config` —— 状态与配置
//!
//! 骨架占位：命令树已声明，全部子命令暂以“未实现”退出；
//! M0 起按 `docs/milestones.md` 逐项实现。CLI 与桌面共享 `lk-core`，
//! 两者都通过守护进程的本地 IPC 访问已解锁库。

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "lk",
    version,
    about = "轻钥 LightKey 命令行工具",
    long_about = "轻钥 LightKey：个人密钥 / 私密信息管理工具。\n\
                  本版本为 M0 骨架占位：命令树已声明，行为将在里程碑中实现（见 docs/milestones.md）。"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 初始化一个新库（设置主密码、生成恢复码/恢复信封）
    Init,
    /// 解锁库并连接守护进程
    Unlock,
    /// 锁定库
    Lock,
    /// 条目管理（增删改查、复制、附件）
    Item,
    /// 同步到 BYO 存储（WebDAV / S3）
    Sync,
    /// Agent 授权门规则管理（add / list / remove）
    Rule,
    /// 给具名命令注入被批准的环境变量（如 `lk inject -- npm publish`）
    Inject,
    /// 查看审计日志
    Audit,
    /// 以守护进程方式常驻（持解锁态，密钥仅存内存）
    Daemon,
    /// 显示守护进程与同步状态
    Status,
    /// 读写本地配置
    Config,
}

fn main() {
    let cli = Cli::parse();
    let name = match &cli.command {
        Command::Init => "init",
        Command::Unlock => "unlock",
        Command::Lock => "lock",
        Command::Item => "item",
        Command::Sync => "sync",
        Command::Rule => "rule",
        Command::Inject => "inject",
        Command::Audit => "audit",
        Command::Daemon => "daemon",
        Command::Status => "status",
        Command::Config => "config",
    };
    eprintln!("lk {name}: 骨架占位——该命令将在对应里程碑中实现（见 docs/milestones.md）");
    std::process::exit(2);
}
