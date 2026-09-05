//! 规则程序指纹（M2.98，identity-binding.md §5/§6）——T1（lk-core）三件核心件：
//!
//! 1. **绑定规则比对序纯函数**（[`fingerprint_matches`]，§5.2）：路径不符 →
//!    免哈希失配；size 不符 → 免哈希失配；否则 SHA-256 比对决定命中/失配。
//!    未绑定（`fingerprint=None`）→ 恒放行（直接按现行逻辑短路，行为零变化）。
//! 2. **`command[0]` → canonical 绝对路径解析**（[`command0`] /
//!    [`exe_candidates`] / [`resolve_exe`]，§5.1）：按 PATH 序解析（第一个
//!    命中项即候选）、绝对路径免解析、PATH 全未命中时 `cwd` 兜底。
//! 3. **流式 SHA-256 工具**（[`sha256_reader`] / [`file_sha256`]，§6）：1 MiB
//!    块读取，大文件不高驻全量内存（峰值缓冲 = 块大小）。
//!
//! T1 边界：解析/比对的**最终执行走 daemon 侧**（信 daemon 不信客户端，读取
//! 对端真实 env 的 PATH——T2 落地）。本模块提供跨平台纯函数与可测试的候选
//! 序/失配门，供 daemon 装配。解析候选路径的 canonicalize 与对端 env PATH
//! 读取由 daemon（T2）承担；size 快速失配门在此纯函数层即可测。

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::model::ProgramFingerprint;
use crate::Result;

/// 流式 SHA-256 块大小（1 MiB，identity-binding.md §6）：决定预计算/重算的
/// 读取缓冲上界，与文件大小无关——大文件不高驻全量内存。
pub const HASH_CHUNK_BYTES: usize = 1024 * 1024;

/// 常见可执行文件后缀（Windows；决议口径 issue #133，cmd 缺省 PATHEXT
/// `.COM;.EXE;.BAT;.CMD` 序）：绑定规则命令形态的 **stem 等价比较**
/// （`lk-core::authz`）与守护进程 PATHEXT **缺省回落**（`lk-daemon`）共用
/// 同一集合。统一小写；后缀检查按大小写不敏感进行（Windows FS 大小写不敏感）。
pub const EXEC_EXTENSIONS: &[&str] = &[".com", ".exe", ".bat", ".cmd"];

// ---------------------------------------------------------------------------
// 1. 绑定规则比对序（§5.2）
// ---------------------------------------------------------------------------

/// 绑定规则比对序纯函数（§5.2）+ 未绑定短路（§4）：
///
/// - 规则**未绑定**（`rule` 为 `None`）→ 恒 `true`（直接按现行逻辑短路，
///   匹配行为零变化；调用方由此决定是否追加指纹裁决）。
/// - 规则**绑定**（`Some`），对已解析出的候选可执行文件 `(candidate_path,
///   candidate_size, candidate_sha256)` 依比对序裁决：
///   1. 路径不一致 → 失配（**免哈希**）；
///   2. size 与记录不符 → 失配（**免哈希**，改内容必改大小的伪装才轮到哈希）；
///   3. 否则 SHA-256 比对 → 一致命中 / 不一致失配（size 同长覆盖场景由哈希
///      兜底）。
///
/// `candidate_path` 应为 canonical 绝对路径（daemon 解析侧产出），与规则
/// `exe_path` 用平台无关的路径相等比较（`Path` 相等=绝对路径标准化后比对）。
pub fn fingerprint_matches(
    rule: Option<&ProgramFingerprint>,
    candidate_path: &str,
    candidate_size: u64,
    candidate_sha256: &str,
) -> bool {
    let Some(fp) = rule else {
        return true; // 未绑定 → 现状语义，短路放行
    };
    // 1. 路径不符 → 免哈希失配
    if Path::new(candidate_path) != Path::new(&fp.exe_path) {
        return false;
    }
    // 2. size 不符 → 免哈希失配
    if candidate_size != fp.size {
        return false;
    }
    // 3. SHA-256 兜底（同长覆盖场景）
    candidate_sha256 == fp.sha256
}

// ---------------------------------------------------------------------------
// 2. command[0] → canonical 绝对路径解析（§5.1）
// ---------------------------------------------------------------------------

/// 命令首词（`command[0]`）：按空白切分的第一个 token（可执行文件/命令名）。
/// 空命令/纯空白 → `None`。
pub fn command0(command: &str) -> Option<&str> {
    command.split_whitespace().next()
}

/// 候选可执行路径，按解析序生成（§5.1），**纯函数不触碰文件系统**：
///
/// - `command[0]` 是绝对路径 → **免 PATH 解析**，唯一候选 = 该路径原样；
/// - 否则每个 PATH 目录拼接 `command[0]`（**候选序可观测**，第一个命中项即
///   候选），**末尾追加 `cwd/command[0]` 兜底**（PATH 全未命中时）。
///
/// `exts` 为可执行文件后缀表（Windows PATHEXT 语义，issue #133）：非绝对命令
/// 在每个目录内按「无扩展原名 → 逐后缀」序展开——`<dir>\npm, <dir>\npm.exe,
/// <dir>\npm.cmd, …`——**目录间仍按 PATH 序**（第一个目录内任一形态命中即
/// 候选，与 cmd 行为一致）；Linux/macOS 传空表（不展开后缀，行为与无 `exts`
/// 完全一致）。解析结果 = 命中项**原样路径**（含后缀——Windows 上 `npm`
/// 解析为 `<dir>\npm.cmd`，调用方无需再自行补全后再 canonicalize）。
///
/// 空命令/纯空白 → 空候选集（调用方按 fail-closed 处理）。
pub fn exe_candidates(
    command: &str,
    path_dirs: &[PathBuf],
    cwd: &Path,
    exts: &[&str],
) -> Vec<PathBuf> {
    let Some(cmd) = command0(command) else {
        return Vec::new();
    };
    let cmd_path = Path::new(cmd);
    if cmd_path.is_absolute() {
        return vec![cmd_path.to_path_buf()];
    }
    let mut out: Vec<PathBuf> =
        Vec::with_capacity(path_dirs.len() * (exts.len() + 1) + exts.len() + 1);
    for d in path_dirs
        .iter()
        .map(|d| d.as_path())
        .chain(std::iter::once(cwd))
    {
        let base = d.join(cmd);
        out.push(base.clone());
        for ext in exts {
            out.push(append_suffix(&base, ext));
        }
    }
    out
}

/// 在文件名字段后追加**无分隔符后缀**（`npm` + `.CMD` → `npm.CMD`；OsString
/// 直拷原始字节，不引入路径分隔符——正是「后缀」而非「子目录」语义）。
fn append_suffix(base: &Path, ext: &str) -> PathBuf {
    let mut os = base.as_os_str().to_os_string();
    os.push(ext);
    PathBuf::from(os)
}

/// 首个被 `exists` 判定的候选解析结果。`exists` 为可执行性判定谓词
/// （is_file / Linux 可执行位）；**Windows 无扩展名命令的后缀探测由 `exts`
/// 候选展开承担**（issue #133，见 [`exe_candidates`]），谓词无需再关心平台
/// 后缀差异。保持本函数平台无关、纯测试可控。「第一个命中项即候选」（§5.1）。
///
/// 语义：按 [`exe_candidates`] 产出的候选序，取**第一个**满足 `exists` 的候选；
/// 全未命中 → `None`（调用方据此 fail-closed 或做 cwd 兜底裁决）。
pub fn resolve_exe(
    command: &str,
    path_dirs: &[PathBuf],
    cwd: &Path,
    exts: &[&str],
    exists: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let candidates = exe_candidates(command, path_dirs, cwd, exts);
    candidates.into_iter().find(|c| exists(c))
}

// ---------------------------------------------------------------------------
// 3. 流式 SHA-256（§6）
// ---------------------------------------------------------------------------

/// 流式 SHA-256：从任意 `Read` 以 1 MiB 块读取并累加哈希，返回 hex（小写）。
/// 任意大小文件**峰值缓冲 = [`HASH_CHUNK_BYTES`]**（不高驻全量内存）。
pub fn sha256_reader(mut r: impl Read) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK_BYTES];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// 文件 SHA-256（hex，小写）：流式读取（1 MiB 块），大文件不高驻全量内存。
pub fn file_sha256(path: &Path) -> Result<String> {
    let f = std::fs::File::open(path)?;
    sha256_reader(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(exe: &str, sha: &str, size: u64) -> ProgramFingerprint {
        ProgramFingerprint {
            exe_path: exe.into(),
            sha256: sha.into(),
            size,
        }
    }

    fn sha64(c: char) -> String {
        c.to_string().repeat(64)
    }

    /// 候选路径父目录名（平台无关的断言辅助）。
    fn parent_name(p: &Path) -> Option<&str> {
        p.parent()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
    }

    // -- 比对序（§5.2）------------------------------------------------------

    /// 未绑定（None）→ 短路恒放行，匹配行为零变化（regression 语义）。
    #[test]
    fn unbound_fingerprint_short_circuits_to_match() {
        assert!(fingerprint_matches(None, "/any/path", 0, ""));
        assert!(fingerprint_matches(None, "/other", 999, "whatever"));
    }

    /// 路径不一致 → 失配且免走哈希（即使提供任意哈希也失配）。
    #[test]
    fn path_mismatch_short_circuits_miss() {
        let rule = fp("/usr/bin/node", &sha64('a'), 100);
        // 候选路径不同 → 失配；哈希即使一致（但本应免比）也按序先失配
        assert!(!fingerprint_matches(
            Some(&rule),
            "/usr/bin/custom-node",
            100,
            &sha64('a')
        ));
    }

    /// size 不符 → 失配且免走哈希。
    #[test]
    fn size_mismatch_short_circuits_miss() {
        let rule = fp("/usr/bin/node", &sha64('a'), 100);
        assert!(!fingerprint_matches(
            Some(&rule),
            "/usr/bin/node",
            101,
            &sha64('a'),
        ));
    }

    /// 路径与 size 均一致 + 哈希一致 → 命中。
    #[test]
    fn hash_match_hits() {
        let rule = fp("/usr/bin/node", &sha64('a'), 100);
        assert!(fingerprint_matches(
            Some(&rule),
            "/usr/bin/node",
            100,
            &sha64('a'),
        ));
    }

    /// 路径与 size 均一致但哈希不一致 → 失配（size 同长覆盖场景由哈希兜底）。
    #[test]
    fn hash_mismatch_misses_when_same_path_size() {
        let rule = fp("/usr/bin/node", &sha64('a'), 100);
        assert!(!fingerprint_matches(
            Some(&rule),
            "/usr/bin/node",
            100,
            &sha64('b'),
        ));
    }

    /// 路径相等按平台无关的 Path 相等比对（尾斜杠/平台分隔符差异不误判）。
    #[test]
    fn path_comparison_tolerates_trailing_separator() {
        #[cfg(windows)]
        let (rule_p, cand_p) = (r"C:\bin\node.exe", r"C:\bin\node.exe");
        #[cfg(not(windows))]
        let (rule_p, cand_p) = ("/usr/bin/node", "/usr/bin/node");
        let rule = fp(rule_p, &sha64('a'), 100);
        assert!(!fingerprint_matches(Some(&rule), cand_p, 100, &sha64('b')));
        assert!(fingerprint_matches(Some(&rule), cand_p, 100, &sha64('a')));
    }

    // -- command[0] 解析（§5.1）---------------------------------------------

    /// 命令首词提取：空白切分。
    #[test]
    fn command0_extracts_first_token() {
        assert_eq!(command0("npm publish"), Some("npm"));
        assert_eq!(
            command0("  /usr/bin/node --version  "),
            Some("/usr/bin/node")
        );
        assert_eq!(command0("node\t--eval x"), Some("node"));
        assert_eq!(command0(""), None);
        assert_eq!(command0("   "), None);
    }

    /// 绝对路径免 PATH 解析：唯一候选 = 该绝对路径原样，无 cwd 兜底追加。
    #[test]
    fn absolute_command_skips_path_and_cwd_fallback() {
        let dirs = vec![PathBuf::from("/p1"), PathBuf::from("/p2")];
        let cwd = PathBuf::from("/cwd");
        // 平台无关的绝对路径：Windows 用盘符前缀，unix 用根前缀。
        #[cfg(windows)]
        let abs = r"C:\tools\node.exe";
        #[cfg(not(windows))]
        let abs = "/usr/bin/node";
        let cands = exe_candidates(abs, &dirs, &cwd, &[]);
        assert_eq!(cands, vec![PathBuf::from(abs)]);
    }

    /// PATH 序候选（可观测）：候选按 PATH 目录序拼接 + cwd 兜底次序；前置假程序
    /// 靠前即候选序靠前，但 ≠ 规则 exePath → 解析命中假程序 → 比对失配。
    #[test]
    fn path_candidate_order_observable_and_prefix_fake_misses() {
        let dirs = vec![
            PathBuf::from("/evil"), // PATH 前置假 `npm`
            PathBuf::from("/usr/bin"),
        ];
        let cwd = PathBuf::from("/cwd");
        let cands = exe_candidates("npm publish", &dirs, &cwd, &[]);
        // 候选序的父目录名 = [evil, usr, cwd]（PATH 序 + cwd 兜底；文件名全是
        // `npm`）。用父目录末分量断言，避免平台分隔符导致字面路径不等。
        let parents: Vec<String> = cands
            .iter()
            .map(|p| {
                p.file_name().unwrap().to_str().unwrap().to_string()
                    + "@"
                    + p.parent().unwrap().file_name().unwrap().to_str().unwrap()
            })
            .collect();
        assert_eq!(parents, vec!["npm@evil", "npm@bin", "npm@cwd"]);

        // 规则绑定的真实程序在 /usr/bin，PATH 前置假程序 /evil/npm 先命中 →
        // resolve 拿到假程序（父目录 evil）→ fingerprint 按路径不符失配（免哈希）。
        let rule = fp("/usr/bin/npm", &sha64('a'), 50);
        let resolved = resolve_exe("npm publish", &dirs, &cwd, &[], |p| {
            // 候选父目录为 `evil`（前置假程序）或 `bin`（真实程序）即视为存在；
            // resolve 取第一个存在项 = 前置假程序。
            parent_name(p) == Some("evil") || parent_name(p) == Some("bin")
        });
        let resolved = resolved.expect("前置假程序应命中");
        // resolve 的是第一个存在项 = 前置假程序（父目录 evil）
        assert_eq!(
            resolved.parent().and_then(|p| p.file_name()),
            Some(std::ffi::OsStr::new("evil")),
        );
        // 候选路径 ≠ 规则 exePath → 未命中（仿 PATH 前置假程序场景）
        assert!(!fingerprint_matches(
            Some(&rule),
            &resolved.to_string_lossy(),
            50,
            &sha64('a'),
        ));

        // 控制组：若前置 PATH 缺假程序，则命中真实规则程序所在（bin）→ 路径
        // 一致 + size/hash 一致 → 命中。
        let resolved2 = resolve_exe("npm publish", &dirs, &cwd, &[], |p| {
            parent_name(p) == Some("bin")
        });
        let resolved2 = resolved2.expect("真实程序应命中");
        assert!(!fingerprint_matches(
            Some(&rule),
            &resolved2.to_string_lossy(),
            50,
            &sha64('b'),
        ));
    }

    /// PATH 全未命中 → cwd 兜底命中。
    #[test]
    fn path_miss_falls_back_to_cwd() {
        let dirs = vec![
            PathBuf::from("/nonexistent1"),
            PathBuf::from("/nonexistent2"),
        ];
        let cwd = PathBuf::from("/proj");
        // PATH 目录不含 `proj`，仅 cwd 兜底候选的父目录为 `proj` → 命中 cwd 候选。
        let resolved = resolve_exe("tool", &dirs, &cwd, &[], |p| {
            p.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("proj"))
        });
        let resolved = resolved.expect("PATH 全未命中应回退 cwd 兜底");
        assert_eq!(resolved.file_name(), Some(std::ffi::OsStr::new("tool")));
        assert_eq!(
            resolved.parent().and_then(Path::file_name),
            Some(std::ffi::OsStr::new("proj")),
        );
        // PATH 全未命中 + cwd 也不存在 → None（fail-closed 边界）
        assert_eq!(resolve_exe("tool", &dirs, &cwd, &[], |_| false), None);
    }

    /// cwd 兜底追加在 PATH 候选之后（兜底语义：PATH 优先）。
    #[test]
    fn cwd_fallback_is_last_candidate() {
        let dirs = vec![PathBuf::from("/p1")];
        let cands = exe_candidates("tool", &dirs, Path::new("/cwd"), &[]);
        let file_names: Vec<String> = cands
            .iter()
            .map(|p| {
                p.file_name().unwrap().to_str().unwrap().to_string()
                    + "@"
                    + p.parent().unwrap().file_name().unwrap().to_str().unwrap()
            })
            .collect();
        assert_eq!(file_names, vec!["tool@p1", "tool@cwd"]);
    }

    /// Windows PATHEXT 候选展开（issue #133）：非绝对命令在每个目录内按
    /// 「无扩展原名 → 逐后缀」序展开，目录间仍按 PATH 序（+ cwd 兜底）——
    /// `<dir>\npm, <dir>\npm.EXE, <dir>\npm.CMD, <next dir>\npm, …`。
    #[test]
    fn exe_candidates_interleaves_extensions_per_directory() {
        let dirs = vec![PathBuf::from("/evil"), PathBuf::from("/bin")];
        let cwd = PathBuf::from("/cwd");
        let exts = [".EXE", ".CMD"];
        let cands = exe_candidates("npm", &dirs, &cwd, &exts);
        // 目录内：无扩展原名先于后缀形态；目录间：PATH 序（evil → bin）+ cwd 兜底
        let names: Vec<String> = cands
            .iter()
            .map(|p| {
                p.file_name().unwrap().to_str().unwrap().to_string()
                    + "@"
                    + p.parent().unwrap().file_name().unwrap().to_str().unwrap()
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "npm@evil",
                "npm.EXE@evil",
                "npm.CMD@evil",
                "npm@bin",
                "npm.EXE@bin",
                "npm.CMD@bin",
                "npm@cwd",
                "npm.EXE@cwd",
                "npm.CMD@cwd",
            ]
        );
        // 空后缀表 → 与展开前完全一致（Linux/macOS 生产形态）
        let plain = exe_candidates("npm", &dirs, &cwd, &[]);
        let plain_names: Vec<String> = plain
            .iter()
            .map(|p| {
                p.file_name().unwrap().to_str().unwrap().to_string()
                    + "@"
                    + p.parent().unwrap().file_name().unwrap().to_str().unwrap()
            })
            .collect();
        assert_eq!(plain_names, vec!["npm@evil", "npm@bin", "npm@cwd"]);
    }

    /// resolve 序（issue #133）：**目录间优先于后缀形态**——前置目录只有
    /// 后缀形态命中（`/evil/npm.CMD`）也先于后置目录的无扩展原名
    /// （`/bin/npm`）；解析结果 = 命中项**原样路径**（含后缀，
    /// `<evil>\npm.CMD` 或平台分隔符变体），调用方直接 canonicalize 即可。
    #[test]
    fn resolve_exe_prefers_first_dir_with_any_extension_form() {
        let dirs = vec![PathBuf::from("/evil"), PathBuf::from("/bin")];
        let cwd = PathBuf::from("/cwd");
        let exts = [".EXE", ".CMD"];
        // 文件形态（纯谓词模拟）：/evil 只有 npm.CMD；/bin 只有 npm（无后缀）
        let exists = |p: &Path| {
            let parent = p
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str());
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            (parent == Some("evil") && name == "npm.CMD")
                || (parent == Some("bin") && name == "npm")
        };
        // 带后缀表：前置目录的 suffix 形态先命中 → /evil/npm.CMD
        let resolved =
            resolve_exe("npm publish", &dirs, &cwd, &exts, exists).expect("前置目录后缀形态应命中");
        assert_eq!(resolved.file_name(), Some(std::ffi::OsStr::new("npm.CMD")));
        assert_eq!(
            resolved.parent().and_then(Path::file_name),
            Some(std::ffi::OsStr::new("evil")),
        );
        // 控制组（无后缀表）：/evil/npm 不存在 → 落到 /bin/npm
        let resolved2 =
            resolve_exe("npm publish", &dirs, &cwd, &[], exists).expect("控制组应命中 /bin/npm");
        assert_eq!(resolved2.file_name(), Some(std::ffi::OsStr::new("npm")));
        assert_eq!(
            resolved2.parent().and_then(Path::file_name),
            Some(std::ffi::OsStr::new("bin")),
        );
    }

    /// 空命令 → 空候选集。
    #[test]
    fn empty_command_yields_no_candidates() {
        assert!(exe_candidates("", &[PathBuf::from("/p")], Path::new("/cwd"), &[]).is_empty());
        assert!(exe_candidates("   ", &[PathBuf::from("/p")], Path::new("/cwd"), &[]).is_empty());
    }

    // -- 流式 SHA-256（§6）---------------------------------------------------

    /// 追踪每次 read 请求的缓冲区大小的读者：断言「大文件不高驻全量」——
    /// 生产流式函数对任意大小文件的**峰值单次读取缓冲 ≤ 块大小**，即它不把
    /// 整个文件一次性读进内存。
    struct TrackingReader<R> {
        inner: R,
        max_buf: usize,
        total_bytes: u64,
    }

    impl<R: Read> TrackingReader<R> {
        fn new(inner: R) -> Self {
            Self {
                inner,
                max_buf: 0,
                total_bytes: 0,
            }
        }
    }

    impl<R: Read> Read for TrackingReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.max_buf = self.max_buf.max(buf.len());
            let n = self.inner.read(buf)?;
            self.total_bytes += n as u64;
            Ok(n)
        }
    }

    /// ≥64 MiB 基准文件：流式哈希内存占有断言（块式读取、不高驻全量）+ 正确性
    /// （与测试内独立累加器算出的预期哈希一致——独立数据源，非复算生产逻辑）。
    #[test]
    fn streaming_hash_of_64mib_file_uses_bounded_chunk_memory() {
        use sha2::{Digest, Sha256};

        const MIB: usize = 1024 * 1024;
        let total = 64 * MIB; // ≥64 MiB 基准
        let block = 4096usize;

        // 独立数据源：确定性字节流（16-字节 LCG u128 块），测试内自行驱动——
        // 生成与独立累加走同一次确定性序列，互不复用生产 hasher 循环。
        // （生成器对象每次 `next` 拿同一缓冲，写文件 / 累加预期哈希都基于它，
        // 保证两次消费同一字节序列。）
        struct Lcg(u64);
        impl Lcg {
            fn new() -> Self {
                Self(0x243F_6A88_85A3_08D3)
            }
            fn block(&mut self, buf: &mut Vec<u8>, block: usize) {
                for _ in 0..block / 8 {
                    self.0 = self
                        .0
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    buf.extend_from_slice(&self.0.to_le_bytes());
                }
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        // 一次确定性序列：写文件 + 独立累加预期哈希（同一 Lcg 实例依次消费）
        let mut expected = Sha256::new();
        let mut tmp = Vec::with_capacity(block);
        {
            use std::io::Write;
            let mut lcg = Lcg::new();
            let mut f = std::fs::File::create(&path).unwrap();
            for _ in 0..total / block {
                tmp.clear();
                lcg.block(&mut tmp, block);
                expected.update(&tmp);
                f.write_all(&tmp).unwrap();
            }
        }
        let expected = hex::encode(expected.finalize());

        // 生产流式哈希读到 TrackingReader，断言峰值缓冲 ≤ 块大小（不高驻全量）
        let file = std::fs::File::open(&path).unwrap();
        let mut tr = TrackingReader::new(file);
        let got = sha256_reader(&mut tr).unwrap();
        assert_eq!(tr.total_bytes as usize, total, "应读到整个 64 MiB");
        assert!(
            tr.max_buf <= HASH_CHUNK_BYTES,
            "单次读取缓冲峰值 {} 应 ≤ 块大小 {}（未把全量读进内存）",
            tr.max_buf,
            HASH_CHUNK_BYTES,
        );
        assert_eq!(got, expected, "流式 hex 与测试独立累加器一致");
    }

    /// file_sha256 小文件正确性（含 `hex` 小写、块边界无关）。
    #[test]
    fn file_sha256_known_vector() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let sha = file_sha256(&path).unwrap();
        let expect = hex::encode(Sha256::digest(b"hello world"));
        assert_eq!(sha, expect);
    }
}
