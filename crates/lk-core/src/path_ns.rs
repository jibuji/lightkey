//! projectDir 跨命名空间归一化（规格：`docs/cross-subsystem.md` §7.4；
//! 补充拍板 #14）。
//!
//! WSL 内客户端经 interop 桥连接 Windows 守护实例时，同一项目目录存在两种
//! 命名空间写法：Windows 侧 UNC（`\\wsl.localhost\<distro>\…`）与 Linux 侧
//! `/home/…`。规则入库（`rule.add`）与授权门运行时 cwd 判定**两侧必须过同
//! 一个归一化函数**再做祖先匹配，才能保证跨命名空间匹配语义一致——不存在
//! 「两种写法各录一条规则」，也不给「伪造 cwd 变体绕过」留空间。
//!
//! 规范形：WSL 路径统一为 `wsl://<distro>/<rest>`（rest 内反斜杠转正斜杠、
//! 重复分隔符折叠、去尾斜杠；distro 名保留原样）。其余输入：
//!
//! - `\\?\C:\…` 等 verbatim 盘符前缀 → 剥离为常规 Windows 绝对路径
//!   （维持现状语义）；
//! - `\\?\UNC\<server>\<share>\…` 非 WSL 主机 → 还原标准 UNC 形态
//!   `\\<server>\<share>\…`；
//! - 其余输入**原样返回**（canonicalize 语义不变）。
//!
//! 归一化在守护进程侧执行（对 bridge 传来的 cwd 字符串）；客户端自报值仍不
//! 被信任——判定依据始终是对端进程真实 cwd。

/// WSL 规范形 URL scheme 前缀。
pub const WSL_SCHEME: &str = "wsl://";

/// 把任意写法的项目目录归一为规范形（幂等；见模块文档）。
///
/// 前缀识别大小写不敏感（Windows 文件系统语义）：`\\WSL.localhost\`、
/// `\\Wsl$\` 等变体均识别；distro 名与路径主体保留原样大小写。
pub fn canonical_project_dir(raw: &str) -> String {
    // verbatim UNC：\\?\UNC\<host>\<share>\<rest>
    // （Windows fs::canonicalize 对 UNC 路径的产物形态）
    if let Some(rest) = strip_prefix_ci(raw, r"\\?\UNC\") {
        return match wsl_host_tail(rest) {
            Some(tail) => match split_distro(tail) {
                Some((distro, t)) => wsl_canonical(distro, t),
                // 仅主机名无 distro → 非合法 WSL 形态，原样返回
                None => raw.to_string(),
            },
            // 非 WSL 主机 → 还原标准 UNC 形态
            None => format!(r"\\{rest}"),
        };
    }
    // verbatim 盘符：\\?\C:\… → 剥离前缀，维持常规绝对路径语义
    if let Some(rest) = strip_prefix_ci(raw, r"\\?\") {
        return rest.to_string();
    }
    // 标准 WSL UNC 两种主机名别名
    for prefix in [r"\\wsl.localhost\", r"\\wsl$\"] {
        if let Some(rest) = strip_prefix_ci(raw, prefix) {
            if let Some((distro, tail)) = split_distro(rest) {
                return wsl_canonical(distro, tail);
            }
        }
    }
    // 其余输入（含非 WSL 标准 UNC、相对路径、Linux 路径等）原样返回
    raw.to_string()
}

/// 是否为 `wsl://<distro>/<rest>` 规范形（前缀识别大小写不敏感）。
pub fn is_wsl_canonical(s: &str) -> bool {
    strip_prefix_ci(s, WSL_SCHEME).is_some()
}

/// 是否为**合法**的 `wsl://<distro>[/<rest>]` 规范形（入库校验用；
/// cross-subsystem.md §7.4「仅接受该形态本身」）：
///
/// - distro 段非空且不含 `\`（规范形分隔符一律 `/`）；
/// - rest 各段非空（不允许 `//`、不以 `/` 结尾——[`wsl_canonical`] 的产物
///   除 distro 根 `wsl://<distro>/` 外无尾斜杠）。
pub fn is_valid_wsl_canonical(s: &str) -> bool {
    let Some(rest) = strip_prefix_ci(s, WSL_SCHEME) else {
        return false;
    };
    let mut segs = rest.split('/');
    // split 恒产出至少一段；distro 段即首段
    let distro = segs.next().unwrap_or("");
    if distro.is_empty() || distro.contains('\\') {
        return false;
    }
    // 剩余段全部非空；仅允许恰好一个空尾段（distro 根形态 `wsl://<distro>/`）
    let tail: Vec<&str> = segs.collect();
    match tail.as_slice() {
        [] => true,   // wsl://<distro>
        [""] => true, // wsl://<distro>/（规范根形态）
        segs => segs.iter().all(|p| !p.is_empty()),
    }
}

/// wsl:// 规范形的祖先匹配：`cwd` 等于 `project_dir` 或为其按目录组件的
/// 前缀。比较大小写不敏感（NTFS 默认语义；distro 名保留原样但匹配不区分），
/// 目录边界严格（`…/u/p2` 不命中 `…/u/p`）。两侧均应为规范形
/// （[`canonical_project_dir`] 的产物）。
pub fn wsl_ancestor_matches(project_dir: &str, cwd: &str) -> bool {
    let dir = project_dir.to_ascii_lowercase();
    let cwd = cwd.to_ascii_lowercase();
    // 根形态 `wsl://d/` 折叠为 `wsl://d` 统一处理
    let dir = dir.trim_end_matches('/');
    let cwd = cwd.trim_end_matches('/');
    if cwd == dir {
        return true;
    }
    let mut prefix = dir.to_string();
    prefix.push('/');
    cwd.starts_with(&prefix)
}

/// ASCII 大小写不敏感的前缀剥离（仅用于 ASCII 构成的前缀字面量）。
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len()
        && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
    {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// 识别 WSL UNC 主机段（大小写不敏感）：`wsl.localhost\` / `wsl$\`，
/// 返回其后剩余路径。
fn wsl_host_tail(s: &str) -> Option<&str> {
    [r"wsl.localhost\", r"wsl$\"]
        .iter()
        .find_map(|p| strip_prefix_ci(s, p))
}

/// 拆出 distro 名与其后剩余路径；空串 / 仅分隔符 → `None`（非合法 WSL 形态）。
fn split_distro(rest: &str) -> Option<(&str, &str)> {
    let rest = rest.trim_start_matches(['\\', '/']);
    if rest.is_empty() {
        return None;
    }
    match rest.find(['\\', '/']) {
        Some(i) => Some((&rest[..i], &rest[i + 1..])),
        None => Some((rest, "")),
    }
}

/// 拼 `wsl://<distro>/<rest>` 规范形：`\`→`/`、折叠重复分隔符、去尾斜杠；
/// 无 rest（distro 根）→ `wsl://<distro>/`。
fn wsl_canonical(distro: &str, tail: &str) -> String {
    let normalized: String = tail
        .chars()
        .map(|c| if c == '\\' { '/' } else { c })
        .collect();
    let segs: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    if segs.is_empty() {
        format!("{WSL_SCHEME}{distro}/")
    } else {
        format!("{WSL_SCHEME}{distro}/{}", segs.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{project_dir_matches, rule_matches};
    use crate::model::Rule;

    fn rule(project_dir: &str, command: &str) -> Rule {
        Rule {
            id: uuid::Uuid::new_v4(),
            project_dir: project_dir.into(),
            name: "t".into(),
            command: command.into(),
            keys: vec!["A".into()],
            created: "2026-01-01T00:00:00.000000Z".into(),
        }
    }

    #[test]
    fn passthrough_keeps_existing_semantics() {
        // 其余输入原样返回（canonicalize 语义不变）
        assert_eq!(canonical_project_dir(""), "");
        assert_eq!(canonical_project_dir("/home/u/proj"), "/home/u/proj");
        assert_eq!(canonical_project_dir("relative/path"), "relative/path");
        assert_eq!(canonical_project_dir(r"C:\Users\u\p"), r"C:\Users\u\p");
        // 非 WSL 的标准 UNC 原样返回
        assert_eq!(
            canonical_project_dir(r"\\server\share\x"),
            r"\\server\share\x"
        );
        assert_eq!(
            canonical_project_dir(r"\\?\UNC\server\share\x"),
            r"\\server\share\x"
        );
    }

    /// 合法规范形判定（入库校验用）：distro 段必须非空，rest 无空段；
    /// `wsl://`、`wsl:///etc` 等缺 distro 形态非法（§7.4「仅接受该形态本身」）。
    #[test]
    fn valid_wsl_canonical_gate() {
        for ok in [
            "wsl://Debian/home/u/p",
            "wsl://Debian/",
            "wsl://Debian",
            "WSL://Ubuntu-22.04/root", // 前缀大小写不敏感（与匹配侧一致）
            "wsl://My_Distro/a/b/c",
        ] {
            assert!(is_valid_wsl_canonical(ok), "应合法：{ok}");
        }
        for bad in [
            "wsl://",
            "wsl:///",
            "wsl:///etc",       // 空 distro
            "wsl://Debian//x",  // 空段
            "wsl://Debian/x/",  // 非根尾斜杠
            "wsl://Deb\\ian/x", // distro 含反斜杠（非规范形分隔符）
            "/home/u/p",
            "",
        ] {
            assert!(!is_valid_wsl_canonical(bad), "应非法：{bad}");
        }
        // canonical_project_dir 的产物全部合法（自洽）
        for raw in [
            r"\\wsl.localhost\Debian\",
            r"\\wsl$\Ubuntu\home\u",
            r"\\?\UNC\wsl.localhost\D\a\b\c",
        ] {
            let c = canonical_project_dir(raw);
            assert!(is_valid_wsl_canonical(&c), "归一化产物应合法：{c}");
        }
    }

    #[test]
    fn verbatim_drive_prefix_is_stripped() {
        assert_eq!(canonical_project_dir(r"\\?\C:\Users\u\p"), r"C:\Users\u\p");
        // 盘符小写同样识别
        assert_eq!(canonical_project_dir(r"\\?\c:\Users\u\p"), r"c:\Users\u\p");
        assert_eq!(canonical_project_dir(r"\\?\D:\"), r"D:\");
    }

    #[test]
    fn unc_forms_map_to_wsl_scheme() {
        assert_eq!(
            canonical_project_dir(r"\\wsl.localhost\Ubuntu\home\u\p"),
            "wsl://Ubuntu/home/u/p"
        );
        // wsl$ 别名
        assert_eq!(
            canonical_project_dir(r"\\wsl$\Ubuntu-22.04\home\u"),
            "wsl://Ubuntu-22.04/home/u"
        );
        // verbatim UNC 包裹的 wsl.localhost
        assert_eq!(
            canonical_project_dir(r"\\?\UNC\wsl.localhost\Debian\root\repo"),
            "wsl://Debian/root/repo"
        );
        // verbatim UNC 包裹的 wsl$ 别名
        assert_eq!(
            canonical_project_dir(r"\\?\UNC\wsl$\Debian\a\b"),
            "wsl://Debian/a/b"
        );
    }

    #[test]
    fn prefixes_are_case_insensitive_and_distro_preserved() {
        // 前缀大写识别；distro 名保留原样
        assert_eq!(
            canonical_project_dir(r"\\WSL.LOCALHOST\debian\tmp"),
            "wsl://debian/tmp"
        );
        assert_eq!(
            canonical_project_dir(r"\\WSL$\My-Distro\SRC"),
            "wsl://My-Distro/SRC"
        );
        assert_eq!(
            canonical_project_dir(r"\\?\UNC\WSL.LOCALHOST\Deb_Ian\home"),
            "wsl://Deb_Ian/home"
        );
    }

    #[test]
    fn trailing_slash_and_duplicate_separators_normalized() {
        assert_eq!(
            canonical_project_dir(r"\\wsl.localhost\Debian\home\u\p\"),
            "wsl://Debian/home/u/p"
        );
        assert_eq!(
            canonical_project_dir(r"\\wsl.localhost\Debian\home\\u\\\p"),
            "wsl://Debian/home/u/p"
        );
        // 正斜杠混用同样折叠
        assert_eq!(
            canonical_project_dir(r"\\wsl.localhost\Debian/home//u"),
            "wsl://Debian/home/u"
        );
        // distro 根（无 rest）
        assert_eq!(
            canonical_project_dir(r"\\wsl.localhost\Debian\"),
            "wsl://Debian/"
        );
        // 幂等
        let once = canonical_project_dir(r"\\wsl.localhost\Debian\home\u\p\");
        assert_eq!(canonical_project_dir(&once), once);
        assert!(is_wsl_canonical(&once));
        assert!(!is_wsl_canonical("/home/u/p"));
    }

    /// 安全用例（cross-subsystem.md §10）：伪造 cwd 变体归一化后必须与规则
    /// 一致匹配——不得因写法不同绕过，也不得越界命中。
    #[test]
    fn forged_cwd_variants_match_rule_after_normalization() {
        let r = rule("wsl://Debian/home/u/p", "*");
        // 大小写变体 + 尾斜杠 + 别名 + verbatim 包裹，全部命中同一规则
        for cwd in [
            r"\\wsl.localhost\DEBIAN\home\u\p\",
            r"\\wsl.localhost\Debian\home\u\p",
            r"\\WSL$\debian\HOME\u\P",
            r"\\?\UNC\wsl.localhost\Debian\home\u\p\sub",
            r"\\?\UNC\wsl$\DEBIAN\home\u\p",
        ] {
            let c = canonical_project_dir(cwd);
            assert!(rule_matches(&r, &c, "npm publish"), "cwd={cwd}");
        }
        // 目录边界 / 不同 distro / 不同层级：不得命中
        for cwd in [
            r"\\wsl.localhost\Debian\home\u\p2",
            r"\\wsl.localhost\Ubuntu\home\u\p",
            r"\\wsl.localhost\Debian\home\u",
        ] {
            let c = canonical_project_dir(cwd);
            assert!(!rule_matches(&r, &c, "npm publish"), "cwd={cwd}");
        }
    }

    /// wsl:// 规范形祖先匹配矩阵（含大小写不敏感与根形态边界）。
    #[test]
    fn wsl_ancestor_matching_matrix() {
        assert!(project_dir_matches("wsl://Debian/h/p", "wsl://Debian/h/p"));
        assert!(project_dir_matches(
            "wsl://Debian/h/p",
            "wsl://DEBIAN/h/p/sub"
        ));
        assert!(project_dir_matches("wsl://Debian/h/p/", "wsl://debian/h/p"));
        assert!(project_dir_matches("wsl://Debian/", "wsl://debian/x/y"));
        assert!(!project_dir_matches(
            "wsl://Debian/h/p",
            "wsl://Debian/h/p2"
        ));
        assert!(!project_dir_matches("wsl://Debian/h/p", "wsl://Ubuntu/h/p"));
        // 一侧非 wsl:// 规范形 → 不走该分支（回退普通 Path 比较）
        assert!(!project_dir_matches("/a/b", "wsl://Debian/a/b"));
    }
}
