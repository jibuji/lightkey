//! 绑定裁决（M2.98，identity-binding.md §5.2/§5.3/§6；identity 三拆之一，
//! issue #152）：
//!
//! - **绑定裁决比对序**（[`adjudicate_binding`]，§5.2）：先比路径（免
//!   stat/hash）、再比 size（先 stat，免 hash）、一致才哈希比对（走缓存，
//!   元信息一致复用 = O(stat)）；
//! - **审批 finalize 侧重算指纹**（[`recompute_fingerprint`]，§5.3「以新
//!   指纹重新授权」）：不信任客户端上报值，重新 canonicalize + stat +
//!   流式 SHA-256。
//!
//! **begin 与 finalize 共用单一函数**：daemon 侧裁决入口唯一为
//! `Daemon::fingerprint_adjudicate`（`daemon/authz.rs`，内部调本模块
//! [`adjudicate_binding`]）——解锁态 `authz_begin` 与锁定态一体化
//! `authz_finalize_unlock`（issue #140 补裁决）两侧共用同一函数，#140 类
//! 修复面收敛一处。
//!
//! 姊妹模块：[`crate::peer_env`]（对端环境读取）、[`crate::exe_resolve`]
//! （可执行解析 + 指纹缓存）。

use std::path::Path;

use lk_core::authz::FingerprintMismatch;
use lk_core::model::ProgramFingerprint;

use crate::exe_resolve::FingerprintCache;
use crate::peer_env::PeerEnv;

/// 绑定裁决结果（调用方据此决定放行 / 转审批）。
pub enum BindingOutcome {
    /// 候选路径/size/哈希与**某条**绑定规则一致 → 静态放行 + 审计。
    Allowed,
    /// 候选解析成功但指纹不符（路径/size/哈希任一）→ 视同未命中 → NeedsApproval
    /// + 失配展示（当前解析路径 + 8 位哈希摘要）。
    Mismatch(FingerprintMismatch),
    /// 候选无法解析（env 读取失败 / PATH+cwd 全未命中 / canonicalize 失败）→
    /// 视同未命中 → NeedsApproval（不携带失配展示——无可解析路径）。
    Unresolved,
}

/// 绑定规则比对（§5.2 比对序），在已解析出候选路径的前提下裁决：
///
/// 1. **路径**：候选 canonical 路径与绑定规则 `exe_path` 不一致 → 失配（免
///    stat/hash，§5.1「PATH 前置假程序」场景）；
/// 2. **size**：先 `stat`（走缓存计数），与规则 `size` 不符 → 失配（免 hash，§6-3）；
/// 3. **hash**：流式 SHA-256（走缓存，元信息一致复用 = O(stat)），不符 → 失配。
///
/// 规则：对绑定规则集，候选路径**与至少一条**匹配即放行（注入由任一条授权
/// 规则裁定；多条绑定不同 exe 的规则对同一 `command[0]` 各自独立——本命令由
/// 匹配的那条裁定）。
///
/// 花销一次 stat + 一次 hash 的上界（hash 仅在路径与 size 都通过后发生，且
/// 元信息一致时复用缓存哈希）。
pub fn adjudicate_binding(
    peer_env: &dyn PeerEnv,
    pid: u32,
    cwd: &str,
    command: &str,
    bound_fps: &[ProgramFingerprint],
    cache: &mut FingerprintCache,
) -> BindingOutcome {
    if bound_fps.is_empty() {
        return BindingOutcome::Allowed; // 未绑定 → 现状语义
    }
    let Some(path) = crate::exe_resolve::resolve_exe_path(peer_env, pid, cwd, command) else {
        return BindingOutcome::Unresolved;
    };
    // 1. 路径：候选与任一绑定规则路径一致？（Path 平台无关等值）
    if !bound_fps
        .iter()
        .any(|fp| Path::new(&path) == Path::new(&fp.exe_path))
    {
        // 失配展示：当前解析路径 + 8 位哈希摘要（哈希仅为展示而算，属失配
        // 罕见的人机路径，不违背「决策免哈希」——决策在第 1 步已免哈希判失配）。
        return BindingOutcome::Mismatch(mismatch_info(&path, cache));
    }
    // 2. size：stat 候选（缓存计数），与任一绑定规则 size 一致？
    let Some(meta) = cache.stat(&path) else {
        return BindingOutcome::Unresolved; // stat 失败（候选消失/不可读）→ fail-closed
    };
    if !bound_fps.iter().any(|fp| fp.size == meta.size) {
        return BindingOutcome::Mismatch(mismatch_info(&path, cache));
    }
    // 3. hash：流式 SHA-256（缓存；元信息一致复用），与任一绑定规则一致？
    let Some(sha256) = cache.sha256(&path, meta) else {
        return BindingOutcome::Unresolved; // 读取失败 → fail-closed
    };
    if !bound_fps.iter().any(|fp| fp.sha256 == sha256) {
        return BindingOutcome::Mismatch(mismatch_info(&path, cache));
    }
    BindingOutcome::Allowed
}

/// 构造失配展示信息（当前解析路径 + 8 位哈希摘要；不展示完整值）。
fn mismatch_info(path: &Path, cache: &mut FingerprintCache) -> FingerprintMismatch {
    // 展示时有缓存则给摘要，否则留空（安全不泄露完整值）。
    let sha256_short = cache.resolve_sha256_short(path).unwrap_or_default();
    FingerprintMismatch {
        resolved_exe_path: path.to_string_lossy().into_owned(),
        sha256_short,
    }
}

/// 审批 finalize 侧重算指纹（§5.3「以新指纹重新授权」）：**不信任客户端上报
/// 的 sha256/size**，对请求绑定的 exe_path 重新 canonicalize + stat + 流式
/// SHA-256（走缓存，元信息一致复用）。失败（路径不可解析 / 文件不可读）→
/// `None`（调用方据此 fail：无法绑定到不可达的可执行文件）。
///
/// `precompute_threshold`（§6-2，config `fingerprintPrecomputeThresholdBytes`，
/// 缺省 [`crate::exe_resolve::FINGERPRINT_PRECOMPUTE_THRESHOLD`]）：文件大小
/// ≤ 阈值 → 哈希现算并**预热缓存**（= 预计算，锁内一次性、人在场可接受）；
/// 超过阈值 → **惰性**：固化落盘所需的哈希仍现算（fail-closed 不变），但不
/// 预热缓存——首次命中重新全量哈希。阈值只影响缓存预热时机，不改变安全语义。
pub fn recompute_fingerprint(
    exe_path: &str,
    cache: &mut FingerprintCache,
    precompute_threshold: u64,
) -> Option<ProgramFingerprint> {
    let canonical = std::fs::canonicalize(exe_path).ok()?;
    let meta = cache.stat(&canonical)?;
    let sha256 = if meta.size <= precompute_threshold {
        cache.sha256(&canonical, meta)?
    } else {
        cache.hash_uncached(&canonical)?
    };
    Some(ProgramFingerprint {
        exe_path: canonical.to_string_lossy().into_owned(),
        sha256,
        size: meta.size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exe_resolve::{FingerprintCache, MetaSnapshot, FINGERPRINT_PRECOMPUTE_THRESHOLD};
    use std::path::PathBuf;

    /// 阈值语义测试夹具：真实临时文件路径（元信息/哈希由注入的 FakeSource
    /// 决定，文件内容无关）。返回临时目录守卫（须同 scope 持有，防提前删除）
    /// 与 canonical 路径。
    fn fake_exe_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tool.exe");
        std::fs::write(&p, b"fake exe").unwrap();
        let canonical = std::fs::canonicalize(&p).unwrap();
        (dir, canonical)
    }

    /// 假文件源：元信息 + 确定性哈希。
    struct FakeSource {
        meta: MetaSnapshot,
        sha: String,
    }
    impl crate::exe_resolve::FingerprintSource for FakeSource {
        fn stat(&self, _path: &Path) -> Option<MetaSnapshot> {
            Some(self.meta)
        }
        fn hash(&self, _path: &Path) -> lk_core::Result<String> {
            Ok(self.sha.clone())
        }
    }

    fn sha64(c: char) -> String {
        c.to_string().repeat(64)
    }

    /// recompute_fingerprint 阈值语义（§6-2，issue #138）——≤ 阈值：finalize
    /// 现算并**预热缓存**（预计算生效：同 meta 再取复用，不重算）。
    #[test]
    fn recompute_fingerprint_precomputes_within_threshold() {
        let (_dir, path) = fake_exe_path();
        let meta = MetaSnapshot {
            size: 100,
            mtime_nanos: 42,
            file_id: 7,
        };
        let mut cache = FingerprintCache::with_source(Box::new(FakeSource {
            meta,
            sha: sha64('a'),
        }));
        let fp = recompute_fingerprint(
            &path.to_string_lossy(),
            &mut cache,
            FINGERPRINT_PRECOMPUTE_THRESHOLD,
        )
        .expect("可读文件应固化成功");
        assert_eq!(fp.sha256, sha64('a'));
        assert_eq!(fp.size, 100);
        // 预计算生效：缓存已含指纹——同 meta 再取复用，hash_calls 不增
        assert_eq!(cache.sha256(&path, meta), Some(sha64('a')));
        assert_eq!(cache.hash_calls(), 1, "≤ 阈值：固化现算一次，评估复用");
    }

    /// recompute_fingerprint 阈值语义（§6-2）——> 阈值：**惰性**——固化落盘
    /// 所需哈希仍现算（fail-closed 不变），但缓存不预热：首次命中重新全量哈希。
    #[test]
    fn recompute_fingerprint_lazy_above_threshold() {
        let (_dir, path) = fake_exe_path();
        let meta = MetaSnapshot {
            size: FINGERPRINT_PRECOMPUTE_THRESHOLD + 1,
            mtime_nanos: 42,
            file_id: 7,
        };
        let mut cache = FingerprintCache::with_source(Box::new(FakeSource {
            meta,
            sha: sha64('a'),
        }));
        let fp = recompute_fingerprint(
            &path.to_string_lossy(),
            &mut cache,
            FINGERPRINT_PRECOMPUTE_THRESHOLD,
        )
        .expect("> 阈值固化仍现算（落盘 sha256 必需）");
        assert_eq!(fp.sha256, sha64('a'));
        assert_eq!(fp.size, FINGERPRINT_PRECOMPUTE_THRESHOLD + 1);
        assert_eq!(cache.hash_calls(), 1, "固化哈希现算一次");
        // 缓存冷态：同 meta 再取须重算（预计算未发生）
        assert_eq!(cache.sha256(&path, meta), Some(sha64('a')));
        assert_eq!(cache.hash_calls(), 2, "> 阈值：缓存未预热，首次命中重算");
    }

    /// 阈值边界与自定义配置语义：size == 阈值（≤ 含等于）→ 预热；阈值 0
    /// （config 可设）→ 全部惰性。
    #[test]
    fn recompute_fingerprint_threshold_boundary_and_custom() {
        let (_dir, path) = fake_exe_path();
        let meta = MetaSnapshot {
            size: 100,
            mtime_nanos: 42,
            file_id: 7,
        };
        // size == 阈值 → 预热（≤ 边界含等于）
        let mut cache = FingerprintCache::with_source(Box::new(FakeSource {
            meta,
            sha: sha64('a'),
        }));
        let _ = recompute_fingerprint(&path.to_string_lossy(), &mut cache, 100).unwrap();
        assert_eq!(cache.hash_calls(), 1);
        assert_eq!(
            cache.sha256(&path, meta),
            Some(sha64('a')),
            "size == 阈值应预热（≤ 含等于）"
        );
        assert_eq!(cache.hash_calls(), 1);
        // 自定义阈值 0 → 全部惰性（缓存不预热）
        let mut cache0 = FingerprintCache::with_source(Box::new(FakeSource {
            meta,
            sha: sha64('a'),
        }));
        let _ = recompute_fingerprint(&path.to_string_lossy(), &mut cache0, 0).unwrap();
        assert_eq!(cache0.sha256(&path, meta), Some(sha64('a')));
        assert_eq!(cache0.hash_calls(), 2, "阈值 0：全部惰性，首次命中重算");
    }

    /// 恒失败文件源（预计算失败路径：stat/hash 不可达）。
    struct UnreadableSource;
    impl crate::exe_resolve::FingerprintSource for UnreadableSource {
        fn stat(&self, _path: &Path) -> Option<MetaSnapshot> {
            None
        }
        fn hash(&self, _path: &Path) -> lk_core::Result<String> {
            Err(lk_core::Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unreadable",
            )))
        }
    }

    /// 预计算失败不影响 finalize 既有语义（fail-closed 保持）：文件不可读 →
    /// `None`（调用方判失败），不 panic、不改变错误形态。
    #[test]
    fn recompute_fingerprint_failure_stays_fail_closed() {
        // stat 失败（候选不可读）→ None
        let mut cache = FingerprintCache::with_source(Box::new(UnreadableSource));
        assert_eq!(
            recompute_fingerprint("/bin/tool", &mut cache, FINGERPRINT_PRECOMPUTE_THRESHOLD),
            None,
            "stat 不可读 → None（fail-closed）"
        );
        // hash 失败 → None（阈值两侧同形态）
        struct HashFailsSource;
        impl crate::exe_resolve::FingerprintSource for HashFailsSource {
            fn stat(&self, _path: &Path) -> Option<MetaSnapshot> {
                Some(MetaSnapshot {
                    size: 1,
                    mtime_nanos: 1,
                    file_id: 1,
                })
            }
            fn hash(&self, _path: &Path) -> lk_core::Result<String> {
                Err(lk_core::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "unreadable",
                )))
            }
        }
        let mut cache = FingerprintCache::with_source(Box::new(HashFailsSource));
        assert_eq!(
            recompute_fingerprint("/bin/tool", &mut cache, FINGERPRINT_PRECOMPUTE_THRESHOLD),
            None,
            "≤ 阈值 hash 失败 → None"
        );
        assert_eq!(
            recompute_fingerprint("/bin/tool", &mut cache, 0),
            None,
            "> 阈值 hash 失败 → None"
        );
    }
}
