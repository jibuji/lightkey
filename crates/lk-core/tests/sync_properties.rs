//! 墓碑收敛属性测试（第一层，`docs/testing.md` §1）：
//!
//! **收敛不变量**：任意多端、任意同步顺序 → 最终所有端条目集合一致
//! （最终一致，`docs/sync.md` §4）；含 30 天硬删后仍收敛（无复活循环）。
//!
//! 实现：3 个客户端副本（同一主密码 = 同一密钥）+ 本地模拟存储
//! （`file://` 同款 [`LocalStorage`]），固定种子随机操作（新建/编辑/删除）
//! 与随机同步顺序，确定性可复现。测试密钥全部在测试内生成（fixture
//! 密钥不进仓库）。

use std::collections::{BTreeMap, BTreeSet};

use lk_core::audit::AuditLog;
use lk_core::crypto::{iso_fmt_for_tests, now_iso, open, seal, test_kdf_params, SealType};
use lk_core::model::{IndexEntry, ItemDraft, Tombstone};
use lk_core::storage::{LocalStorage, StorageBackend, INDEX_KEY};
use lk_core::sync::SyncEngine;
use lk_core::vault::{init_vault_with_params, UnlockedVault};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

const CLIENTS: usize = 3;
const ROUNDS: usize = 8;

fn login_draft(name: &str) -> ItemDraft {
    ItemDraft::Login {
        name: name.into(),
        username: "u".into(),
        password: "p".into(),
        uris: vec![],
        custom: vec![],
    }
}

/// 复制种子 vault 到 dst（同一主密码 → 同一密钥）。
fn copy_vault(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".lk")
            || name == "vault.json"
            || name == "audit.log"
            || name == "recovery.envelope"
        {
            std::fs::copy(entry.path(), dst.join(name)).unwrap();
        }
    }
}

/// 客户端条目集合（id → (revision, deleted, name)）。
fn snapshot(vault: &mut UnlockedVault) -> BTreeMap<Uuid, (String, bool, String)> {
    let mut m = BTreeMap::new();
    for s in vault.list().unwrap() {
        let item = vault.get(s.id).unwrap();
        m.insert(
            s.id,
            (
                item.revision().to_string(),
                item.deleted(),
                item.name().to_string(),
            ),
        );
    }
    m
}

fn future_iso(days: i64) -> String {
    (time::OffsetDateTime::now_utc() + time::Duration::days(days))
        .format(&iso_fmt_for_tests())
        .unwrap()
}

/// 把目录内全部墓碑改写为 `days` 天前（同步引擎硬删裁决注时；
/// 全部经公开 API：读密文 → 解密 → 改时间 → 重密封 → 原子写）。
fn age_all_tombstones(dir: &std::path::Path, vault: &UnlockedVault, days: i64) -> usize {
    let old_ts = (time::OffsetDateTime::now_utc() - time::Duration::days(days))
        .format(&iso_fmt_for_tests())
        .unwrap();
    let mut n = 0usize;
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".tomb.lk") {
            continue;
        }
        let blob = std::fs::read(entry.path()).unwrap();
        let pt = open(
            vault.keys().k_data.as_ref(),
            SealType::Tombstone,
            &name,
            &blob,
        )
        .unwrap();
        let mut tomb: Tombstone = serde_json::from_slice(&pt).unwrap();
        tomb.deleted_at = old_ts.clone();
        let new_blob = seal(
            vault.keys().k_data.as_ref(),
            SealType::Tombstone,
            &name,
            &serde_json::to_vec(&tomb).unwrap(),
        );
        std::fs::write(entry.path(), new_blob).unwrap();
        n += 1;
    }
    n
}

/// 收敛属性测试（确定性循环，避免 Argon2id 拖慢 proptest 主循环）：
/// 随机操作 + 随机同步顺序，多轮后所有端一致；墓碑过期硬删后仍一致。
#[test]
fn multi_client_sync_converges_any_order() {
    // 种子 vault（随机 KDF 参数 + 随机密钥；不落仓库）
    let seed = tempfile::tempdir().unwrap();
    let mut audit = AuditLog::open(seed.path()).unwrap();
    init_vault_with_params(seed.path(), "pw", false, &mut audit, &test_kdf_params()).unwrap();

    let mut dirs = Vec::new();
    let mut vaults: Vec<UnlockedVault> = Vec::new();
    for _ in 0..CLIENTS {
        let dir = tempfile::tempdir().unwrap();
        copy_vault(seed.path(), dir.path());
        vaults.push(UnlockedVault::unlock(dir.path(), "pw").unwrap());
        dirs.push(dir);
    }
    let remote_dir = tempfile::tempdir().unwrap();
    let remote = LocalStorage::new(remote_dir.path().to_path_buf());

    let mut rng = StdRng::seed_from_u64(42);
    let mut ids: Vec<Vec<Uuid>> = vec![Vec::new(); CLIENTS];

    for round in 0..ROUNDS {
        // 每个客户端：随机 0~2 个本地操作（离线语义）
        for c in 0..CLIENTS {
            let mut ops = rng.gen_range(0..=2);
            while ops > 0 {
                ops -= 1;
                match rng.gen_range(0..3) {
                    // 新建
                    0 => {
                        let name = format!("item-{}", rng.gen_range(0..1000));
                        let item = vaults[c].put(None, login_draft(&name), None).unwrap();
                        ids[c].push(item.id());
                    }
                    // 编辑既有（未删除）
                    1 => {
                        if let Some(&id) = ids[c].choose(&mut rng) {
                            if let Ok(cur) = vaults[c].get(id) {
                                if !cur.deleted() {
                                    let name = format!("edit-{}", rng.gen_range(0..1000));
                                    let _ = vaults[c].put(
                                        Some(id),
                                        login_draft(&name),
                                        Some(cur.revision().to_string()),
                                    );
                                }
                            }
                        }
                    }
                    // 软删除
                    _ => {
                        if let Some(&id) = ids[c].choose(&mut rng) {
                            let _ = vaults[c].delete(id);
                        }
                    }
                }
            }
        }
        // 随机顺序全量同步（乱序可能让后同步的变更被先同步者错过——
        // 这正是最终一致的语义；随后补一轮确定性全量同步完成传播）
        let mut order: Vec<usize> = (0..CLIENTS).collect();
        order.shuffle(&mut rng);
        for c in order {
            SyncEngine::new(&remote)
                .run_round(&mut vaults[c], &now_iso())
                .unwrap();
        }
        for v in vaults.iter_mut() {
            SyncEngine::new(&remote).run_round(v, &now_iso()).unwrap();
        }
        // 收敛断言：所有端条目集合一致
        let base = snapshot(&mut vaults[0]);
        for v in vaults.iter_mut().skip(1) {
            assert_eq!(snapshot(v), base, "第 {round} 轮后各端必须一致");
        }
    }

    // 墓碑过期（31 天）+ 全量同步（两遍，保证确认流完成）→ 硬删后仍收敛
    let mut tomb_count = 0usize;
    for (v, d) in vaults.iter_mut().zip(dirs.iter()) {
        tomb_count += age_all_tombstones(d.path(), v, 31);
    }
    assert!(tomb_count > 0, "随机操作应产生至少一个墓碑（硬删路径可测）");
    for _pass in 0..2 {
        for v in vaults.iter_mut() {
            SyncEngine::new(&remote)
                .run_round(v, &future_iso(31))
                .unwrap();
        }
    }
    // 收敛 + 无墓碑残留
    let base = snapshot(&mut vaults[0]);
    for v in vaults.iter_mut().skip(1) {
        assert_eq!(snapshot(v), base, "硬删后各端仍须一致");
    }
    assert!(
        base.iter().all(|(_, (_, deleted, _))| !deleted),
        "硬删后无 deleted 残留"
    );

    // 远端索引与任一端本地索引一致（解密比对）
    let idx = remote.get(INDEX_KEY).unwrap().unwrap();
    let parsed: Vec<IndexEntry> = serde_json::from_slice(
        &open(
            vaults[0].keys().k_data.as_ref(),
            SealType::Index,
            INDEX_KEY,
            &idx.data,
        )
        .unwrap(),
    )
    .unwrap();
    let local: BTreeSet<Uuid> = base.keys().copied().collect();
    let remote_set: BTreeSet<Uuid> = parsed.iter().map(|e| e.id).collect();
    assert_eq!(local, remote_set, "远端索引与收敛后的条目集合一致");
}
