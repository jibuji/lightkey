//! 同步引擎集成测试（经公共接口驱动；`diff` 为唯一被测内部函数）。

use super::*;

use uuid::Uuid;

use crate::{Error, Result};

use crate::audit::AuditLog;
use crate::crypto::{iso_fmt_for_tests, now_iso, test_kdf_params};
use crate::crypto::{open, seal, Keys, SealType};
use crate::model::{IndexEntry, Item, ObjectKind, Rule, Tombstone};
use crate::model::{ItemDraft, ItemKind};
use crate::storage::LocalStorage;
use crate::storage::{StorageBackend, INDEX_KEY};
use crate::vault::{init_vault_with_params, UnlockedVault};

// 种子 vault（所有客户端副本共享同一主密码 → 同一密钥）。
thread_local! {
    static SEED: std::cell::RefCell<Option<tempfile::TempDir>> =
        const { std::cell::RefCell::new(None) };
}

fn seed_vault() -> &'static tempfile::TempDir {
    SEED.with(|s| {
        let mut s = s.borrow_mut();
        if s.is_none() {
            let dir = tempfile::tempdir().unwrap();
            let mut audit = AuditLog::open(dir.path()).unwrap();
            init_vault_with_params(
                dir.path(),
                "pw123456",
                false,
                &mut audit,
                &test_kdf_params(),
            )
            .unwrap();
            *s = Some(dir);
        }
        // 泄露借用：thread_local 持有的 TempDir 生命周期为 'static 语义
        unsafe {
            std::mem::transmute::<&tempfile::TempDir, &'static tempfile::TempDir>(
                s.as_ref().unwrap(),
            )
        }
    })
}

/// 复制已初始化 vault（同一主密码 = 同一密钥；模拟双客户端）。
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

fn login_draft(name: &str) -> ItemDraft {
    ItemDraft::Login {
        name: name.into(),
        username: "u".into(),
        password: "p".into(),
        uris: vec![],
        custom: vec![],
    }
}

fn unlock(dir: &std::path::Path) -> UnlockedVault {
    UnlockedVault::unlock(dir, "pw123456").unwrap()
}

/// 场景夹具：两个客户端 vault（同密钥）+ 共享远端存储。
struct Fixture {
    #[allow(dead_code)]
    a_dir: tempfile::TempDir,
    #[allow(dead_code)]
    b_dir: tempfile::TempDir,
    #[allow(dead_code)]
    remote_dir: tempfile::TempDir,
}

fn fixture() -> (Fixture, UnlockedVault, UnlockedVault, LocalStorage) {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let remote_dir = tempfile::tempdir().unwrap();
    copy_vault(seed_vault().path(), a_dir.path());
    copy_vault(seed_vault().path(), b_dir.path());
    let a = unlock(a_dir.path());
    let b = unlock(b_dir.path());
    let remote = LocalStorage::new(remote_dir.path().to_path_buf());
    (
        Fixture {
            a_dir,
            b_dir,
            remote_dir,
        },
        a,
        b,
        remote,
    )
}

fn sync(vault: &mut UnlockedVault, remote: &LocalStorage, now: &str) -> SyncSummary {
    SyncEngine::new(remote).run_round(vault, now).unwrap()
}

/// 平台无关的「绝对路径」假值（Windows 下 `/proj` 非绝对，put_rule 校验拒绝）。
fn fake_abs_proj() -> String {
    std::env::temp_dir()
        .join("lk-test-proj")
        .to_string_lossy()
        .to_string()
}

/// 注时：`days` 天后的 ISO（硬删裁决用）。
fn future_iso(days: i64) -> String {
    (time::OffsetDateTime::now_utc() + time::Duration::days(days))
        .format(&iso_fmt_for_tests())
        .unwrap()
}

/// 把条目墓碑时间改写为 `days` 天前（同步引擎硬删裁决注时）。
fn age_tombstone(vault: &mut UnlockedVault, id: Uuid, days: i64) {
    let old = vault
        .tombstones()
        .into_iter()
        .find(|(tid, _)| *tid == id)
        .unwrap()
        .1;
    let old_ts = (time::OffsetDateTime::now_utc() - time::Duration::days(days))
        .format(&iso_fmt_for_tests())
        .unwrap();
    let tomb = Tombstone {
        id,
        deleted_at: old_ts,
        revision: old.revision.clone(),
    };
    let key = format!("{id}.tomb.lk");
    let blob = seal(
        vault.keys().k_data.as_ref(),
        SealType::Tombstone,
        &key,
        &serde_json::to_vec(&tomb).unwrap(),
    );
    vault.import_tomb(&blob, &tomb).unwrap();
}

/// 各客户端条目集合（id → (revision, deleted, name)），断言收敛用。
fn snapshot(vault: &mut UnlockedVault) -> std::collections::BTreeMap<Uuid, (String, bool, String)> {
    let mut m = std::collections::BTreeMap::new();
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

#[test]
fn first_sync_uploads_index_and_items() {
    let (fx, mut a, _b, remote) = fixture();
    let item = a.put(None, login_draft("GitHub"), None).unwrap();
    let s = sync(&mut a, &remote, &now_iso());
    assert_eq!(s.pushed, 1);
    assert!(s.changed);
    // 远端布局：index.lk + 条目密文
    let objs = remote.list().unwrap();
    assert_eq!(objs.len(), 2);
    assert!(objs.iter().any(|o| o.key == INDEX_KEY));
    assert!(objs
        .iter()
        .any(|o| o.key == format!("{}.item.lk", item.id())));
    // 远端只见密文（LKC1 magic）
    for o in &objs {
        let data = remote.get(&o.key).unwrap().unwrap().data;
        assert_eq!(&data[..4], b"LKC1");
    }
    drop(fx);
}

#[test]
fn pull_newer_remote_entry() {
    let (fx, mut a, mut b, remote) = fixture();
    let item = a.put(None, login_draft("X"), None).unwrap();
    sync(&mut a, &remote, &now_iso());
    sync(&mut b, &remote, &now_iso()); // B 拿到 X rev1
                                       // A 编辑 → 同步 → B 拉取
    a.put(
        Some(item.id()),
        login_draft("X2"),
        Some(item.revision().into()),
    )
    .unwrap();
    sync(&mut a, &remote, &now_iso());
    let s = sync(&mut b, &remote, &now_iso());
    assert_eq!(s.pulled, 1);
    assert_eq!(b.get(item.id()).unwrap().name(), "X2");
    assert_eq!(snapshot(&mut a), snapshot(&mut b));
    drop(fx);
}

#[test]
fn double_edit_lww_converges() {
    let (fx, mut a, mut b, remote) = fixture();
    let item = a.put(None, login_draft("X"), None).unwrap();
    sync(&mut a, &remote, &now_iso());
    sync(&mut b, &remote, &now_iso());
    // 离线双改：A 先改（rev2a），B 后改（rev2b > rev2a）
    let a2 = a
        .put(
            Some(item.id()),
            login_draft("from-A"),
            Some(item.revision().into()),
        )
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    let b2 = b
        .put(
            Some(item.id()),
            login_draft("from-B"),
            Some(item.revision().into()),
        )
        .unwrap();
    assert!(b2.revision() > a2.revision());
    // 依次上线：最终一致 = 后改者（B）胜
    sync(&mut a, &remote, &now_iso());
    sync(&mut b, &remote, &now_iso());
    sync(&mut a, &remote, &now_iso());
    assert_eq!(a.get(item.id()).unwrap().name(), "from-B");
    assert_eq!(b.get(item.id()).unwrap().name(), "from-B");
    assert_eq!(snapshot(&mut a), snapshot(&mut b));
    drop(fx);
}

#[test]
fn tombstone_propagates_and_hard_delete_after_confirmation() {
    let (fx, mut a, mut b, remote) = fixture();
    let item = a.put(None, login_draft("Z"), None).unwrap();
    sync(&mut a, &remote, &now_iso());
    sync(&mut b, &remote, &now_iso());
    // A 删除 → 同步 → B 收敛（墓碑传播）
    a.delete(item.id()).unwrap();
    sync(&mut a, &remote, &now_iso());
    let s = sync(&mut b, &remote, &now_iso());
    assert_eq!(s.pulled, 1);
    assert!(b.get(item.id()).unwrap().deleted());
    assert!(b.tombstones().iter().any(|(id, _)| *id == item.id()));
    // 远端有墓碑文件
    assert!(remote
        .get(&format!("{}.tomb.lk", item.id()))
        .unwrap()
        .is_some());
    // 未到期 → 不硬删
    let s = sync(&mut a, &remote, &now_iso());
    assert_eq!(s.purged, 0);
    // 墓碑注时 31 天前 → 已确认 → 本地+远端同时硬删
    age_tombstone(&mut a, item.id(), 31);
    age_tombstone(&mut b, item.id(), 31);
    let s = sync(&mut a, &remote, &future_iso(31));
    assert_eq!(s.purged, 1, "已确认且过期 → 硬删");
    assert!(remote
        .get(&format!("{}.item.lk", item.id()))
        .unwrap()
        .is_none());
    assert!(remote
        .get(&format!("{}.tomb.lk", item.id()))
        .unwrap()
        .is_none());
    assert!(a.get(item.id()).is_err());
    // B 同步 → 墓碑已过期且远端索引缺失 → 本地清理（不复活、不重推）
    let s = sync(&mut b, &remote, &future_iso(31));
    assert_eq!(s.purged, 1);
    assert!(b.get(item.id()).is_err());
    // 远端不再出现该条目（无复活循环）
    assert!(remote
        .get(&format!("{}.item.lk", item.id()))
        .unwrap()
        .is_none());
    drop(fx);
}

#[test]
fn remote_index_lost_full_pull() {
    let (fx, mut a, mut b, remote) = fixture();
    let item = a.put(None, login_draft("X"), None).unwrap();
    sync(&mut a, &remote, &now_iso());
    sync(&mut b, &remote, &now_iso());
    // 远端索引丢失 → B 全量拉取重建
    remote.delete(INDEX_KEY).unwrap();
    let _s = sync(&mut b, &remote, &now_iso());
    assert!(remote.get(INDEX_KEY).unwrap().is_some(), "索引重建");
    assert_eq!(b.get(item.id()).unwrap().name(), "X");
    drop(fx);
}

#[test]
fn remote_index_corrupt_reports_anomaly() {
    let (fx, mut a, _b, remote) = fixture();
    let item = a.put(None, login_draft("X"), None).unwrap();
    sync(&mut a, &remote, &now_iso());
    // 篡改远端索引 → 解密失败 → SyncAnomaly，本地不被覆盖
    let idx = remote.get(INDEX_KEY).unwrap().unwrap();
    let mut tampered = idx.data;
    tampered[20] ^= 0xFF;
    remote.put(INDEX_KEY, &tampered, Some(&idx.etag)).unwrap();
    let mut v = unlock(fx.a_dir.path());
    let err = SyncEngine::new(&remote).run_round(&mut v, &now_iso());
    assert!(matches!(err, Err(Error::SyncAnomaly(_))));
    assert_eq!(v.get(item.id()).unwrap().name(), "X", "本地未动");
    drop(fx);
}

#[test]
fn remote_item_corrupt_reports_anomaly() {
    let (fx, mut a, mut b, remote) = fixture();
    let item = a.put(None, login_draft("X"), None).unwrap();
    sync(&mut a, &remote, &now_iso());
    sync(&mut b, &remote, &now_iso());
    // A 编辑并推送 → 远端条目被篡改 → B 拉取时报异常
    a.put(
        Some(item.id()),
        login_draft("X2"),
        Some(item.revision().into()),
    )
    .unwrap();
    sync(&mut a, &remote, &now_iso());
    let key = format!("{}.item.lk", item.id());
    let g = remote.get(&key).unwrap().unwrap();
    let mut tampered = g.data;
    tampered[30] ^= 0xFF;
    remote.put(&key, &tampered, Some(&g.etag)).unwrap();
    let err = SyncEngine::new(&remote).run_round(&mut b, &now_iso());
    assert!(matches!(err, Err(Error::SyncAnomaly(_))));
    assert_eq!(b.get(item.id()).unwrap().name(), "X", "本地未被覆盖");
    drop(fx);
}

#[test]
fn attachment_sync_and_chunk_resume() {
    let (fx, mut a, mut b, remote) = fixture();
    let data: Vec<u8> = (0..(crate::model::CHUNK_BYTES as usize + 123))
        .map(|i| (i % 251) as u8)
        .collect();
    use base64::Engine as _;
    let item = a
        .put(
            None,
            ItemDraft::File {
                name: "f.bin".into(),
                note: String::new(),
                size: 0,
                file_type: "application/octet-stream".into(),
                attachment: "f.bin".into(),
                attach_id: None,
                file_data: Some(base64::engine::general_purpose::STANDARD.encode(&data)),
            },
            None,
        )
        .unwrap();
    let aid = item.attach_id().unwrap();
    // 模拟上传中断：先只上传元数据 + 0 号分块
    let meta_key = format!("{aid}.attach.lk");
    remote
        .put(&meta_key, &a.attach_meta_blob(aid).unwrap(), None)
        .unwrap();
    let c0 = format!("{aid}.0.chunk.lk");
    remote
        .put(&c0, &a.chunk_blob(aid, 0).unwrap(), None)
        .unwrap();
    sync(&mut a, &remote, &now_iso()); // 补传剩余分块（断点续传）
    assert!(remote.get(&format!("{aid}.1.chunk.lk")).unwrap().is_some());
    // B 拉取 → 附件完整可导出
    sync(&mut b, &remote, &now_iso());
    let bundle = b.export(item.id()).unwrap();
    assert_eq!(bundle.data, data);
    drop(fx);
}

#[test]
fn deleted_missing_from_remote_old_tombstone_dropped() {
    let (fx, mut a, mut b, remote) = fixture();
    // A 本地建条目并删除（从未同步），墓碑 31 天前
    let item = a.put(None, login_draft("ghost"), None).unwrap();
    a.delete(item.id()).unwrap();
    age_tombstone(&mut a, item.id(), 31);
    // 首次同步：远端无此条目且墓碑已过期 → 不推送，仅本地清理
    let s = sync(&mut a, &remote, &future_iso(31));
    assert_eq!(s.purged, 1);
    assert!(a.get(item.id()).is_err());
    assert!(remote.get(INDEX_KEY).unwrap().is_some(), "空索引已创建");
    assert!(
        remote
            .get(&format!("{}.item.lk", item.id()))
            .unwrap()
            .is_none(),
        "远端从未出现该条目"
    );
    // 对端 B 同步 → 无影响
    sync(&mut b, &remote, &future_iso(31));
    assert_eq!(snapshot(&mut b), std::collections::BTreeMap::new());
    drop(fx);
}

/// M2：规则与条目同路径同步——远端有规则（索引 + `{uuid}.rule.lk`）→
/// 拉取落盘；远端索引含规则但对象缺失（损坏/中断）→ 自愈剔除（与条目
/// 同语义）。
#[test]
fn rule_sync_pulls_and_self_heals_missing_object() {
    let (fx, mut a, _b, remote) = fixture();
    // 远端真实规则（密文 + 索引条目）
    let rule_obj = crate::model::Rule {
        id: Uuid::new_v4(),
        project_dir: "/proj".into(),
        name: "publish".into(),
        command: "npm publish".into(),
        keys: vec!["NPM_TOKEN".into()],
        capability: crate::model::RULE_CAPABILITY_INJECT.into(),
        actions: crate::model::default_rule_actions(),
        created: "2026-01-01T00:00:00.000000Z".into(),
    };
    let key = format!("{}.rule.lk", rule_obj.id);
    let rule_blob = seal(
        a.keys().k_data.as_ref(),
        SealType::Rule,
        &key,
        &rule_obj.to_plaintext().unwrap(),
    );
    remote.put(&key, &rule_blob, None).unwrap();
    let entry = IndexEntry {
        id: rule_obj.id,
        revision: "2026-01-02T00:00:00.000000Z".into(),
        kind: ObjectKind::Rule,
        deleted: false,
    };
    let entries = vec![entry.clone()];
    let blob = seal(
        a.keys().k_data.as_ref(),
        SealType::Index,
        INDEX_KEY,
        &serde_json::to_vec(&entries).unwrap(),
    );
    remote.put(INDEX_KEY, &blob, None).unwrap();
    // A 同步 → 规则被拉取落盘（索引保留）
    a.put(None, login_draft("X"), None).unwrap();
    let s = sync(&mut a, &remote, &now_iso());
    assert_eq!(s.pulled, 1, "规则随条目同路径拉取");
    let rules = a.list_rules().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, rule_obj.id);
    assert_eq!(rules[0].command, "npm publish");
    // 索引同时含规则与条目
    let idx = remote.get(INDEX_KEY).unwrap().unwrap();
    let parsed: Vec<IndexEntry> = serde_json::from_slice(
        &open(
            a.keys().k_data.as_ref(),
            SealType::Index,
            INDEX_KEY,
            &idx.data,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(parsed
        .iter()
        .any(|e| e.id == rule_obj.id && e.kind == ObjectKind::Rule));
    assert!(parsed.iter().any(|e| e.kind == ObjectKind::Item));

    // 自愈：远端索引含规则但对象缺失 → 合并索引剔除（不引失效密文）
    let ghost = IndexEntry {
        id: Uuid::new_v4(),
        revision: "2026-01-03T00:00:00.000000Z".into(),
        kind: ObjectKind::Rule,
        deleted: false,
    };
    let mut entries2 = parsed.clone();
    entries2.push(ghost.clone());
    let blob2 = seal(
        a.keys().k_data.as_ref(),
        SealType::Index,
        INDEX_KEY,
        &serde_json::to_vec(&entries2).unwrap(),
    );
    remote.put(INDEX_KEY, &blob2, None).unwrap();
    sync(&mut a, &remote, &now_iso());
    let idx = remote.get(INDEX_KEY).unwrap().unwrap();
    let parsed: Vec<IndexEntry> = serde_json::from_slice(
        &open(
            a.keys().k_data.as_ref(),
            SealType::Index,
            INDEX_KEY,
            &idx.data,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        !parsed.iter().any(|e| e.id == ghost.id),
        "对象缺失的规则索引条目应被自愈剔除"
    );
    drop(fx);
}

/// M2：规则双端收敛——A 添加规则 → 同步 → B 同步拉取；
/// A 删除规则 → 同步 → B 同步收到删除（软删 + 墓碑传播）。
#[test]
fn rule_push_pull_and_delete_propagate() {
    let (fx, mut a, mut b, remote) = fixture();
    // A 添加规则
    let rule = a
        .put_rule(
            crate::model::RuleDraft {
                project_dir: fake_abs_proj(),
                name: "publish".into(),
                command: "npm publish".into(),
                keys: vec!["NPM_TOKEN".into()],
                capability: crate::model::RULE_CAPABILITY_INJECT.into(),
                actions: crate::model::default_rule_actions(),
            },
            None,
        )
        .unwrap();
    // A → 远端
    let s = sync(&mut a, &remote, &now_iso());
    assert_eq!(s.pushed, 1);
    assert!(
        remote
            .get(&format!("{}.rule.lk", rule.id))
            .unwrap()
            .is_some(),
        "远端应有规则密文"
    );
    // B 拉取
    let s = sync(&mut b, &remote, &now_iso());
    assert_eq!(s.pulled, 1);
    let b_rules = b.list_rules().unwrap();
    assert_eq!(b_rules.len(), 1);
    assert_eq!(b_rules[0].command, "npm publish");
    // B 再同步 → 无变化（不重复拉取）
    let s = sync(&mut b, &remote, &now_iso());
    assert!(s.is_clean(), "规则收敛后不再拉取：{s:?}");
    // A 删除规则 → 传播
    a.delete_rule(rule.id).unwrap();
    let s = sync(&mut a, &remote, &now_iso());
    assert_eq!(s.pushed, 1, "软删规则随同步推送");
    let s = sync(&mut b, &remote, &now_iso());
    assert_eq!(s.pulled, 1, "B 收到规则删除（墓碑）");
    assert_eq!(b.list_rules().unwrap().len(), 0, "B 的规则已删除");
    drop(fx);
}

/// M2：规则 LWW——两端各自添加同一 id 不同内容（替换），revision 更新
/// 者胜（与条目同语义）。
#[test]
fn rule_lww_conflict_resolves_by_revision() {
    let (fx, mut a, mut b, remote) = fixture();
    let rule = a
        .put_rule(
            crate::model::RuleDraft {
                project_dir: fake_abs_proj(),
                name: "p".into(),
                command: "npm publish".into(),
                keys: vec!["A".into()],
                capability: crate::model::RULE_CAPABILITY_INJECT.into(),
                actions: crate::model::default_rule_actions(),
            },
            None,
        )
        .unwrap();
    let rev1 = a.rule_revision(rule.id).unwrap();
    sync(&mut a, &remote, &now_iso());
    sync(&mut b, &remote, &now_iso());
    // B 替换（内容不同，revision 更新）
    b.put_rule(
        crate::model::RuleDraft {
            project_dir: fake_abs_proj(),
            name: "p2".into(),
            command: "npm *".into(),
            keys: vec!["B".into()],
            capability: crate::model::RULE_CAPABILITY_INJECT.into(),
            actions: crate::model::default_rule_actions(),
        },
        Some(rule.id),
    )
    .unwrap();
    let rev2 = b.rule_revision(rule.id).unwrap();
    assert!(rev2 > rev1, "替换 bump 修订号");
    sync(&mut b, &remote, &now_iso());
    // A 同步 → 拉取新版本
    let s = sync(&mut a, &remote, &now_iso());
    assert_eq!(s.pulled, 1);
    let a_rules = a.list_rules().unwrap();
    assert_eq!(a_rules.len(), 1);
    assert_eq!(a_rules[0].name, "p2");
    assert_eq!(a_rules[0].keys, vec!["B".to_string()]);
    drop(fx);
}

/// M2：规则 30 天硬删收敛——软删传播 → 时间越过 TOMBSTONE_GRACE →
/// purge 后两端 `{id}.rule.lk` + `{id}.tomb.lk` + 索引项均清理且不再复活
/// （对齐条目 `tombstone_propagates_and_hard_delete_after_confirmation`）。
#[test]
fn rule_tombstone_propagates_and_hard_delete_after_confirmation() {
    let (fx, mut a, mut b, remote) = fixture();
    // A 添加规则 → 传播到 B
    let rule = a
        .put_rule(
            crate::model::RuleDraft {
                project_dir: fake_abs_proj(),
                name: "publish".into(),
                command: "npm publish".into(),
                keys: vec!["NPM_TOKEN".into()],
                capability: crate::model::RULE_CAPABILITY_INJECT.into(),
                actions: crate::model::default_rule_actions(),
            },
            None,
        )
        .unwrap();
    sync(&mut a, &remote, &now_iso());
    let s = sync(&mut b, &remote, &now_iso());
    assert_eq!(s.pulled, 1);
    assert_eq!(b.list_rules().unwrap().len(), 1);
    // A 删除 → 同步 → B 收敛（软删 + 墓碑传播）
    a.delete_rule(rule.id).unwrap();
    sync(&mut a, &remote, &now_iso());
    let s = sync(&mut b, &remote, &now_iso());
    assert_eq!(s.pulled, 1, "B 收到规则删除（墓碑）");
    assert_eq!(b.list_rules().unwrap().len(), 0, "B 的规则已删除");
    assert!(b.tombstones().iter().any(|(id, _)| *id == rule.id));
    // 远端有墓碑文件
    assert!(remote
        .get(&format!("{}.tomb.lk", rule.id))
        .unwrap()
        .is_some());
    // 未到期 → 不硬删
    let s = sync(&mut a, &remote, &now_iso());
    assert_eq!(s.purged, 0);
    // 墓碑注时 31 天前 → 已确认 → 本地+远端同时硬删
    age_tombstone(&mut a, rule.id, 31);
    age_tombstone(&mut b, rule.id, 31);
    let s = sync(&mut a, &remote, &future_iso(31));
    assert_eq!(s.purged, 1, "规则已确认且过期 → 硬删");
    assert!(remote
        .get(&format!("{}.rule.lk", rule.id))
        .unwrap()
        .is_none());
    assert!(remote
        .get(&format!("{}.tomb.lk", rule.id))
        .unwrap()
        .is_none());
    assert!(a.get_rule(rule.id).is_err());
    assert!(a.rule_revision(rule.id).is_none(), "索引项已清理");
    // B 同步 → 墓碑已过期且远端索引缺失 → 本地清理（不复活、不重推）
    let s = sync(&mut b, &remote, &future_iso(31));
    assert_eq!(s.purged, 1);
    assert!(b.get_rule(rule.id).is_err());
    assert!(b.rule_revision(rule.id).is_none(), "索引项已清理");
    // 远端不再出现该规则（无复活循环）
    assert!(remote
        .get(&format!("{}.rule.lk", rule.id))
        .unwrap()
        .is_none());
    drop(fx);
}

/// M2：远端索引丢失自愈时，已删规则不得复活——重建索引须从远端墓碑
/// 恢复 deleted=true（以墓碑 revision 作合成修订号，对齐条目体内
/// item.deleted() 恢复的行为）。
#[test]
fn rule_deleted_not_resurrected_on_remote_index_loss() {
    let (fx, mut a, mut b, remote) = fixture();
    let rule = a
        .put_rule(
            crate::model::RuleDraft {
                project_dir: fake_abs_proj(),
                name: "publish".into(),
                command: "npm publish".into(),
                keys: vec!["NPM_TOKEN".into()],
                capability: crate::model::RULE_CAPABILITY_INJECT.into(),
                actions: crate::model::default_rule_actions(),
            },
            None,
        )
        .unwrap();
    sync(&mut a, &remote, &now_iso());
    // B 拿到活跃规则
    let s = sync(&mut b, &remote, &now_iso());
    assert_eq!(s.pulled, 1);
    assert_eq!(b.list_rules().unwrap().len(), 1);
    // A 删除规则并同步（远端墓碑 + 索引 deleted=true）
    a.delete_rule(rule.id).unwrap();
    sync(&mut a, &remote, &now_iso());
    assert!(remote
        .get(&format!("{}.tomb.lk", rule.id))
        .unwrap()
        .is_some());
    // 远端索引丢失（B 尚未收到删除）→ B 全量拉取重建
    remote.delete(INDEX_KEY).unwrap();
    let s = sync(&mut b, &remote, &now_iso());
    assert_eq!(s.pulled, 1, "B 从重建索引收敛到删除态");
    assert_eq!(b.list_rules().unwrap().len(), 0, "已删规则不得复活");
    assert!(b.tombstones().iter().any(|(id, _)| *id == rule.id));
    // 远端重建索引含 deleted=true（不复活广播）
    let idx = remote.get(INDEX_KEY).unwrap().unwrap();
    let parsed: Vec<IndexEntry> = serde_json::from_slice(
        &open(
            b.keys().k_data.as_ref(),
            SealType::Index,
            INDEX_KEY,
            &idx.data,
        )
        .unwrap(),
    )
    .unwrap();
    let entry = parsed
        .iter()
        .find(|e| e.id == rule.id)
        .expect("重建索引应含该规则条目");
    assert!(entry.deleted, "重建索引须保留 deleted=true");
    drop(fx);
}

/// M2：删除后同 id 复活规则，远端索引丢失重建不得把活跃规则误判为已删。
/// 复活推送必须清理远端陈旧墓碑（否则重建探测到墓碑会把活跃规则再标为
/// deleted=true），与 `rule_deleted_not_resurrected_on_remote_index_loss`
/// 互为镜像。
#[test]
fn rule_revived_not_falsely_deleted_on_remote_index_loss() {
    let (fx, mut a, mut b, remote) = fixture();
    let rule = a
        .put_rule(
            crate::model::RuleDraft {
                project_dir: fake_abs_proj(),
                name: "publish".into(),
                command: "npm publish".into(),
                keys: vec!["NPM_TOKEN".into()],
                capability: crate::model::RULE_CAPABILITY_INJECT.into(),
                actions: crate::model::default_rule_actions(),
            },
            None,
        )
        .unwrap();
    sync(&mut a, &remote, &now_iso());
    let s = sync(&mut b, &remote, &now_iso());
    assert_eq!(s.pulled, 1);
    assert_eq!(b.list_rules().unwrap().len(), 1);
    // A 删除 → 同步（远端墓碑 + 索引 deleted=true）
    a.delete_rule(rule.id).unwrap();
    sync(&mut a, &remote, &now_iso());
    assert!(remote
        .get(&format!("{}.tomb.lk", rule.id))
        .unwrap()
        .is_some());
    // A 同 id 复活 → 同步（远端陈旧墓碑应被清理）
    a.put_rule(
        crate::model::RuleDraft {
            project_dir: fake_abs_proj(),
            name: "publish2".into(),
            command: "npm *".into(),
            keys: vec!["A".into()],
            capability: crate::model::RULE_CAPABILITY_INJECT.into(),
            actions: crate::model::default_rule_actions(),
        },
        Some(rule.id),
    )
    .unwrap();
    sync(&mut a, &remote, &now_iso());
    assert!(
        remote
            .get(&format!("{}.tomb.lk", rule.id))
            .unwrap()
            .is_none(),
        "复活推送须清理远端陈旧墓碑"
    );
    // 远端索引丢失 → B 全量拉取重建：活跃规则不得被误判为已删
    remote.delete(INDEX_KEY).unwrap();
    sync(&mut b, &remote, &now_iso());
    assert_eq!(b.list_rules().unwrap().len(), 1, "复活规则不得被误删");
    assert!(
        !b.tombstones().iter().any(|(id, _)| *id == rule.id),
        "重建不得伪造删除墓碑"
    );
    // 远端重建索引含 deleted=false
    let idx = remote.get(INDEX_KEY).unwrap().unwrap();
    let parsed: Vec<IndexEntry> = serde_json::from_slice(
        &open(
            b.keys().k_data.as_ref(),
            SealType::Index,
            INDEX_KEY,
            &idx.data,
        )
        .unwrap(),
    )
    .unwrap();
    let entry = parsed
        .iter()
        .find(|e| e.id == rule.id)
        .expect("重建索引应含该规则条目");
    assert!(!entry.deleted, "重建索引不得把活跃规则标为 deleted");
    drop(fx);
}

#[test]
fn storm_backoff_math() {
    assert_eq!(next_poll_interval(60, 0), 60);
    assert_eq!(next_poll_interval(60, 1), 120);
    assert_eq!(next_poll_interval(60, 2), 240);
    assert_eq!(next_poll_interval(60, 20), MAX_SYNC_INTERVAL_SECS);
    assert_eq!(next_poll_interval(5, 0), MIN_SYNC_INTERVAL_SECS);
    assert_eq!(next_poll_interval(100_000, 0), MAX_SYNC_INTERVAL_SECS);
    assert_eq!(storm_level_after(10, 3), 0);
    assert_eq!(storm_level_after(100, 3), 4);
    assert_eq!(poll_interval_after(60, 100, 2), 480);
    assert_eq!(poll_interval_after(60, 10, 2), 60);
}

#[test]
fn sync_config_validation() {
    let ok = SyncConfig {
        url: "https://dav.example.com".into(),
        interval_secs: 60,
    };
    assert!(ok.validate().is_ok());
    let bad_interval = SyncConfig {
        url: "https://dav.example.com".into(),
        interval_secs: 5,
    };
    assert!(bad_interval.validate().is_err());
    // 补充拍板 #8：上限收敛到 1h——3600 合法，3601 被拒。
    let max_interval = SyncConfig {
        url: "https://dav.example.com".into(),
        interval_secs: MAX_SYNC_INTERVAL_SECS,
    };
    assert!(max_interval.validate().is_ok());
    let over_max_interval = SyncConfig {
        url: "https://dav.example.com".into(),
        interval_secs: MAX_SYNC_INTERVAL_SECS + 1,
    };
    assert!(over_max_interval.validate().is_err());
    let bad_scheme = SyncConfig {
        url: "ftp://x".into(),
        interval_secs: 60,
    };
    assert!(bad_scheme.validate().is_err());
    let file = SyncConfig {
        url: "file:///tmp/x".into(),
        interval_secs: 60,
    };
    assert!(file.validate().is_ok());
}

/// CAS 冲突确定性验证：包装后端在条件写前用「他端新版本」覆盖对象，
/// 必触发 If-Match 失败 → LWW 裁决。
#[test]
fn cas_conflict_lww_retry_wins() {
    use crate::storage::{GetResult, PutOutcome, RemoteObject};
    struct RaceBackend {
        inner: LocalStorage,
        tamper_on_put: std::sync::Mutex<bool>,
        k_data: Vec<u8>,
        race_key: String,
        race_item: Item,
    }
    impl StorageBackend for RaceBackend {
        fn name(&self) -> &'static str {
            "race"
        }
        fn get(&self, key: &str) -> Result<Option<GetResult>> {
            self.inner.get(key)
        }
        fn put(&self, key: &str, data: &[u8], expected: Option<&str>) -> Result<PutOutcome> {
            if key == self.race_key && expected.is_some() && *self.tamper_on_put.lock().unwrap() {
                // 模拟并发写者：在条件写前把对象换成「更新更早的他端版本」
                *self.tamper_on_put.lock().unwrap() = false;
                let new_blob = seal(
                    &self.k_data,
                    SealType::Item,
                    key,
                    &self.race_item.to_plaintext().unwrap(),
                );
                let cur = self.inner.etag(key)?.unwrap_or_default();
                let _ = self.inner.put(key, &new_blob, Some(&cur));
            }
            self.inner.put(key, data, expected)
        }
        fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key)
        }
        fn list(&self) -> Result<Vec<RemoteObject>> {
            self.inner.list()
        }
        fn etag(&self, key: &str) -> Result<Option<String>> {
            self.inner.etag(key)
        }
    }

    let (fx, mut a, mut b, remote) = fixture();
    let item = a.put(None, login_draft("X"), None).unwrap();
    sync(&mut a, &remote, &now_iso());
    sync(&mut b, &remote, &now_iso());
    // 双方离线编辑（B 更晚）
    a.put(
        Some(item.id()),
        login_draft("A-new"),
        Some(item.revision().into()),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    b.put(
        Some(item.id()),
        login_draft("B-new"),
        Some(item.revision().into()),
    )
    .unwrap();
    sync(&mut a, &remote, &now_iso()); // 远端已是 A-new（rev2a）
                                       // B 同步：push 触发 CAS 冲突；远端 rev2a < 本地 rev2b → LWW 本地胜 → 重试成功
                                       // 「他端版本」revision 取 A 的（比 B 早）
    let race_item = Item::from_draft(
        login_draft("A-new"),
        item.id(),
        a.get(item.id()).unwrap().revision().to_string(),
    );
    let race_remote = RaceBackend {
        inner: LocalStorage::new(fx.remote_dir.path().to_path_buf()),
        tamper_on_put: std::sync::Mutex::new(true),
        k_data: b.keys().k_data.clone().to_vec(),
        race_key: format!("{}.item.lk", item.id()),
        race_item,
    };
    let s = SyncEngine::new(&race_remote)
        .run_round(&mut b, &now_iso())
        .unwrap();
    assert!(s.conflicts >= 1, "CAS 冲突必须发生");
    assert_eq!(b.get(item.id()).unwrap().name(), "B-new", "本地更晚 → 胜出");
    // 全量收敛
    sync(&mut a, &remote, &now_iso());
    assert_eq!(a.get(item.id()).unwrap().name(), "B-new");
    assert_eq!(snapshot(&mut a), snapshot(&mut b));
    drop(fx);
}

/// CAS 冲突且远端更晚 → 本地放弃，采纳远端（last-write-wins 对端胜）。
#[test]
fn cas_conflict_adopts_newer_remote() {
    use crate::storage::{GetResult, PutOutcome, RemoteObject};
    struct AdoptRaceBackend {
        inner: LocalStorage,
        tamper_on_put: std::sync::Mutex<bool>,
        k_data: Vec<u8>,
        race_key: String,
        race_item: Item,
    }
    impl StorageBackend for AdoptRaceBackend {
        fn name(&self) -> &'static str {
            "race"
        }
        fn get(&self, key: &str) -> Result<Option<GetResult>> {
            self.inner.get(key)
        }
        fn put(&self, key: &str, data: &[u8], expected: Option<&str>) -> Result<PutOutcome> {
            if key == self.race_key && expected.is_some() && *self.tamper_on_put.lock().unwrap() {
                *self.tamper_on_put.lock().unwrap() = false;
                let new_blob = seal(
                    &self.k_data,
                    SealType::Item,
                    key,
                    &self.race_item.to_plaintext().unwrap(),
                );
                let cur = self.inner.etag(key)?.unwrap_or_default();
                let _ = self.inner.put(key, &new_blob, Some(&cur));
            }
            self.inner.put(key, data, expected)
        }
        fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key)
        }
        fn list(&self) -> Result<Vec<RemoteObject>> {
            self.inner.list()
        }
        fn etag(&self, key: &str) -> Result<Option<String>> {
            self.inner.etag(key)
        }
    }

    let (fx, mut a, mut b, remote) = fixture();
    let item = a.put(None, login_draft("X"), None).unwrap();
    sync(&mut a, &remote, &now_iso());
    sync(&mut b, &remote, &now_iso());
    // A 编辑（rev2a）并同步 → 远端索引/对象 = rev2a
    let a2 = a
        .put(
            Some(item.id()),
            login_draft("A-new"),
            Some(item.revision().into()),
        )
        .unwrap();
    sync(&mut a, &remote, &now_iso());
    // B 离线编辑（rev2b > rev2a）；A 再改（rev2c > rev2b）但**不**同步
    b.put(
        Some(item.id()),
        login_draft("B-new"),
        Some(item.revision().into()),
    )
    .unwrap();
    let b_rev = b.get(item.id()).unwrap().revision().to_string();
    std::thread::sleep(std::time::Duration::from_millis(2));
    a.put(
        Some(item.id()),
        login_draft("A-latest"),
        Some(a2.revision().into()),
    )
    .unwrap();
    let a_rev = a.get(item.id()).unwrap().revision().to_string();
    assert!(a_rev > b_rev);
    // B 同步：push（base=rev2a 对象 ETag）→ 竞态写者注入 rev2c →
    // CAS 冲突 → 远端 rev2c 更晚 → B 放弃本地，采纳远端
    let race_item = Item::from_draft(login_draft("A-latest"), item.id(), a_rev);
    let race_remote = AdoptRaceBackend {
        inner: LocalStorage::new(fx.remote_dir.path().to_path_buf()),
        tamper_on_put: std::sync::Mutex::new(true),
        k_data: b.keys().k_data.clone().to_vec(),
        race_key: format!("{}.item.lk", item.id()),
        race_item,
    };
    let s = SyncEngine::new(&race_remote)
        .run_round(&mut b, &now_iso())
        .unwrap();
    assert!(s.conflicts >= 1);
    assert_eq!(
        b.get(item.id()).unwrap().name(),
        "A-latest",
        "远端更晚 → 采纳"
    );
    assert_eq!(snapshot(&mut a), snapshot(&mut b));
    drop(fx);
}

/// 远端对象缺失（索引有、对象无）→ 跳过 + 自愈合并索引。
#[test]
fn missing_remote_object_skips_and_heals() {
    let (fx, mut a, mut b, remote) = fixture();
    let item = a.put(None, login_draft("X"), None).unwrap();
    sync(&mut a, &remote, &now_iso());
    // A 编辑并推送（rev2）→ 远端条目对象被删（索引仍在 rev2）
    a.put(
        Some(item.id()),
        login_draft("X2"),
        Some(item.revision().into()),
    )
    .unwrap();
    sync(&mut a, &remote, &now_iso());
    remote.delete(&format!("{}.item.lk", item.id())).unwrap();
    let s = sync(&mut b, &remote, &now_iso());
    assert!(
        s.warnings.iter().any(|w| w.contains("对象缺失")),
        "{:?}",
        s.warnings
    );
    // 索引自愈：对象缺失条目被剔除
    let idx = remote.get(INDEX_KEY).unwrap().unwrap();
    let parsed: Vec<IndexEntry> = serde_json::from_slice(
        &open(
            b.keys().k_data.as_ref(),
            SealType::Index,
            INDEX_KEY,
            &idx.data,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(parsed.is_empty());
    drop(fx);
}

#[test]
fn pull_deleted_without_remote_tomb_synthesizes() {
    let (fx, mut a, mut b, remote) = fixture();
    let item = a.put(None, login_draft("Z"), None).unwrap();
    sync(&mut a, &remote, &now_iso());
    sync(&mut b, &remote, &now_iso());
    a.delete(item.id()).unwrap();
    sync(&mut a, &remote, &now_iso());
    // 远端墓碑被删（对象缺失）→ B 合成墓碑，不报错
    remote.delete(&format!("{}.tomb.lk", item.id())).unwrap();
    let s = sync(&mut b, &remote, &now_iso());
    assert_eq!(s.pulled, 1);
    assert!(b.get(item.id()).unwrap().deleted());
    assert!(b.tombstones().iter().any(|(id, _)| *id == item.id()));
    drop(fx);
}

/// 回归：拉取后重启（重新解锁）→ 磁盘索引已持久化，条目仍可见。
#[test]
fn pulled_entries_survive_restart() {
    let (fx, mut a, mut b, remote) = fixture();
    let item = a.put(None, login_draft("X"), None).unwrap();
    sync(&mut a, &remote, &now_iso());
    // B 拉取后重启
    sync(&mut b, &remote, &now_iso());
    drop(b);
    let mut b2 = unlock(fx.b_dir.path());
    assert_eq!(
        b2.list().unwrap().len(),
        1,
        "重启后拉取条目在索引中可见（磁盘 index.lk 已持久化）"
    );
    assert_eq!(b2.get(item.id()).unwrap().name(), "X");
    // 继续收敛
    let b3 = b2.put(None, login_draft("Y"), None).unwrap();
    sync(&mut b2, &remote, &now_iso());
    sync(&mut a, &remote, &now_iso());
    assert_eq!(a.get(b3.id()).unwrap().name(), "Y");
    drop(fx);
}

#[test]
fn item_kind_accessor_still_works() {
    // 防误删（M0 语义回归哨兵）
    let item = Item::from_draft(login_draft("x"), Uuid::new_v4(), now_iso());
    assert_eq!(item.kind(), ItemKind::Login);
}

// -- G1 根治回归：两阶段（抓取无锁 → 应用复核）的竞态语义 ---------------

/// 抓取后、应用前本地被并发更新（更晚）→ 应用阶段 LWW 复核跳过旧快照
/// 导入，本地编辑不被覆盖；下轮推送收敛。
#[test]
fn apply_skips_stale_import_when_local_newer() {
    let (fx, mut a, _b, remote) = fixture();
    let item = a.put(None, login_draft("X"), None).unwrap();
    sync(&mut a, &remote, &now_iso());
    // B 同步拿到 rev1（旧状态）
    let mut b = unlock(fx.b_dir.path());
    sync(&mut b, &remote, &now_iso());
    // 远端较新（rev2）
    a.put(
        Some(item.id()),
        login_draft("remote-new"),
        Some(item.revision().into()),
    )
    .unwrap();
    sync(&mut a, &remote, &now_iso());
    // B（旧状态 rev1）：抓取阶段缓冲远端 rev2
    let mut plan = SyncEngine::new(&remote)
        .fetch_round(&b, &now_iso())
        .unwrap();
    assert!(
        plan.imports.iter().any(|i| i.id == item.id()),
        "抓取已缓冲远端版本"
    );
    // 同步期间命令更新了同一条目（rev3 > rev2）
    std::thread::sleep(std::time::Duration::from_millis(2));
    b.put(
        Some(item.id()),
        login_draft("local-race"),
        Some(item.revision().into()),
    )
    .unwrap();
    // 应用复核：本地已更新且更晚 → 跳过导入（不覆盖）
    SyncEngine::new(&remote)
        .apply_round(&mut b, &mut plan)
        .unwrap();
    assert_eq!(b.get(item.id()).unwrap().name(), "local-race");
    assert_eq!(plan.summary.pulled, 0, "应用复核跳过旧快照导入");
    // 下轮收敛：本地较新 → 推送 → 两端一致
    sync(&mut b, &remote, &now_iso());
    sync(&mut a, &remote, &now_iso());
    assert_eq!(a.get(item.id()).unwrap().name(), "local-race");
    assert_eq!(snapshot(&mut a), snapshot(&mut b));
    drop(fx);
}

/// 硬删计划后、应用前条目被并发复活 → 应用阶段复核（条目 revision ≠
/// 裁决时墓碑 revision）跳过，复活条目不被误删，且下轮正常推送。
#[test]
fn apply_skips_stale_hard_delete_when_item_resurrected() {
    let (fx, _a, mut b, remote) = fixture();
    // B 本地：建条目 → 删除（墓碑注时 31 天前）→ 从未同步
    let item = b.put(None, login_draft("ghost"), None).unwrap();
    b.delete(item.id()).unwrap();
    age_tombstone(&mut b, item.id(), 31);
    // 抓取：远端无此条目且墓碑已过期 → 计划本地硬删
    let mut plan = SyncEngine::new(&remote)
        .fetch_round(&b, &future_iso(31))
        .unwrap();
    assert!(
        plan.hard_delete.iter().any(|(id, _)| *id == item.id()),
        "抓取已计划硬删"
    );
    // 同步期间命令复活了条目（CAS 更新 → 新 revision）
    std::thread::sleep(std::time::Duration::from_millis(2));
    b.put(
        Some(item.id()),
        login_draft("alive"),
        Some(b.get(item.id()).unwrap().revision().into()),
    )
    .unwrap();
    // 应用复核：条目 revision ≠ 裁决时墓碑 revision → 跳过硬删
    SyncEngine::new(&remote)
        .apply_round(&mut b, &mut plan)
        .unwrap();
    assert_eq!(plan.summary.purged, 0);
    assert_eq!(
        b.get(item.id()).unwrap().name(),
        "alive",
        "复活条目不被误删"
    );
    // 下轮：复活条目正常推送（无数据丢失）
    let s = sync(&mut b, &remote, &future_iso(31));
    assert_eq!(s.pushed, 1);
    assert!(remote
        .get(&format!("{}.item.lk", item.id()))
        .unwrap()
        .is_some());
    drop(fx);
}

/// 推送快照一致性守卫：diff 决策后条目被并发更新（revision 前进）→
/// 本轮跳过推送且从合并索引剔除（远端索引/密文恒一致），下轮再推。
#[test]
fn push_skips_when_item_changed_after_diff() {
    // 视图：索引报 diff 决策点的旧快照（rev2），条目读取返回并发更新后的
    // 版本（rev3）——等价于守护进程「抓取快照 → 命令并发更新」的窗口。
    struct EvolvingView<'v> {
        v: &'v UnlockedVault,
        old_index: Vec<IndexEntry>,
        new_item: Item,
        new_blob: Vec<u8>,
    }
    impl VaultRead for EvolvingView<'_> {
        fn keys(&self) -> Keys {
            self.v.keys().clone()
        }
        fn index_snapshot(&self) -> Result<Vec<IndexEntry>> {
            Ok(self.old_index.clone())
        }
        fn item(&self, id: Uuid) -> Result<Item> {
            self.v.get(id)
        }
        fn item_with_blob(&self, id: Uuid) -> Result<(Item, Vec<u8>)> {
            if id == self.new_item.id() {
                return Ok((self.new_item.clone(), self.new_blob.clone()));
            }
            self.v.item_with_blob(id)
        }
        fn rule(&self, id: Uuid) -> Result<Rule> {
            self.v.rule(id)
        }
        fn rule_with_blob(&self, id: Uuid) -> Result<(Rule, Vec<u8>)> {
            self.v.rule_with_blob(id)
        }
        fn rule_revision(&self, id: Uuid) -> Option<String> {
            self.v.rule_revision(id)
        }
        fn tomb_blob(&self, id: Uuid) -> Result<Vec<u8>> {
            self.v.tomb_blob(id)
        }
        fn attachment_blobs(&self, aid: Uuid) -> Result<AttachmentBlobs> {
            self.v.attachment_blobs(aid)
        }
        fn attachment_keys(&self, aid: Uuid) -> Vec<String> {
            self.v.attachment_keys(aid)
        }
        fn tombstones(&self) -> Result<Vec<(Uuid, Tombstone)>> {
            Ok(self.v.tombstones())
        }
    }

    let (fx, mut a, mut b, remote) = fixture();
    let item = a.put(None, login_draft("X"), None).unwrap();
    sync(&mut a, &remote, &now_iso());
    sync(&mut b, &remote, &now_iso());
    // B 本地编辑 → rev2（diff 决策点的快照）；随后再编辑 → rev3（并发更新）
    b.put(
        Some(item.id()),
        login_draft("rev2"),
        Some(item.revision().into()),
    )
    .unwrap();
    let old_index = b.index_snapshot();
    std::thread::sleep(std::time::Duration::from_millis(2));
    let edited = b
        .put(
            Some(item.id()),
            login_draft("rev3"),
            Some(b.get(item.id()).unwrap().revision().into()),
        )
        .unwrap();
    let new_blob = b.item_blob(item.id()).unwrap();
    // 抓取：diff（快照 rev2 > 远端 rev1 → 推送）→ 守卫发现条目已变 → 跳过
    let view = EvolvingView {
        v: &b,
        old_index,
        new_item: edited,
        new_blob,
    };
    let plan = SyncEngine::new(&remote)
        .fetch_round(&view, &now_iso())
        .unwrap();
    assert_eq!(plan.summary.pushed, 0, "并发更新 → 本轮跳过推送");
    assert_eq!(plan.summary.conflicts, 0);
    // 远端未被旧快照污染：索引仍只含 rev1（rev2 条目被剔除，无密文缺失）
    let idx = remote.get(INDEX_KEY).unwrap().unwrap();
    let parsed: Vec<IndexEntry> = serde_json::from_slice(
        &open(
            b.keys().k_data.as_ref(),
            SealType::Index,
            INDEX_KEY,
            &idx.data,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].revision, item.revision().to_string());
    // 下轮：rev3 正常推送收敛
    let s = sync(&mut b, &remote, &now_iso());
    assert_eq!(s.pushed, 1);
    sync(&mut a, &remote, &now_iso());
    assert_eq!(a.get(item.id()).unwrap().name(), "rev3");
    assert_eq!(snapshot(&mut a), snapshot(&mut b));
    drop(fx);
}

/// 回归：索引 CAS 冲突触发有界重试，且重试间远端把某条目推进到更新
/// revision → 引擎必须重新拉取该条目（旧缓冲不得回写覆盖远端索引），
/// 否则会把远端索引回退到旧 revision（索引/密文不一致，反复摇摆）。
#[test]
fn index_cas_retry_does_not_regress_remote_revision() {
    use crate::storage::{GetResult, PutOutcome, RemoteObject};
    struct IndexRaceBackend {
        inner: LocalStorage,
        race_once: std::sync::Mutex<bool>,
        k_data: Vec<u8>,
        race_key: String,
        race_item: Item,
        race_blob: Vec<u8>,
    }
    impl StorageBackend for IndexRaceBackend {
        fn name(&self) -> &'static str {
            "race"
        }
        fn get(&self, key: &str) -> Result<Option<GetResult>> {
            self.inner.get(key)
        }
        fn put(&self, key: &str, data: &[u8], expected: Option<&str>) -> Result<PutOutcome> {
            if key == INDEX_KEY && expected.is_some() && *self.race_once.lock().unwrap() {
                *self.race_once.lock().unwrap() = false;
                // 模拟并发客户端 C：条目推进到更新 revision + 重写索引 →
                // 使本轮索引 CAS 冲突（触发有界重试 + 重拉）
                let cur_obj = self.inner.etag(&self.race_key)?;
                self.inner
                    .put(&self.race_key, &self.race_blob, cur_obj.as_deref())?;
                let idx = vec![IndexEntry {
                    id: self.race_item.id(),
                    revision: self.race_item.revision().to_string(),
                    kind: ObjectKind::Item,
                    deleted: self.race_item.deleted(),
                }];
                let idx_blob = seal(
                    &self.k_data,
                    SealType::Index,
                    INDEX_KEY,
                    &serde_json::to_vec(&idx).unwrap(),
                );
                let cur_idx = self.inner.etag(INDEX_KEY)?;
                self.inner.put(INDEX_KEY, &idx_blob, cur_idx.as_deref())?;
                return Ok(PutOutcome::Conflict);
            }
            self.inner.put(key, data, expected)
        }
        fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key)
        }
        fn list(&self) -> Result<Vec<RemoteObject>> {
            self.inner.list()
        }
        fn etag(&self, key: &str) -> Result<Option<String>> {
            self.inner.etag(key)
        }
    }

    let (fx, mut a, mut b, remote) = fixture();
    let item = a.put(None, login_draft("X"), None).unwrap();
    sync(&mut a, &remote, &now_iso());
    sync(&mut b, &remote, &now_iso());
    // A 推进到 rev2 并同步（B 落后）
    a.put(
        Some(item.id()),
        login_draft("A-v2"),
        Some(item.revision().into()),
    )
    .unwrap();
    sync(&mut a, &remote, &now_iso());
    // A 再推进到 rev3（并发客户端 C 的新版本），但**不**同步
    let race_item = a
        .put(
            Some(item.id()),
            login_draft("C-v4"),
            Some(a.get(item.id()).unwrap().revision().into()),
        )
        .unwrap();
    let race_blob = a.item_blob(item.id()).unwrap();
    // B 本地新建 Y：本轮合并索引必有变化 → 必写索引 → 触发 CAS 冲突 + 重试
    b.put(None, login_draft("Y"), None).unwrap();
    let race_backend = IndexRaceBackend {
        inner: LocalStorage::new(fx.remote_dir.path().to_path_buf()),
        race_once: std::sync::Mutex::new(true),
        k_data: a.keys().k_data.clone().to_vec(),
        race_key: format!("{}.item.lk", item.id()),
        race_item: race_item.clone(),
        race_blob,
    };
    let s = SyncEngine::new(&race_backend)
        .run_round(&mut b, &now_iso())
        .unwrap();
    // 重试后必须采纳最新远端版本（不被旧缓冲回写覆盖）
    assert_eq!(b.get(item.id()).unwrap().name(), "C-v4");
    assert_eq!(b.get(item.id()).unwrap().revision(), race_item.revision());
    assert_eq!(s.pulled, 1, "只应用最终（最新）远端版本");
    // 远端索引未回退：仍引用最新 revision（索引与密文一致）
    let idx = race_backend.inner.get(INDEX_KEY).unwrap().unwrap();
    let parsed: Vec<IndexEntry> = serde_json::from_slice(
        &open(
            a.keys().k_data.as_ref(),
            SealType::Index,
            INDEX_KEY,
            &idx.data,
        )
        .unwrap(),
    )
    .unwrap();
    let x_entry = parsed.iter().find(|e| e.id == item.id()).unwrap();
    assert_eq!(x_entry.revision, race_item.revision().to_string());
    drop(fx);
}
