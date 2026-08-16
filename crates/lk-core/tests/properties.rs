//! 属性测试（第一层，`docs/testing.md` §1）：
//!
//! - **加密往返**：任意明文 → 加密 → 解密 == 明文；任意字节翻转 → 解密失败。
//! - **CAS 冲突**：base revision 过期 → 写失败；last-write-wins 收敛。
//! - **恢复信封**：恢复码往返一致；错误恢复码失败；重置后旧钥不可解新数据。
//!
//! 测试密钥全部在测试内随机生成（fixture 密钥不进仓库）。

use lk_core::audit::{AuditLog, AuditResult, EventInput};
use lk_core::crypto::{open, seal, test_kdf_params, Keys, SealType};
use lk_core::model::ItemDraft;
use lk_core::recovery::{RecoveryCode, RecoveryEnvelope};
use lk_core::vault::{init_vault_with_params, recover_vault_with_params, UnlockedVault};
use lk_core::Error;
use proptest::prelude::*;

/// 任意明文（0~8KB，含空、短、长、二进制）。
fn any_plaintext() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..8192)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// 任意明文 → 密封 → 打开 == 明文（任意密钥）。
    #[test]
    fn crypto_roundtrip_any_plaintext(pt in any_plaintext(), k in any::<[u8; 32]>()) {
        let key = k;
        let blob = seal(&key, SealType::Item, "obj-1", &pt);
        let opened = open(&key, SealType::Item, "obj-1", &blob).unwrap();
        prop_assert_eq!(opened, pt);
    }

    /// 任意字节翻转 → 解密失败（统一 Decrypt，防 oracle）。
    #[test]
    fn crypto_byte_flip_fails(
        pt in any_plaintext().prop_filter("至少 1 字节", |p| !p.is_empty()),
        flip in 0..8192usize,
        k in any::<[u8; 32]>()
    ) {
        let blob = seal(&k, SealType::Item, "obj-1", &pt);
        if flip < blob.len() {
            let mut tampered = blob;
            tampered[flip] ^= 0x01;
            prop_assert!(matches!(open(&k, SealType::Item, "obj-1", &tampered), Err(Error::Decrypt)));
        }
    }

    /// 错误密钥 → 解密失败。
    #[test]
    fn crypto_wrong_key_fails(pt in any_plaintext(), k1 in any::<[u8; 32]>(), k2 in any::<[u8; 32]>()) {
        prop_assume!(k1 != k2);
        let blob = seal(&k1, SealType::Item, "obj-1", &pt);
        prop_assert!(matches!(open(&k2, SealType::Item, "obj-1", &blob), Err(Error::Decrypt)));
    }

    /// 错误对象 id（AAD 换位）→ 解密失败。
    #[test]
    fn crypto_aad_swap_fails(pt in any_plaintext(), k in any::<[u8; 32]>()) {
        let blob = seal(&k, SealType::Item, "obj-1", &pt);
        prop_assert!(matches!(open(&k, SealType::Item, "obj-2", &blob), Err(Error::Decrypt)));
        prop_assert!(matches!(open(&k, SealType::Index, "obj-1", &blob), Err(Error::Decrypt)));
    }
}

/// CAS 冲突属性测试（确定性场景循环，避免 Argon2id 拖慢 proptest 主循环）：
/// 每次在全新临时库上验证：base 过期 → 写失败；刷新后重试 → 收敛成功。
#[test]
fn cas_conflict_and_last_write_wins_converge() {
    for _ in 0..8 {
        let dir = tempfile::tempdir().unwrap();
        let mut audit = AuditLog::open(dir.path()).unwrap();
        init_vault_with_params(dir.path(), "pw", false, &mut audit, &test_kdf_params()).unwrap();
        let mut v = UnlockedVault::unlock(dir.path(), "pw").unwrap();

        let draft = |name: &str| ItemDraft::Login {
            name: name.into(),
            username: "u".into(),
            password: "p".into(),
            uris: vec![],
            custom: vec![],
        };

        // 客户端 A、B 同时读到 r1
        let item = v.put(None, draft("r1"), None).unwrap();
        let r1 = item.revision().to_string();
        assert_eq!(v.list().unwrap().len(), 1);

        // A 先写（base=r1）→ 成功 r2
        let a = v
            .put(Some(item.id()), draft("A"), Some(r1.clone()))
            .unwrap();
        assert!(a.revision() > r1.as_str());

        // B 用过期 base=r1 写 → Conflict
        assert!(matches!(
            v.put(Some(item.id()), draft("B"), Some(r1.clone())),
            Err(Error::Conflict)
        ));

        // B 刷新（重拉最新 r2）→ 重试 → 收敛为 B（last-write-wins）
        let latest = v.get(item.id()).unwrap();
        let b = v
            .put(
                Some(item.id()),
                draft("B"),
                Some(latest.revision().to_string()),
            )
            .unwrap();
        assert!(b.revision() > a.revision());
        assert_eq!(v.get(item.id()).unwrap().name(), "B");

        // 最终只有一条，revision 单调不减
        let s = v.list().unwrap();
        assert_eq!(s.len(), 1);
        assert!(s[0].revision.as_str() >= b.revision());
    }
}

/// 墓碑收敛不变量：删除后墓碑只增不改（软删除幂等），条目进入 deleted 态。
#[test]
fn tombstone_invariants() {
    for _ in 0..8 {
        let dir = tempfile::tempdir().unwrap();
        let mut audit = AuditLog::open(dir.path()).unwrap();
        init_vault_with_params(dir.path(), "pw", false, &mut audit, &test_kdf_params()).unwrap();
        let mut v = UnlockedVault::unlock(dir.path(), "pw").unwrap();

        let draft = ItemDraft::Secret {
            name: "k".into(),
            value: "v".into(),
            purpose: String::new(),
            expires_at: None,
        };
        let item = v.put(None, draft, None).unwrap();
        let id = item.id();

        let t1 = v.delete(id).unwrap();
        assert!(v.get(id).unwrap().deleted());
        // 幂等删除：墓碑不变更（同 id、同 deletedAt、同 revision）
        let t2 = v.delete(id).unwrap();
        assert_eq!(t1.id, t2.id);
        assert_eq!(t1.deleted_at, t2.deleted_at);
        assert_eq!(t1.revision, t2.revision);
        // 墓碑文件存在
        assert!(dir.path().join(format!("{id}.tomb.lk")).exists());
    }
}

/// 恢复信封属性：往返一致；错误恢复码失败；重置后旧钥不可解新数据。
#[test]
fn recovery_envelope_properties() {
    for _ in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let mut audit = AuditLog::open(dir.path()).unwrap();

        // 建库 → 解锁 → 写入一条
        let (_, code) =
            init_vault_with_params(dir.path(), "pw", false, &mut audit, &test_kdf_params())
                .unwrap();
        {
            let mut v = UnlockedVault::unlock(dir.path(), "pw").unwrap();
            let draft = ItemDraft::Note {
                name: "n".into(),
                content: "content".into(),
            };
            v.put(None, draft, None).unwrap();
        }

        // 恢复前：记录旧密钥（用于「旧钥不可解新数据」断言）
        let old_keys = {
            let hdr = lk_core::vault::load_header(dir.path()).unwrap();
            let mk = hdr.kdf.derive_master_key("pw").unwrap();
            mk.derive_keys()
        };

        // 错误恢复码 → 统一失败
        let wrong = RecoveryCode::generate();
        assert!(recover_vault_with_params(
            dir.path(),
            &wrong,
            "newpw",
            &mut audit,
            &test_kdf_params()
        )
        .is_err());

        // 正确恢复码 + 新主密码 → 新恢复码
        let new_code =
            recover_vault_with_params(dir.path(), &code, "newpw", &mut audit, &test_kdf_params())
                .unwrap();
        assert_ne!(new_code.display(), code.display());

        // 新密码可解锁、条目可读；旧密码失败
        let mut v2 = UnlockedVault::unlock(dir.path(), "newpw").unwrap();
        assert_eq!(v2.list().unwrap().len(), 1);
        assert!(UnlockedVault::unlock(dir.path(), "pw").is_err());

        // 旧钥不可解新数据：条目密文已用新钥重加密
        let item_id = v2.list().unwrap()[0].id;
        let fname = format!("{item_id}.item.lk");
        let blob = std::fs::read(dir.path().join(&fname)).unwrap();
        assert!(matches!(
            open(old_keys.k_data.as_ref(), SealType::Item, &fname, &blob),
            Err(Error::Decrypt)
        ));

        // 新信封：旧恢复码不可开，新恢复码可开（旧信封作废）
        let envelope_bytes = std::fs::read(dir.path().join("recovery.envelope")).unwrap();
        let envelope = RecoveryEnvelope::from_bytes(&envelope_bytes).unwrap();
        assert!(envelope.open(&code).is_err(), "旧恢复码不可开新信封");
        assert!(envelope.open(&new_code).is_ok(), "新恢复码可开新信封");
    }
}

/// 审计追加语义：canonical 确定性；任意字节翻转 → HMAC 校验失败。
#[test]
fn audit_append_semantics() {
    for _ in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        let keys = Keys::from_raw([7u8; 32], [9u8; 32]);

        let e1 = log
            .append(
                &keys,
                &EventInput::new("lk", "item.put", AuditResult::Allowed),
            )
            .unwrap();
        // canonical 字节稳定（同事件两次序列化一致）
        assert_eq!(e1.canonical_bytes().unwrap(), e1.canonical_bytes().unwrap());
        assert_eq!(log.verify(&keys, &|_| None).unwrap(), 1);

        // 篡改：翻转任一行中的 1 字节（避开 JSON 结构破坏——直接改事件字段值）
        let path = log.path().to_path_buf();
        let content = std::fs::read(&path).unwrap();
        let idx = content
            .windows(b"item.put".len())
            .position(|w| w == b"item.put")
            .unwrap()
            + 2;
        let mut tampered = content;
        tampered[idx] ^= 0x01;
        std::fs::write(&path, &tampered).unwrap();
        assert!(log.verify(&keys, &|_| None).is_err());
    }
}

/// 事件总线属性（M1.5 事件总线契约，`docs/plugin-architecture.md` §5）：
///
/// - **投递完备**：任意事件序列 → 每个订阅者都收到全部事件（无丢失）。
/// - **保序**：单个订阅者按广播顺序收到事件。
///
/// 订阅者与发送者之间无返回值（观察广播），故不测聚合语义。
fn any_event() -> impl Strategy<Value = lk_core::bus::VaultEvent> {
    use lk_core::bus::{LockReason, SessionVia, VaultEvent};
    prop_oneof![
        (
            prop::array::uniform16(any::<u8>()),
            "[a-z]{0,12}",
            "[a-z]{0,8}",
            any::<bool>(),
        )
            .prop_map(|(b, rev, kind, deleted)| VaultEvent::ItemChanged {
                item_id: uuid::Uuid::from_bytes(b),
                revision_date: rev,
                kind,
                deleted,
            }),
        any::<u8>().prop_map(|v| VaultEvent::SessionUnlocked {
            via: match v % 3 {
                0 => SessionVia::Password,
                1 => SessionVia::Biometric,
                _ => SessionVia::Recovery,
            },
        }),
        any::<u8>().prop_map(|v| VaultEvent::SessionLocked {
            reason: match v % 4 {
                0 => LockReason::Manual,
                1 => LockReason::Timeout,
                2 => LockReason::Lockscreen,
                _ => LockReason::DaemonExit,
            },
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// 任意事件序列 → 每个订阅者都收到全部事件且保序（emit 广播语义）。
    #[test]
    fn bus_delivers_all_events_to_all_subscribers(events in prop::collection::vec(any_event(), 0..64)) {
        use lk_core::bus::{EventBus, EventSink};
        use std::sync::{Arc, Mutex};

        #[derive(Default)]
        struct Rec(Mutex<Vec<lk_core::bus::VaultEvent>>);
        impl EventSink for Rec {
            fn on_event(&self, event: &lk_core::bus::VaultEvent) {
                self.0.lock().unwrap().push(event.clone());
            }
        }

        let bus = Arc::new(EventBus::new());
        let a = Arc::new(Rec::default());
        let b = Arc::new(Rec::default());
        bus.subscribe(Arc::clone(&a) as Arc<dyn EventSink>);
        bus.subscribe(Arc::clone(&b) as Arc<dyn EventSink>);

        for event in &events {
            bus.emit(event);
        }
        // 投递完备 + 保序：与广播序列一致
        prop_assert_eq!(&*a.0.lock().unwrap(), &events);
        prop_assert_eq!(&*b.0.lock().unwrap(), &events);
    }
}
