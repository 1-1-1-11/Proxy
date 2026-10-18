// [INPUT]: 虚构 UUID/组织/凭据、隔离文件系统和归档格式。
// [OUTPUT]: A/B 往返去重、刷新凭据覆盖、跨组织隔离、旧版迁移与覆盖故障回归。
// [POS]: 账号匹配与不可变归档代次的离线证明，不读取真实用户数据。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
use super::*;
#[cfg(windows)]
use dunce::canonicalize;
#[cfg(not(windows))]
use std::fs::canonicalize;
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    time::Instant,
};
struct Fixture {
    root: PathBuf,
    home: PathBuf,
    vault: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("baga-opt-{}", new_id().unwrap()));
        let home = root.join("home");
        private::directory(&home.join(".claude")).unwrap();
        Self {
            vault: root.join("vault"),
            root,
            home,
        }
    }
    fn write(&self, path: &str, text: &[u8]) {
        let path = self.home.join(path);
        private::directory(path.parent().unwrap()).unwrap();
        private::write(&path, text).unwrap();
    }
    fn login(&self, id: &str, org: &str, token: &str) {
        self.write(".claude.json", serde_json::to_string(&serde_json::json!({"oauthAccount":{"accountUuid":id,"organizationUuid":org,"emailAddress":format!("{id}@example.invalid"),"displayName":id}})).unwrap().as_bytes());
        self.write(
            ".claude/.credentials.json",
            serde_json::to_string(&serde_json::json!({"claudeAiOauth":{"accessToken":token}}))
                .unwrap()
                .as_bytes(),
        );
    }
    fn token(&self) -> String {
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(self.home.join(".claude/.credentials.json")).unwrap())
                .unwrap();
        value["claudeAiOauth"]["accessToken"]
            .as_str()
            .unwrap()
            .into()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[test]
fn repeated_accounts_update_one_slot_and_keep_latest_tokens_and_history() {
    let f = Fixture::new();
    let r = Reporter::channel(None);
    let p = Policy::default();
    let mut s = store::Store::open(&f.vault, &f.home).unwrap();
    s.db.configure_browser(true,false,None).unwrap();
    let initial_browser = s.db.browser_slot().unwrap();
    f.login("A", "one", "a-first");
    f.write(".claude/history.jsonl", b"a-history");
    s.switch("empty", "A custom", &p, &r).unwrap();
    let a = s.records()[0].id.clone();
    assert_eq!(a, initial_browser);
    assert_eq!(s.db.browser_for(&a).unwrap().as_deref(), Some(initial_browser.as_str()));
    let browser_b = s.db.browser_slot().unwrap();
    assert_ne!(browser_b, initial_browser);
    f.login("B", "one", "b-first");
    f.write(".claude/history.jsonl", b"b-history");
    s.switch(&a, "B custom", &p, &r).unwrap();
    let b = s.records().into_iter().find(|row| row.id != a).unwrap().id;
    assert_eq!(f.token(), "a-first");
    for n in 0..4 {
        f.login("A", "one", &format!("a-refresh-{n}"));
        f.write(".claude/history.jsonl", format!("a-new-{n}").as_bytes());
        assert_eq!(
            catalog::current_id(&f.vault, &f.home, &s.db)
                .unwrap()
                .as_deref(),
            Some(a.as_str())
        );
        s.switch(&b, "name changed", &p, &r).unwrap();
        assert_eq!(
            f.token(),
            if n == 0 {
                "b-first".into()
            } else {
                format!("b-refresh-{}", n - 1)
            }
        );
        f.login("B", "one", &format!("b-refresh-{n}"));
        s.switch(&a, "another name", &p, &r).unwrap();
        assert_eq!(f.token(), format!("a-refresh-{n}"));
        assert_eq!(
            fs::read(f.home.join(".claude/history.jsonl")).unwrap(),
            format!("a-new-{n}").as_bytes()
        );
        assert_eq!(s.records().len(), 2);
        assert_eq!(s.db.browser_slot().unwrap(), initial_browser);
        assert_eq!(s.db.browser_for(&b).unwrap().as_deref(),Some(browser_b.as_str()));
    }
    assert_eq!(
        s.records().iter().find(|row| row.id == a).unwrap().name,
        "A custom"
    );
    // 已经是 A 时不允许用旧 A 快照覆盖当前新令牌。
    f.login("A", "one", "a-live");
    s.switch(&a, "same", &p, &r).unwrap();
    assert_eq!(f.token(), "a-live");
    s.fail_after_clear = true;
    assert!(s.switch(&b, "failure", &p, &r).is_err());
    assert_eq!(f.token(), "a-live");
    assert_eq!(s.records().len(), 2);
    assert!(s.db.get("recovery").unwrap().is_none());
    drop(s);
    let s = store::Store::open(&f.vault, &f.home).unwrap();
    let generations = fs::read_dir(&f.vault)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|e| e == "baga"))
        .count();
    assert_eq!(generations, s.records().len());
}
#[test]
fn matching_is_private_stable_and_never_collapses_unknown_or_other_organizations() {
    let key = [8; 32];
    let a = serde_json::json!({"oauthAccount":{"accountUuid":"A","organizationUuid":"one","emailAddress":"old@example.invalid"}});
    let renamed = serde_json::json!({"oauthAccount":{"accountUuid":"A","organizationUuid":"one","emailAddress":"new@example.invalid","displayName":"changed"}});
    assert_eq!(
        catalog::account_key(&a, &key),
        catalog::account_key(&renamed, &key)
    );
    let mut other = a.clone();
    other["oauthAccount"]["organizationUuid"] = "two".into();
    assert_ne!(
        catalog::account_key(&a, &key),
        catalog::account_key(&other, &key)
    );
    assert_ne!(
        catalog::account_key(&a, &key),
        catalog::account_key(&a, &[9; 32])
    );
    assert!(catalog::account_key(
        &serde_json::json!({"oauthAccount":{"displayName":"unknown"}}),
        &key
    )
    .is_none());
    let f = Fixture::new();
    f.login("A", "one", "token");
    let mut s = store::Store::open(&f.vault, &f.home).unwrap();
    s.switch("empty", "one", &Policy::default(), &Reporter::channel(None))
        .unwrap();
    let a = s.records()[0].id.clone();
    f.login("B", "one", "manual-login");
    assert!(catalog::current_id(&f.vault, &f.home, &s.db)
        .unwrap()
        .is_none());
    f.login("A", "two", "different-org");
    s.switch(&a, "two", &Policy::default(), &Reporter::channel(None))
        .unwrap();
    assert_eq!(s.records().len(), 2);
    assert!(!serde_json::to_string(&s.records())
        .unwrap()
        .contains("account_key"));
}
#[test]
fn gzip_compatibility_and_zstd_authentication_are_preserved() {
    let data = vec![55; 2 * 1024 * 1024];
    let key = [7; 32];
    for legacy in [true, false] {
        let seal = codec::Seal::new(Vec::new(), &key).unwrap();
        let encrypted = if legacy {
            let mut gzip = flate2::write::GzEncoder::new(seal, flate2::Compression::default());
            gzip.write_all(&data).unwrap();
            gzip.finish().unwrap().finish().unwrap()
        } else {
            let mut encoder = compression::encode(seal).unwrap();
            encoder.write_all(&data).unwrap();
            encoder.finish().unwrap().finish().unwrap()
        };
        let decode = |bytes: Vec<u8>| {
            let open = codec::Open::new(std::io::Cursor::new(bytes), &key)?;
            let mut decoded = compression::decode(open)?;
            let mut result = Vec::new();
            decoded.read_to_end(&mut result)?;
            Ok::<_, std::io::Error>(result)
        };
        assert_eq!(decode(encrypted.clone()).unwrap(), data);
        for cut in [1, 16, 20] {
            assert!(decode(encrypted[..encrypted.len() - cut].to_vec()).is_err());
        }
        let mut extra = encrypted.clone();
        extra.push(0);
        assert!(decode(extra).is_err());
        let mut damaged = encrypted;
        damaged[80] ^= 1;
        assert!(decode(damaged).is_err());
    }
}
#[test]
fn updating_an_archive_commits_the_new_generation_with_its_recovery_marker() {
    let f = Fixture::new();
    f.login("A", "one", "old");
    let mut s = store::Store::open(&f.vault, &f.home).unwrap();
    let p = Policy::default();
    let r = Reporter::channel(None);
    s.switch("empty", "A", &p, &r).unwrap();
    let old = s.records()[0].clone();
    s.switch(&old.id, "empty", &p, &r).unwrap();
    f.login("A", "one", "latest");
    let (new, stage) = s.save("update", &p, &r).unwrap();
    assert_eq!(old.id, new.id);
    assert_ne!(old.archive, new.archive);
    assert_eq!(
        s.db.by_account(new.account_key.as_deref().unwrap())
            .unwrap()
            .unwrap()
            .archive,
        old.archive
    );
    s.db.pending(&new, "empty").unwrap();
    s.clear(&store::Store::selected(&stage, &p)).unwrap();
    drop(stage);
    drop(s);
    let mut s = store::Store::open(&f.vault, &f.home).unwrap();
    assert_eq!(
        s.db.get("recovery").unwrap().as_deref(),
        Some(old.id.as_str())
    );
    s.recover("checkpoint", &r).unwrap();
    assert_eq!(f.token(), "latest");
}
#[test]
#[ignore = "manual synthetic performance measurement"]
fn synthetic_switch_and_compression_benchmark() {
    let f = Fixture::new();
    f.login("A", "one", "fixture");
    // 代表性 JSONL：重复结构、变化文本、500 个会话；仅人工合成数据。
    let mut data = Vec::new();
    for n in 0..150_000u64 {
        writeln!(data,"{{\"role\":\"assistant\",\"id\":{n},\"content\":\"synthetic session tool output {}\"}}", n.wrapping_mul(2654435761u64)).unwrap();
    }
    let start = Instant::now();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&data).unwrap();
    let gzip = gzip.finish().unwrap();
    let gz_time = start.elapsed();
    let start = Instant::now();
    let mut zstd = compression::encode(Vec::new()).unwrap();
    zstd.write_all(&data).unwrap();
    let zstd = zstd.finish().unwrap();
    let zs_time = start.elapsed();
    for n in 0..500 {
        f.write(
            &format!(".claude/projects/fixture/{n}.jsonl"),
            &data[n * 100..n * 100 + 256 * 1024],
        );
    }
    let mut s = store::Store::open(&f.vault, &f.home).unwrap();
    let start = Instant::now();
    s.switch("empty", "A", &Policy::default(), &Reporter::channel(None))
        .unwrap();
    let stash = start.elapsed();
    let id = s.records().into_iter().find(|r| !r.empty).unwrap().id;
    let start = Instant::now();
    s.switch(&id, "empty", &Policy::default(), &Reporter::channel(None))
        .unwrap();
    let restore = start.elapsed();
    eprintln!("synthetic {} bytes: gzip={} bytes {:?}; zstd={} bytes {:?}; 500-file stash {:?}; restore {:?}",data.len(),gzip.len(),gz_time,zstd.len(),zs_time,stash,restore);
    assert!(zstd.len() < data.len());
    assert_eq!(f.token(), "fixture");
}

#[test]
fn rejected_catalog_update_never_replaces_the_committed_archive_or_live_account() {
    let f = Fixture::new();
    let p = Policy::default();
    let r = Reporter::channel(None);
    let mut s = store::Store::open(&f.vault, &f.home).unwrap();
    f.login("A", "one", "a-old");
    s.switch("empty", "A", &p, &r).unwrap();
    let a = s.records()[0].clone();
    f.login("B", "one", "b-old");
    s.switch(&a.id, "B", &p, &r).unwrap();
    let b = s.records().into_iter().find(|row| row.id != a.id).unwrap();
    let committed = fs::read(f.vault.join(&a.archive)).unwrap();
    f.login("A", "one", "a-live");
    let connection = rusqlite::Connection::open(f.vault.join("identities.sqlite")).unwrap();
    connection.execute_batch("CREATE TRIGGER reject_update BEFORE UPDATE ON identities BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(s.switch(&b.id, "update", &p, &r).is_err());
    assert_eq!(f.token(), "a-live");
    assert_eq!(fs::read(f.vault.join(&a.archive)).unwrap(), committed);
    assert_eq!(
        s.db.by_account(a.account_key.as_deref().unwrap())
            .unwrap()
            .unwrap()
            .archive,
        a.archive
    );
    assert!(s.db.get("recovery").unwrap().is_none());
}

#[test]
fn version_one_gzip_catalog_migrates_and_old_duplicate_targets_remain_usable() {
    let f = Fixture::new();
    let p = Policy::default();
    let r = Reporter::channel(None);
    let s = store::Store::open(&f.vault, &f.home).unwrap();
    let mut ids = Vec::new();
    for n in 0..2 {
        f.login("A", "one", &format!("legacy-{n}"));
        let (mut record, stage) = s.save_checkpoint("legacy", &p, &r).unwrap();
        let original = record.archive.clone();
        record.archive = format!("{}.baga", record.id);
        record.account_key = None;
        record.saved_at = n + 1;
        let open =
            codec::Open::new(fs::File::open(f.vault.join(&original)).unwrap(), &s.key).unwrap();
        let decoded = compression::decode(open).unwrap();
        let mut old_tar = tar::Archive::new(decoded);
        let seal = codec::Seal::new(
            private::create(&f.vault.join(&record.archive)).unwrap(),
            &s.key,
        )
        .unwrap();
        let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
            seal,
            flate2::Compression::default(),
        ));
        for entry in old_tar.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            if path == std::path::Path::new("manifest.json") {
                let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                value.as_object_mut().unwrap().remove("account_key");
                bytes = serde_json::to_vec(&value).unwrap();
            }
            let mut header = entry.header().clone();
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, &path, &bytes[..]).unwrap();
        }
        let file = tar
            .into_inner()
            .unwrap()
            .finish()
            .unwrap()
            .finish()
            .unwrap();
        file.sync_all().unwrap();
        s.db.remember(&record).unwrap();
        ids.push(record.id);
        fs::remove_file(f.vault.join(original)).unwrap();
        drop(stage);
    }
    drop(s);
    let connection = rusqlite::Connection::open(f.vault.join("identities.sqlite")).unwrap();
    connection
        .execute_batch("ALTER TABLE identities DROP COLUMN account_key; PRAGMA user_version=1;")
        .unwrap();
    drop(connection);
    let mut s = store::Store::open(&f.vault, &f.home).unwrap();
    assert_eq!(s.records().len(), 2);
    assert!(s
        .records()
        .iter()
        .all(|row| row.account_key.as_ref().is_some_and(|key| !key.is_empty())));
    // 旧 UI 仍可传入迁移前的卡片编号；同账号切换不回灌过期凭据。
    s.switch(&ids[0], "current", &p, &r).unwrap();
    assert_eq!(f.token(), "legacy-1");
    assert_eq!(s.records().len(), 1);
    assert_eq!(s.records()[0].id, ids[1]);
}
