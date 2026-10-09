// src-tauri/tests/preview_contract.rs
//! 本地文件预览 票 07 · 分片协议共享契约（Bridge 侧）。
//!
//! openhanako 与 hanako-tauri 各存一份逐字节相同的 `local-preview-frames.json`，两仓测试各读自己那份：
//! ① 断言文件 SHA-256 == 约定常量（任何一边改了样例而另一边没改 → 哈希不同 → 红）；
//! ② 断言 Bridge 实际构造 / 解析的帧与样例的字段名、类型逐一对得上（任一边改字段名 → 红）。
//!
//! 服务端侧对应 `openhanako/tests/preview-dispatcher-chunked.test.js` 的 ⑦ 节，哈希常量同值。

use hanako_tauri_lib::daemon::preview::parse_preview_request;
use hanako_tauri_lib::daemon::preview_read::{end_frame, meta_frame};
use hanako_tauri_lib::daemon::preview_stream::{chunk_frame_seq, parse_pull, parse_server_abort, CHUNK_BYTES};
use sha2::{Digest, Sha256};

const FIXTURE: &str = include_str!("fixtures/local-preview-frames.json");

/// 与 openhanako 侧 `CONTRACT_SHA256` 同值。改样例必须两仓一起改。
const CONTRACT_SHA256: &str = "b713caa5e618d4161e6503f50220f46298a14df6b0b3f9852d95e6b7a572031b";

fn fx() -> serde_json::Value {
    serde_json::from_str(FIXTURE).expect("契约样例必须是合法 JSON")
}

fn keys(v: &serde_json::Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

#[test]
fn 样例文件内容与约定哈希一致() {
    let mut h = Sha256::new();
    h.update(FIXTURE.as_bytes());
    let got = format!("{:x}", h.finalize());
    assert_eq!(got, CONTRACT_SHA256, "样例被改动：两仓必须同时更新样例与哈希常量");
}

#[test]
fn 常量与实现一致() {
    let f = fx();
    assert_eq!(f["constants"]["chunkBytes"], CHUNK_BYTES);
    assert_eq!(f["constants"]["window"], 3);
    assert_eq!(f["constants"]["capability"], hanako_tauri_lib::daemon::register::PREVIEW_CAPABILITY);
}

/// 变异：把 `PreviewRequest` 解析里的 `"transfer"` 改名 → 本用例红。
#[test]
fn 能解析服务端的_preview_request_样例_含_transfer() {
    let f = fx();
    let req = parse_preview_request(&f["serverToBridge"]["preview_request"]).expect("样例必须能解析");
    assert_eq!(req.preview_id, "pv_contract_1");
    assert_eq!(req.path, "docs/report.pdf");
    assert!(req.chunked, "样例带 transfer=chunked，必须被识别为分片请求");
}

/// 变异：把「只认字面量 chunked」改成「有 transfer 字段就算」→ 本用例红。
#[test]
fn transfer_只认字面量_chunked() {
    let mut v = fx()["serverToBridge"]["preview_request"].clone();
    for bad in [serde_json::json!("single"), serde_json::json!(""), serde_json::json!("CHUNKED"), serde_json::json!(true), serde_json::json!(2)] {
        v["transfer"] = bad.clone();
        assert!(!parse_preview_request(&v).unwrap().chunked, "transfer={bad} 不得被当成分片");
    }
    v.as_object_mut().unwrap().remove("transfer");
    assert!(!parse_preview_request(&v).unwrap().chunked, "缺 transfer = 步一单帧");
}

#[test]
fn 能解析服务端的_pull_与_abort_样例() {
    let f = fx();
    assert_eq!(parse_pull(&f["serverToBridge"]["preview_pull"]), Some(("pv_contract_1".into(), 3)));
    assert_eq!(parse_server_abort(&f["serverToBridge"]["preview_abort"]), Some("pv_contract_1".into()));
}

/// 变异：Bridge 的 meta 帧字段改名 → 红。
#[test]
fn bridge_发出的_meta_end_帧形状等于样例() {
    let f = fx();
    let m = meta_frame("pv_contract_1", 5, false);
    assert_eq!(keys(&m), keys(&f["bridgeToServer"]["preview_meta"]));
    assert_eq!(m["size"], f["bridgeToServer"]["preview_meta"]["size"]);
    assert_eq!(m["truncated"], f["bridgeToServer"]["preview_meta"]["truncated"]);
    let e = end_frame("pv_contract_1");
    assert_eq!(keys(&e), keys(&f["bridgeToServer"]["preview_end"]));
}

/// 变异：分片帧去掉 seq 或改名 → 红。
#[test]
fn bridge_发出的_chunk_帧形状等于样例_含_seq() {
    let f = fx();
    let sample = &f["bridgeToServer"]["preview_chunk"];
    let c = chunk_frame_seq("pv_contract_1", sample["seq"].as_u64().unwrap(), b"hello");
    assert_eq!(keys(&c), keys(sample));
    assert_eq!(c["seq"], sample["seq"]);
    assert_eq!(c["data"], sample["data"], "样例 data = base64(\"hello\")");
}
