// src-tauri/build.rs
//
// Windows 单测崩溃修复（tauri#13419）：
// 默认 tauri_build::build() 经 tauri-winres 把应用 manifest 用 rustc-link-arg-bins
// 只链进【主二进制】，【测试可执行文件】拿不到 manifest → 测试 exe 启动时加载
// WebView2Loader 报 0xc0000139 STATUS_ENTRYPOINT_NOT_FOUND（找不到入口点）。
//
// 修法（Tauri maintainer 建议）：用 new_without_app_manifest() 关掉默认的
// 仅主二进制嵌入，改用 cargo:rustc-link-arg（作用于所有产物含测试 exe）手动嵌入
// 同一份 manifest。生产行为不变（同一份 manifest，只是嵌入范围扩到测试产物）。

fn main() {
    // 编译期注入的默认 hub 地址（见 daemon/config.rs DEFAULT_HUB_URL）：变了要重编
    println!("cargo:rerun-if-env-changed=HANAKO_DEFAULT_HUB_URL");
    println!("cargo:rerun-if-env-changed=HANAKO_BUILD_SHA");
    #[allow(unused_mut)] // 仅 windows 分支需要 mut（重绑定 attributes）
    let mut attributes = tauri_build::Attributes::new();
    #[cfg(windows)]
    {
        attributes = attributes
            .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest());
        embed_manifest_for_all_targets();
    }
    tauri_build::try_build(attributes).expect("tauri_build 失败");
}

/// 把 Windows 应用 manifest 用 rustc-link-arg 嵌入所有产物（含测试 exe）。
/// manifest 内容与 tauri-build 默认内嵌的 windows-app-manifest.xml 完全一致。
#[cfg(windows)]
fn embed_manifest_for_all_targets() {
    let manifest = std::env::current_dir()
        .expect("取当前目录失败")
        .join("windows-app-manifest.xml");
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.to_str().unwrap());
}
