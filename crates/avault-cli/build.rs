fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TARGET");

    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("linux") {
        println!("cargo:rustc-link-lib=dylib=tss2-esys");
        println!("cargo:rustc-link-lib=dylib=tss2-sys");
        println!("cargo:rustc-link-lib=dylib=tss2-tctildr");
        println!("cargo:rustc-link-lib=dylib=tss2-mu");
        println!("cargo:rustc-link-lib=dylib=crypto");
    }
}
