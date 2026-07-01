fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=HOST");
    println!("cargo:rerun-if-env-changed=TARGET");

    let host = std::env::var("HOST").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();
    // Cross cfg checks do not need host linker paths; the release Linux jobs are native.
    if target == host && target.contains("linux") {
        print_pkg_config_libdir("libcrypto");
        print_gcc_file_libdir("libatomic.a");
        print_gcc_file_libdir("libgcc.a");
        // Keep TPM/OpenSSL static so the CLI can start on hosts without tpm2-tss installed.
        for arg in [
            "-Wl,-Bstatic",
            "-Wl,--start-group",
            "-ltss2-esys",
            "-ltss2-sys",
            "-ltss2-tctildr",
            "-ltss2-tcti-device",
            "-ltss2-mu",
            "-lcrypto",
            "-latomic",
            "-lgcc",
            "-Wl,--end-group",
            "-Wl,-Bdynamic",
            "-lc",
        ] {
            println!("cargo:rustc-link-arg={arg}");
        }
    }
}

fn print_pkg_config_libdir(package: &str) {
    let output = std::process::Command::new("pkg-config")
        .args(["--variable=libdir", package])
        .output()
        .unwrap_or_else(|err| panic!("failed to run pkg-config for {package}: {err}"));
    if !output.status.success() {
        panic!(
            "pkg-config failed for {package}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let libdir = String::from_utf8(output.stdout)
        .unwrap_or_else(|err| panic!("pkg-config returned non-UTF-8 libdir for {package}: {err}"));
    println!("cargo:rustc-link-search=native={}", libdir.trim());
}

fn print_gcc_file_libdir(file: &str) {
    let output = std::process::Command::new("gcc")
        .arg(format!("-print-file-name={file}"))
        .output()
        .unwrap_or_else(|err| panic!("failed to run gcc for {file}: {err}"));
    if !output.status.success() {
        panic!(
            "gcc failed while locating {file}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let path = String::from_utf8(output.stdout)
        .unwrap_or_else(|err| panic!("gcc returned non-UTF-8 path for {file}: {err}"));
    let path = std::path::Path::new(path.trim());
    let libdir = path
        .parent()
        .unwrap_or_else(|| panic!("gcc did not return a path for {file}: {}", path.display()));
    println!("cargo:rustc-link-search=native={}", libdir.display());
}
