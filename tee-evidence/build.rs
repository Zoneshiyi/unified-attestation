use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if cfg!(not(all(target_os = "linux", target_arch = "x86_64"))) {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    if env::var_os("CARGO_FEATURE_CSV_USER_ATTESTER").is_some() {
        build_csv_backend(
            "csv_user_attestation",
            &manifest_dir.join("src/csv_user/csv_user_attestation.c"),
            &manifest_dir.join("src/csv_user"),
            &[
                "csv_user_attestation_report_size",
                "csv_user_get_attestation_report",
            ],
        );
    }

    if env::var_os("CARGO_FEATURE_CSV_KERNEL_ATTESTER").is_some() {
        build_csv_backend(
            "csv_kernel_attestation",
            &manifest_dir.join("src/csv_kernel/csv_kernel_attestation.c"),
            &manifest_dir.join("src/csv_kernel"),
            &[
                "csv_kernel_attestation_report_size",
                "csv_kernel_get_attestation_report",
            ],
        );
    }
}

fn build_csv_backend(lib_name: &str, source: &Path, include_dir: &Path, required_symbols: &[&str]) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let object = out_dir.join(format!("{lib_name}.o"));

    println!("cargo:rerun-if-changed={}", source.display());
    println!(
        "cargo:rerun-if-changed={}",
        include_dir.join("csv_attestation.h").display()
    );
    println!("cargo:rerun-if-env-changed=CSV_GMSSL_INCLUDE");
    println!("cargo:rerun-if-env-changed=CSV_GMSSL_LIB");

    let gmssl_include =
        env::var("CSV_GMSSL_INCLUDE").unwrap_or_else(|_| "/opt/gmssl/include".to_string());
    let gmssl_lib = env::var("CSV_GMSSL_LIB").unwrap_or_else(|_| "/opt/gmssl/lib".to_string());

    let status = Command::new("gcc")
        .arg("-Wall")
        .arg("-O2")
        .arg("-fPIC")
        .arg("-m64")
        .arg("-mrdrnd")
        .arg("-c")
        .arg(source)
        .arg("-I")
        .arg(include_dir)
        .arg("-I")
        .arg(gmssl_include)
        .arg("-o")
        .arg(&object)
        .status()
        .unwrap_or_else(|err| panic!("failed to invoke gcc for {lib_name}: {err}"));
    assert!(status.success(), "gcc failed while building {lib_name}");

    verify_symbols(lib_name, &object, required_symbols);

    println!("cargo:rustc-link-search=native={gmssl_lib}");
    println!("cargo:rustc-link-arg={}", object.display());
    println!("cargo:rustc-link-arg=-lcrypto");
}

fn verify_symbols(lib_name: &str, object: &Path, required_symbols: &[&str]) {
    let output = Command::new("nm")
        .arg("-g")
        .arg(object)
        .output()
        .unwrap_or_else(|err| panic!("failed to invoke nm for {lib_name}: {err}"));
    assert!(
        output.status.success(),
        "nm failed while checking {lib_name}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for symbol in required_symbols {
        assert!(
            stdout
                .lines()
                .any(|line| line.split_whitespace().last() == Some(*symbol)),
            "{lib_name} did not export `{symbol}`; check that the matching C file was copied into the matching src/csv_* directory"
        );
    }
}
