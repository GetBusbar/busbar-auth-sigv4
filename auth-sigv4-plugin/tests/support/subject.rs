use std::path::{Path, PathBuf};
use std::process::Command;

/// The real `busbar` binary, built (once, cached by cargo) from `BUSBAR_CHECKOUT` with its default
/// features. An unset `BUSBAR_CHECKOUT` is a FAILURE everywhere, never a skip: a security claim
/// ("SigV4 is never sent unsigned") must not pass by not running.
pub fn busbar_exe() -> PathBuf {
    let Some(dir) = std::env::var_os("BUSBAR_CHECKOUT") else {
        panic!(
            "BUSBAR_CHECKOUT is unset: this end-to-end suite needs a busbar checkout at .busbar-ref \
             (plugin CI sets it with `busbar_checkout: true`; locally export BUSBAR_CHECKOUT=<path>). \
             It never skips, because a skipped run proves nothing about 'never sent unsigned'"
        );
    };
    let root = PathBuf::from(dir)
        .canonicalize()
        .expect("BUSBAR_CHECKOUT names an existing busbar checkout");
    let target = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").expect(
        "CARGO_TARGET_DIR must name the coordinator-assigned target for the actual binary build",
    ));
    assert!(
        target.is_absolute() && target.is_dir(),
        "CARGO_TARGET_DIR must name the existing absolute assigned target"
    );
    let toolchain = format!("+{}", busbar_toolchain(&root));
    static BUILT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    BUILT.get_or_init(|| {
        let status = Command::new("cargo")
            .args([
                toolchain.as_str(),
                "build",
                "--locked",
                "-j2",
                "--release",
                "--manifest-path",
                "dist/default/Cargo.toml",
                "--bin",
                "busbar",
            ])
            .current_dir(&root)
            .status()
            .expect("run cargo build for busbar");
        assert!(
            status.success(),
            "building the real busbar binary must succeed"
        );
    });
    target.join("release/busbar")
}

/// The toolchain channel the busbar checkout at `root` pins (its `rust-toolchain.toml`): the core
/// is built with its own compiler, never a copy of the version held here.
fn busbar_toolchain(root: &Path) -> String {
    let pin = std::fs::read_to_string(root.join("rust-toolchain.toml"))
        .expect("the busbar checkout pins its toolchain in rust-toolchain.toml");
    pin.lines()
        .filter_map(|line| line.trim().strip_prefix("channel"))
        .filter_map(|rest| rest.trim_start().strip_prefix('='))
        .map(|value| value.trim().trim_matches('"').to_owned())
        .find(|channel| !channel.is_empty())
        .expect("the busbar rust-toolchain.toml names a channel")
}
