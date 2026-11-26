fn main() {
  napi_build::setup();

  // Resolve against the manifest directory, not the process cwd: cargo runs
  // build scripts from the workspace root for some invocations (and a vendored
  // or mirrored build may run them elsewhere entirely).
  let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  let package_path = manifest_dir.join("package.json");
  let package = std::fs::read_to_string(&package_path)
    .unwrap_or_else(|e| panic!("{} should be readable: {e}", package_path.display()));
  let package: serde_json::Value =
    serde_json::from_str(&package).expect("package.json should be valid JSON");
  let version = package["version"]
    .as_str()
    .expect("package.json should have a string version");

  println!("cargo:rustc-env=NODE_YARA_X_VERSION={version}");
  println!("cargo:rerun-if-changed={}", package_path.display());
}
