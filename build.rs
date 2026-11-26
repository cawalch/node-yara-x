fn main() {
  napi_build::setup();

  let package = std::fs::read_to_string("package.json")
    .expect("package.json should be readable from the crate root");
  let package: serde_json::Value =
    serde_json::from_str(&package).expect("package.json should be valid JSON");
  let version = package["version"]
    .as_str()
    .expect("package.json should have a string version");

  println!("cargo:rustc-env=NODE_YARA_X_VERSION={version}");
  println!("cargo:rerun-if-changed=package.json");
}
