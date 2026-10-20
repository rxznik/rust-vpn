fn main() {
    let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let mut library_paths = std::collections::HashMap::new();
    library_paths.insert(
        "material".to_string(),
        manifest.join("third_party/material-1.1.0/material.slint"),
    );
    let config = slint_build::CompilerConfiguration::new().with_library_paths(library_paths);
    slint_build::compile_with_config("ui/app.slint", config).unwrap();
}
