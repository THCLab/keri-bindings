use std::{env, path::Path};

use flapigen::{LanguageConfig, PythonConfig};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    flapigen_expand(
        Path::new("src/glue.rs.in"),
        &Path::new(&out_dir).join("glue.rs"),
    );
}

fn flapigen_expand(from: &Path, out: &Path) {
    println!("Run flapigen_expand");
    let lib_name = "libsai_python";
    let python_cfg = PythonConfig::new(lib_name.to_owned());
    let flapigen =
        flapigen::Generator::new(LanguageConfig::PythonConfig(python_cfg)).rustfmt_bindings(true);
    flapigen.expand(lib_name, from, out);
}
