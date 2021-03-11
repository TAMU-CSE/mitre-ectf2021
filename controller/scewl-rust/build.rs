use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=../lm3s/lm3s_cmsis.h");

    let cmsis = bindgen::Builder::default()
        .header("../lm3s/lm3s_cmsis.h")
        .clang_arg("-I../CMSIS/Include")
        .clang_arg("-I..")
        .clang_arg("-I/usr/include/newlib/sys")
        .detect_include_paths(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .use_core()
        .ctypes_prefix("cty")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    cmsis
        .write_to_file(out_path.join("cmsis.rs"))
        .expect("Couldn't write bindings!");
}
