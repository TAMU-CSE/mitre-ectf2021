use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    File::create(out_path.join("memory.x"))
        .unwrap()
        .write_all(include_bytes!("memory.x"))
        .unwrap();
    println!("cargo:rustc-link-search={}", out_path.display());

    println!("cargo:rerun-if-changed=memory.x");

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
        .whitelist_type("UART_Type")
        .generate()
        .expect("Unable to generate bindings");

    cmsis
        .write_to_file(out_path.join("cmsis.rs"))
        .expect("Couldn't write bindings!");
}
