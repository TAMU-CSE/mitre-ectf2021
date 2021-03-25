use std::env;
use std::path::Path;

use std::error::Error;
use std::fs::File;
use std::io::Write;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SCEWL_ID");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let values_path = Path::new(&out_dir).join("values.rs");
    let mut values = File::create(values_path)?;

    let id = env::var("SCEWL_ID");
    match id {
        Ok(id) => {
            let id = id.parse::<u16>()?;

            values.write_all(
                format!(
                    r#"
#[doc(hidden)]
const SCEWL_ID: u16 = {};

#[doc(hidden)]
const SECRET: [u8; 64] = *include_bytes!("/sed/{}_secret");
                    "#,
                    id, id
                )
                .as_ref(),
            )?;
        }
        Err(_) => {
            println!("cargo:warning=Default values used for SCEWL_ID and SECRET");

            values.write_all(
                r#"
#[doc(hidden)]
const SCEWL_ID: u16 = 0;

#[doc(hidden)]
const SECRET: [u8; 64] = [0_u8; 64];
                    "#
                .as_ref(),
            )?;
        }
    }

    Ok(())
}
