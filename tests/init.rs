use anyhow::Result;
use std::sync::Once;

static INIT: Once = Once::new();

pub fn init() -> Result<()> {
    INIT.call_once(move || {
        println!("Test!");
    });

    Ok(())
}
