use anyhow::Result;
use init::init;

mod init;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_todo() -> Result<()> {
        init()?;

        Ok(())
    }
}
