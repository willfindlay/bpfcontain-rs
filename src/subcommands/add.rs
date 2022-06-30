use anyhow::{bail, Result};
use docker_api::{Containers, Docker};

use crate::{bindings, cli::Add};

/// Main entrypoint into launching a container.
pub fn main(add: &Add) -> Result<()> {
    match add {
        Add::File { pid, path } => {
            log::info!(
                "Adding {} to container running under pid {}...",
                path.display(),
                pid
            );
            bindings::ioctl::add_file_to_container(*pid, &path)?;
        }
        Add::ContainerFiles { container_id } => {
            // TODO: once we make everything async let's remove this
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    if let Err(e) = do_container_files(container_id).await {
                        log::error!("Error while adding container files: {}", e);
                        std::process::exit(-1);
                    }
                });
        }
    };

    Ok(())
}

async fn do_container_files(container_id: &str) -> Result<()> {
    // TODO make this configurable
    let docker = Docker::unix("/var/run/docker.sock");
    let container = Containers::new(docker).get(container_id).inspect().await?;

    if container.driver != "overlay2" {
        bail!(
            "storage drivers other than overlay2 are not currently supported, got: {}",
            container.driver
        )
    }

    for (_, paths) in container.graph_driver.data.iter() {
        for path in paths.split(':') {
            log::debug!("found a path: {}", path);
            for entry in jwalk::WalkDir::new(path)
                .skip_hidden(false)
                .follow_links(true)
                .into_iter()
                .filter_map(Result::ok)
            {
                if entry.file_type.is_symlink() {
                    continue;
                }
                if let Err(e) = bindings::ioctl::add_file_to_container(
                    container.state.pid as u32,
                    &entry.path(),
                ) {
                    log::error!(
                        "Failed to add file {} to container: {}",
                        entry.path().display(),
                        e
                    );
                }
            }
        }
    }

    Ok(())
}
