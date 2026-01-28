use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package_0 = packages
        .clone()
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "nerscfslat-ebpf-close")
        .ok_or_else(|| anyhow!("nerscfslat-ebpf-close package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package_0;
    let ebpf_package_0 = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    match aya_build::build_ebpf([ebpf_package_0], Toolchain::default()) {
        Ok(_) => {}
        Err(err) => return Err(err),
    }

    let ebpf_package_1 = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "nerscfslat-ebpf-fsync")
        .ok_or_else(|| anyhow!("nerscfslat-ebpf-fsync package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package_1;
    let ebpf_package_1 = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    match aya_build::build_ebpf([ebpf_package_1], Toolchain::default()) {
        Ok(_) => return Ok(()),
        Err(err) => return Err(err),
    }
}
