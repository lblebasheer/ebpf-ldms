use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;

    let ebpf_crate_names = [
        "nerscfslat-ebpf-close",
        "nerscfslat-ebpf-fsync",
        "nerscfslat-ebpf-writev",
        "nerscfslat-ebpf-write",
    ];

    let found: Vec<_> = ebpf_crate_names
        .iter()
        .map(|crate_name| {
            packages
                .iter()
                .find(|p| p.name.as_str() == *crate_name)
                .ok_or_else(|| anyhow!("{crate_name} package not found"))
        })
        .collect::<anyhow::Result<_>>()?;

    let ebpf_packages: Vec<_> = found
        .iter()
        .map(|p| -> anyhow::Result<aya_build::Package<'_>> {
            Ok(aya_build::Package {
                name: p.name.as_str(),
                root_dir: p
                    .manifest_path
                    .parent()
                    .ok_or_else(|| anyhow!("no parent for {}", p.manifest_path))?
                    .as_str(),
                ..Default::default()
            })
        })
        .collect::<anyhow::Result<_>>()?;

    aya_build::build_ebpf(ebpf_packages, Toolchain::default())?;
    Ok(())
}
