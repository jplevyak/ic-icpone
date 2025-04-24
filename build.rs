use anyhow::Result;
use vergen_git2::{BuildBuilder, CargoBuilder, Emitter, Git2Builder, RustcBuilder, SysinfoBuilder};

fn main() -> Result<()> {
    let build = BuildBuilder::default().build_timestamp(true).build()?;
    let cargo = CargoBuilder::default().opt_level(true).build()?;
    let rustc = RustcBuilder::default().semver(true).build()?;
    let si = SysinfoBuilder::default().cpu_core_count(true).build()?;
    let git2 = Git2Builder::all_git()?;
    Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&cargo)?
        .add_instructions(&rustc)?
        .add_instructions(&si)?
        .add_instructions(&git2)?
        .emit()?;
    Ok(())
}
