//! Shares on disk, for a signer that is a process rather than a person.
//!
//! One file per share plus the public package, for any ciphersuite. A share
//! file is the whole authority of one participant, so it belongs on that
//! participant's machine and nowhere else — a directory holding *all* of them
//! is a devnet holding one key in several pieces, and `zynzapd` says so when
//! it loads one.

use std::path::Path;

use frost_core::Ciphersuite;

use crate::ceremony::{IdentifierFor, ThresholdKeys};

pub fn save<C: Ciphersuite>(
    dir: &Path,
    keys: &[(IdentifierFor<C>, ThresholdKeys<C>)],
) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    for (id, k) in keys {
        let name = format!("share-{}.bin", hex(&id.serialize()));
        std::fs::write(dir.join(name), k.key_package.serialize().map_err(bad)?)?;
    }
    if let Some((_, k)) = keys.first() {
        std::fs::write(
            dir.join("public.bin"),
            k.public_package.serialize().map_err(bad)?,
        )?;
    }
    Ok(())
}

/// Load only the public package — everything a coordinator needs and no
/// secret share. A sequencer that signs through custodians holds this and no
/// `share-*.bin`, so a compromise of the sequencer box yields no key material.
pub fn load_public<C: Ciphersuite>(
    dir: &Path,
) -> std::io::Result<frost_core::keys::PublicKeyPackage<C>> {
    frost_core::keys::PublicKeyPackage::<C>::deserialize(&std::fs::read(dir.join("public.bin"))?)
        .map_err(bad)
}

pub fn load<C: Ciphersuite>(
    dir: &Path,
) -> std::io::Result<Vec<(IdentifierFor<C>, ThresholdKeys<C>)>> {
    let public = frost_core::keys::PublicKeyPackage::<C>::deserialize(&std::fs::read(
        dir.join("public.bin"),
    )?)
    .map_err(bad)?;
    let mut names: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        if !name.to_string_lossy().starts_with("share-") {
            continue;
        }
        let kp = frost_core::keys::KeyPackage::<C>::deserialize(&std::fs::read(dir.join(&name))?)
            .map_err(bad)?;
        out.push((
            *kp.identifier(),
            ThresholdKeys {
                key_package: kp,
                public_package: public.clone(),
            },
        ));
    }
    Ok(out)
}

fn bad<E: std::fmt::Debug>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e))
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
