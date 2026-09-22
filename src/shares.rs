//! Shares on disk, for a signer that is a process rather than a person.
//!
//! One file per share plus the public package, for any ciphersuite. A share
//! file is the whole authority of one participant, so it belongs on that
//! participant's machine and nowhere else — a directory holding *all* of them
//! is a devnet holding one key in several pieces, and the node says so when
//! it loads one.

use std::path::Path;

use frost_core::Ciphersuite;

use crate::ceremony::{IdentifierFor, ThresholdKeys};

/// Write a secret so that only its owner can read it.
///
/// A share file is the whole authority of one participant. Written with the
/// process umask it lands world-readable on a typical machine, which means
/// any other account on the box is a member of the quorum. The mode is set
/// **before** the bytes are written, not after, so there is no window in
/// which the file exists and is readable.
#[cfg(unix)]
fn write_secret(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Elsewhere the filesystem is expected to carry the restriction, and the
/// caller is told so rather than being left to assume this did it.
#[cfg(not(unix))]
fn write_secret(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

pub fn save<C: Ciphersuite>(
    dir: &Path,
    keys: &[(IdentifierFor<C>, ThresholdKeys<C>)],
) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    // The directory too: a listing of share filenames tells an onlooker which
    // participants live here, and a writable directory lets one be replaced.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    for (id, k) in keys {
        let name = format!("share-{}.bin", hex(&id.serialize()));
        write_secret(&dir.join(name), &k.key_package.serialize().map_err(bad)?)?;
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

#[cfg(all(test, unix))]
mod permissions {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A share file is the whole authority of one participant. Written with
    /// the process umask it lands world-readable on a typical machine, which
    /// makes every other account on the box a member of the quorum.
    #[test]
    fn a_share_is_readable_only_by_its_owner() {
        let dir = std::env::temp_dir().join(format!("zecms-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let keys: Vec<_> = crate::ceremony::Ceremony::new(2, 3)
            .expect("2 of 3 is a vault")
            .run(&mut rand::rngs::OsRng)
            .expect("ceremony")
            .into_iter()
            .collect();
        save(&dir, &keys).expect("save");

        let mut seen = 0;
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let mode = e.metadata().unwrap().permissions().mode() & 0o777;
            if name.starts_with("share-") {
                assert_eq!(mode, 0o600, "{name} must be owner-only, got {mode:o}");
                seen += 1;
            }
        }
        assert!(seen >= 3, "every share was checked (saw {seen})");

        let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "the directory must not be listable by others");

        // And they still load, so the restriction did not break the signer.
        let back = load::<crate::ceremony::Zcash>(&dir).expect("load");
        assert_eq!(back.len(), keys.len());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
