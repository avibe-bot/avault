//! avault-store — where avault's own key material lives.
//!
//! P1 implements the standard-tier `file + mlock` floor: a 32-byte master key in a
//! 0600 file, read into a zeroizing buffer, with best-effort no-core/no-swap hardening.
//! Stronger stores (Keychain / Secure Enclave / TPM / KMS) are P2+.

use anyhow::{bail, Context};
use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// Master key size for the standard-tier store.
pub const MASTER_KEY_BYTES: usize = 32;

/// Selected master-key storage backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Tpm,
    Keychain,
    File,
}

/// The loaded master key. The buffer is zeroized on drop and mlock'd where available.
pub struct MasterKey {
    key: Box<Zeroizing<[u8; MASTER_KEY_BYTES]>>,
}

impl MasterKey {
    fn zeroed_locked() -> Self {
        let key = Box::new(Zeroizing::new([0u8; MASTER_KEY_BYTES]));
        harden_process_memory();
        lock_memory(key.as_ptr(), MASTER_KEY_BYTES);
        Self { key }
    }

    fn generate_locked() -> Self {
        let mut key = Self::zeroed_locked();
        OsRng.fill_bytes(key.key.as_mut().as_mut());
        key
    }

    /// Borrow the key for a single crypto operation.
    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_BYTES] {
        self.key.as_ref()
    }

    fn as_mut_bytes(&mut self) -> &mut [u8; MASTER_KEY_BYTES] {
        self.key.as_mut()
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.key.as_mut().zeroize();
        unlock_memory(self.key.as_ptr(), MASTER_KEY_BYTES);
    }
}

/// Return the default P1 master-key path: `$AVAULT_HOME/machine.key` or
/// `$HOME/.avibe/state/vault/machine.key`.
pub fn default_master_key_path() -> anyhow::Result<PathBuf> {
    if let Some(home) = env::var_os("AVAULT_HOME") {
        return Ok(PathBuf::from(home).join("machine.key"));
    }
    let home = env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join(".avibe")
        .join("state")
        .join("vault")
        .join("machine.key"))
}

/// Load the 32-byte master key, or create it on first use.
pub fn load_or_create_master_key(backend: Backend) -> anyhow::Result<MasterKey> {
    match backend {
        Backend::File => FileStore::new(default_master_key_path()?).get_or_create(),
        Backend::Tpm | Backend::Keychain => {
            bail!("requested master-key backend is not implemented in P1")
        }
    }
}

/// Load the existing 32-byte master key. This never creates a replacement key.
pub fn load_master_key(backend: Backend) -> anyhow::Result<MasterKey> {
    match backend {
        Backend::File => FileStore::new(default_master_key_path()?).get(),
        Backend::Tpm | Backend::Keychain => {
            bail!("requested master-key backend is not implemented in P1")
        }
    }
}

/// P1 file-backed master-key store.
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return the master key, creating it atomically as a 0600 file if missing.
    pub fn get_or_create(&self) -> anyhow::Result<MasterKey> {
        match self.get() {
            Ok(key) => Ok(key),
            Err(_) => {
                self.create_atomic()?;
                self.get()
            }
        }
    }

    /// Return the existing master key, or error if missing/corrupt.
    pub fn get(&self) -> anyhow::Result<MasterKey> {
        validate_file_mode(&self.path)?;
        let mut file = File::open(&self.path).with_context(|| "master key not found")?;

        let mut key = MasterKey::zeroed_locked();
        file.read_exact(key.as_mut_bytes())
            .with_context(|| "master key has invalid length")?;
        let mut extra = [0u8; 1];
        match file.read(&mut extra) {
            Ok(0) => {}
            Ok(_) => bail!("master key has invalid length"),
            Err(err) => return Err(err).context("failed to validate master key length"),
        }
        Ok(key)
    }

    /// Import a master key, refusing to overwrite unless `force` is true.
    pub fn import(&self, key: &[u8; MASTER_KEY_BYTES], force: bool) -> anyhow::Result<()> {
        self.ensure_parent()?;
        if self.path.exists() && !force {
            bail!("master key already exists");
        }

        let parent = self
            .path
            .parent()
            .context("master key path has no parent")?;
        let mut tmp = tempfile::Builder::new()
            .prefix(".machine.")
            .suffix(".tmp")
            .tempfile_in(parent)
            .context("failed to create temporary master key file")?;
        tmp.as_file_mut()
            .write_all(key)
            .context("failed to write temporary master key file")?;
        tmp.as_file_mut()
            .sync_all()
            .context("failed to sync temporary master key file")?;

        if force {
            tmp.persist(&self.path)
                .map_err(|err| err.error)
                .context("failed to install imported master key")?;
        } else {
            tmp.persist_noclobber(&self.path)
                .map_err(|err| err.error)
                .context("master key already exists")?;
        }
        validate_file_mode(&self.path)?;
        sync_parent_dir(&self.path)?;
        Ok(())
    }

    fn create_atomic(&self) -> anyhow::Result<()> {
        self.ensure_parent()?;

        let key = MasterKey::generate_locked();

        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        match options.open(&self.path) {
            Ok(mut file) => {
                file.write_all(key.as_bytes())
                    .context("failed to write new master key")?;
                file.sync_all().context("failed to sync new master key")?;
                sync_parent_dir(&self.path)?;
                Ok(())
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(err) => Err(err).context("failed to create master key"),
        }
    }

    fn ensure_parent(&self) -> anyhow::Result<()> {
        let parent = self
            .path
            .parent()
            .context("master key path has no parent")?;
        fs::create_dir_all(parent).context("failed to create master key directory")?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).ok();
        Ok(())
    }
}

fn sync_parent_dir(path: &Path) -> anyhow::Result<()> {
    let parent = path.parent().context("master key path has no parent")?;
    File::open(parent)
        .context("failed to open master key directory")?
        .sync_all()
        .context("failed to sync master key directory")
}

fn validate_file_mode(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::metadata(path).context("failed to stat master key")?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!("master key mode is too open");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn harden_process_memory() {
    // Safety invariant: `prctl(PR_SET_DUMPABLE, 0)` changes the current process dumpability
    // and does not dereference user pointers. It prevents key pages from entering core dumps.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
}

#[cfg(not(target_os = "linux"))]
fn harden_process_memory() {}

#[cfg(target_os = "linux")]
fn lock_memory(ptr: *const u8, len: usize) {
    let (base, span) = page_span(ptr, len);
    // Safety invariant: the pointer/length describe the live master-key array owned by
    // `MasterKey`; `mlock` and `madvise` do not mutate Rust-visible contents. Failures are
    // best-effort because unprivileged systems may cap `RLIMIT_MEMLOCK`.
    unsafe {
        libc::mlock((base as *const u8).cast(), span);
        libc::madvise((base as *mut u8).cast(), span, libc::MADV_DONTDUMP);
    }
}

#[cfg(target_os = "macos")]
fn lock_memory(ptr: *const u8, len: usize) {
    // Safety invariant: the pointer/length describe the live master-key array owned by
    // `MasterKey`; `mlock` does not mutate Rust-visible contents. macOS has no
    // `MADV_DONTDUMP`, so this is best-effort only.
    unsafe {
        libc::mlock(ptr.cast(), len);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn lock_memory(_ptr: *const u8, _len: usize) {}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unlock_memory(ptr: *const u8, len: usize) {
    #[cfg(target_os = "linux")]
    let (base, span) = page_span(ptr, len);
    #[cfg(target_os = "macos")]
    let (base, span) = (ptr as usize, len);
    // Safety invariant: the pointer/length still refer to the master-key array during
    // `Drop`; `munlock` releases the page-lock after the explicit zeroize in `Drop`.
    unsafe {
        libc::munlock((base as *const u8).cast(), span);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn unlock_memory(_ptr: *const u8, _len: usize) {}

#[cfg(target_os = "linux")]
fn page_span(ptr: *const u8, len: usize) -> (usize, usize) {
    // Safety invariant: `sysconf(_SC_PAGESIZE)` reads process configuration and does not
    // dereference user pointers. A bad return falls back to the common 4096-byte page.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = usize::try_from(page)
        .ok()
        .filter(|p| *p > 0)
        .unwrap_or(4096);
    let start = (ptr as usize / page) * page;
    let end = (ptr as usize + len).div_ceil(page) * page;
    (start, end.saturating_sub(start))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_reads_key_with_0600_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileStore::new(tmp.path().join("machine.key"));
        let first = store.get_or_create().unwrap();
        assert_eq!(first.as_bytes().len(), MASTER_KEY_BYTES);
        let mode = fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let second = store.get().unwrap();
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn get_errors_if_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileStore::new(tmp.path().join("machine.key"));
        assert!(store.get().is_err());
    }

    #[test]
    fn refuses_loose_mode_on_read() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileStore::new(tmp.path().join("machine.key"));
        store.get_or_create().unwrap();
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.get().is_err());
    }

    #[test]
    fn import_refuses_overwrite_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileStore::new(tmp.path().join("machine.key"));
        store.get_or_create().unwrap();
        let key = [9u8; MASTER_KEY_BYTES];
        assert!(store.import(&key, false).is_err());
        store.import(&key, true).unwrap();
        assert_eq!(store.get().unwrap().as_bytes(), &key);
    }

    #[test]
    fn import_does_not_reuse_stale_temp_file() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileStore::new(tmp.path().join("machine.key"));
        let stale_tmp = tmp.path().join("machine.tmp");
        fs::write(&stale_tmp, [3u8; MASTER_KEY_BYTES]).unwrap();
        fs::set_permissions(&stale_tmp, fs::Permissions::from_mode(0o644)).unwrap();

        let key = [9u8; MASTER_KEY_BYTES];
        store.import(&key, false).unwrap();
        assert_eq!(store.get().unwrap().as_bytes(), &key);
        let mode = fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(stale_tmp.exists());
    }
}
