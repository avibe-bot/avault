//! avault-store — where avault's own key material lives.
//!
//! The standard-tier master key uses the strongest implemented local store:
//! macOS Keychain when available, otherwise the file-store floor. The file store
//! keeps a 32-byte master key in an owner-only file (0600 on Unix, protected DACL
//! on Windows), read into a zeroizing buffer, with best-effort no-core/no-swap
//! hardening. TPM / Secure Enclave wrapping backends remain future work.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "macos")]
use security_framework::base::Error as KeychainError;
#[cfg(target_os = "macos")]
use security_framework::os::macos::keychain::SecKeychain;
#[cfg(target_os = "macos")]
use security_framework::passwords::{get_generic_password, set_generic_password};

#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE, HLOCAL,
    INVALID_HANDLE_VALUE,
};
#[cfg(windows)]
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    AddAccessAllowedAceEx, CreateWellKnownSid, EqualSid, GetAce, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACL, ACL_REVISION,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::Debug::{SetErrorMode, SEM_NOGPFAULTERRORBOX};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
#[cfg(windows)]
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
#[cfg(windows)]
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Master key size for the standard-tier store.
pub const MASTER_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const PASSPHRASE_STORE_SCHEME: &str = "machine-key-passphrase-v1";
const SCRYPT_N: u32 = 1 << 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "bot.avibe.avault";
#[cfg(target_os = "macos")]
const KEYCHAIN_ACCOUNT: &str = "standard-master-key";
#[cfg(target_os = "macos")]
const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
#[cfg(target_os = "macos")]
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
#[cfg(target_os = "macos")]
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
#[cfg(target_os = "macos")]
const ERR_SEC_NO_DEFAULT_KEYCHAIN: i32 = -25307;
#[cfg(target_os = "macos")]
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

/// Selected master-key storage backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Auto,
    Tpm,
    Keychain,
    File,
    FilePassphrase,
}

/// The loaded master key. The buffer is zeroized on drop and mlock'd where available.
pub struct MasterKey {
    page: LockedKeyPage,
}

impl MasterKey {
    fn zeroed_locked() -> anyhow::Result<Self> {
        let page = LockedKeyPage::new_zeroed()?;
        harden_process_memory();
        lock_memory(page.as_ptr(), page.len());
        Ok(Self { page })
    }

    /// Copy a 32-byte secret into a dedicated locked, zeroizing page.
    ///
    /// The resident agent uses this for cached protected-tier DEKs. The type name remains
    /// `MasterKey` because it is the existing locked 32-byte secret primitive in this crate.
    pub fn from_bytes(bytes: &[u8; MASTER_KEY_BYTES]) -> anyhow::Result<Self> {
        let mut key = Self::zeroed_locked()?;
        key.as_mut_bytes().copy_from_slice(bytes);
        Ok(key)
    }

    fn generate_locked() -> anyhow::Result<Self> {
        let mut key = Self::zeroed_locked()?;
        OsRng.fill_bytes(key.as_mut_bytes());
        Ok(key)
    }

    /// Borrow the key for a single crypto operation.
    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_BYTES] {
        self.page.as_key()
    }

    fn as_mut_bytes(&mut self) -> &mut [u8; MASTER_KEY_BYTES] {
        self.page.as_mut_key()
    }
}

struct LockedKeyPage {
    ptr: NonNull<u8>,
    len: usize,
    layout: Layout,
}

impl LockedKeyPage {
    fn new_zeroed() -> anyhow::Result<Self> {
        let page = system_page_size();
        let layout =
            Layout::from_size_align(page, page).context("invalid master key page layout")?;
        // Safety invariant: `layout` is non-zero and page-aligned; the returned allocation is
        // owned only by this `LockedKeyPage` and is zero-filled before any key material is read.
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr).context("failed to allocate master key page")?;
        Ok(Self {
            ptr,
            len: page,
            layout,
        })
    }

    fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    fn len(&self) -> usize {
        self.len
    }

    fn as_key(&self) -> &[u8; MASTER_KEY_BYTES] {
        // Safety invariant: `ptr` points to a live allocation of at least one page, and the first
        // 32 bytes are reserved exclusively for the master key for this object's lifetime.
        unsafe { &*(self.ptr.as_ptr().cast::<[u8; MASTER_KEY_BYTES]>()) }
    }

    fn as_mut_key(&mut self) -> &mut [u8; MASTER_KEY_BYTES] {
        // Safety invariant: `&mut self` proves unique access to this dedicated page, whose first
        // 32 bytes are reserved exclusively for the master key.
        unsafe { &mut *(self.ptr.as_ptr().cast::<[u8; MASTER_KEY_BYTES]>()) }
    }
}

impl Drop for LockedKeyPage {
    fn drop(&mut self) {
        // Safety invariant: the page is still exclusively owned here; zeroizing the full page
        // clears the key bytes before `munlock` and before returning the allocation to the heap.
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len).zeroize();
        }
        unlock_memory(self.ptr.as_ptr(), self.len);
        // Safety invariant: this is the same layout returned by `new_zeroed`, and the page has
        // not been deallocated elsewhere.
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

/// Apply best-effort process-wide memory hardening before secret material is read.
///
/// This disables core dumps where supported. It is intentionally idempotent so CLI
/// startup and store key loading can both call it before their own secret windows.
#[cfg(target_os = "linux")]
pub fn harden_process_memory() {
    // Safety invariant: `prctl(PR_SET_DUMPABLE, 0)` changes the current process dumpability
    // and does not dereference user pointers. It prevents key pages from entering core dumps.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
}

/// Apply best-effort process-wide memory hardening before secret material is read.
#[cfg(target_os = "macos")]
pub fn harden_process_memory() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // Safety invariant: `setrlimit(RLIMIT_CORE, {0,0})` changes only the current process
    // resource limit and does not dereference Rust-owned secret buffers.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
}

/// Apply best-effort process-wide memory hardening before secret material is read.
#[cfg(windows)]
pub fn harden_process_memory() {
    // Safety invariant: `SetErrorMode` is process-wide WER/crash UI hardening and does not
    // dereference secret buffers. It reduces accidental crash-dump exposure on Windows.
    unsafe {
        SetErrorMode(SEM_NOGPFAULTERRORBOX);
    }
}

/// Apply best-effort process-wide memory hardening before secret material is read.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn harden_process_memory() {}

/// Authorize a connected Unix-domain socket peer by kernel credentials.
///
/// The resident agent calls this before processing any frame. It accepts only a
/// same-uid peer and deliberately does not use a shared token that could become
/// another secret in the Python daemon.
#[cfg(unix)]
pub fn authorize_same_uid_peer(stream: &impl AsFd) -> anyhow::Result<()> {
    let peer_uid = peer_uid(stream)?;
    let current_uid = current_euid();
    if peer_uid != current_uid {
        bail!("agent peer uid is not authorized");
    }
    Ok(())
}

/// Return this process's effective Unix uid.
#[cfg(unix)]
pub fn effective_uid() -> u32 {
    current_euid()
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &impl AsFd) -> anyhow::Result<u32> {
    let fd = stream.as_fd().as_raw_fd();
    let mut cred = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // Safety invariant: `fd` is a live Unix stream socket. `getsockopt(SO_PEERCRED)` writes only
    // kernel peer-credential metadata into the stack buffer so the agent can reject other users
    // before any secret-bearing frame is honored.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        bail!("failed to read peer credentials");
    }
    // Safety invariant: `getsockopt` succeeded and initialized `cred`.
    let cred = unsafe { cred.assume_init() };
    Ok(cred.uid)
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &impl AsFd) -> anyhow::Result<u32> {
    let fd = stream.as_fd().as_raw_fd();
    let mut cred = std::mem::MaybeUninit::<libc::xucred>::zeroed();
    let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    // Safety invariant: `fd` is a live Unix stream socket. `getsockopt(LOCAL_PEERCRED)` writes
    // only kernel peer-credential metadata into the stack buffer so same-uid authorization does
    // not depend on a shared secret in Python.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        bail!("failed to read peer credentials");
    }
    // Safety invariant: `getsockopt` succeeded and initialized `cred`.
    let cred = unsafe { cred.assume_init() };
    if cred.cr_version != libc::XUCRED_VERSION {
        bail!("peer credentials have unsupported version");
    }
    Ok(cred.cr_uid)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn peer_uid(_stream: &impl AsFd) -> anyhow::Result<u32> {
    bail!("agent peer credentials are unsupported on this Unix platform")
}

#[cfg(unix)]
fn current_euid() -> u32 {
    // Safety invariant: `geteuid` reads process identity metadata only. The agent uses this to
    // compare the kernel-reported peer uid against its own uid before processing frames.
    unsafe { libc::geteuid() }
}

/// Return the default P1 master-key path: `$AVAULT_HOME/machine.key` or
/// `$HOME/.avibe/state/vault/machine.key`.
pub fn default_master_key_path() -> anyhow::Result<PathBuf> {
    if let Some(home) = env::var_os("AVAULT_HOME") {
        return Ok(PathBuf::from(home).join("machine.key"));
    }
    Ok(user_home_dir()?
        .join(".avibe")
        .join("state")
        .join("vault")
        .join("machine.key"))
}

/// Return the opt-in passphrase-wrapped master-key path.
pub fn default_passphrase_master_key_path() -> anyhow::Result<PathBuf> {
    if let Some(home) = env::var_os("AVAULT_HOME") {
        return Ok(PathBuf::from(home).join("machine.passphrase.json"));
    }
    Ok(user_home_dir()?
        .join(".avibe")
        .join("state")
        .join("vault")
        .join("machine.passphrase.json"))
}

#[cfg(not(windows))]
fn user_home_dir() -> anyhow::Result<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

#[cfg(windows)]
fn user_home_dir() -> anyhow::Result<PathBuf> {
    if let Some(home) = env::var_os("HOME").or_else(|| env::var_os("USERPROFILE")) {
        return Ok(PathBuf::from(home));
    }
    match (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH")) {
        (Some(drive), Some(path)) => {
            let mut home = PathBuf::from(drive);
            home.push(path);
            Ok(home)
        }
        _ => bail!("Windows user profile directory is not set"),
    }
}

/// Load the 32-byte master key, or create it on first use.
pub fn load_or_create_master_key(backend: Backend) -> anyhow::Result<MasterKey> {
    match backend {
        Backend::Auto => load_or_create_auto_master_key(),
        Backend::File => FileStore::new(default_master_key_path()?).get_or_create(),
        Backend::Keychain => KeychainStore::new().get_or_create(),
        Backend::FilePassphrase => {
            bail!("passphrase backend requires an explicit passphrase unlock")
        }
        Backend::Tpm => bail!("requested master-key backend is not implemented"),
    }
}

/// Load the existing 32-byte master key. This never creates a replacement key.
pub fn load_master_key(backend: Backend) -> anyhow::Result<MasterKey> {
    match backend {
        Backend::Auto => load_auto_master_key(),
        Backend::File => FileStore::new(default_master_key_path()?).get(),
        Backend::Keychain => KeychainStore::new().get(),
        Backend::FilePassphrase => {
            bail!("passphrase backend requires an explicit passphrase unlock")
        }
        Backend::Tpm => bail!("requested master-key backend is not implemented"),
    }
}

/// Store a master key in the selected backend, refusing to overwrite unless `force` is true.
pub fn import_master_key(
    backend: Backend,
    key: &[u8; MASTER_KEY_BYTES],
    force: bool,
) -> anyhow::Result<()> {
    match backend {
        Backend::Auto => import_auto_master_key(key, force),
        Backend::File => FileStore::new(default_master_key_path()?)
            .import(key, force)
            .context("failed to store imported master key"),
        Backend::Keychain => KeychainStore::new()
            .import(key, force)
            .context("failed to store imported master key in Keychain"),
        Backend::FilePassphrase => {
            bail!("passphrase backend requires an explicit passphrase unlock")
        }
        Backend::Tpm => bail!("requested master-key backend is not implemented"),
    }
}

#[cfg(target_os = "macos")]
fn load_or_create_auto_master_key() -> anyhow::Result<MasterKey> {
    let file = FileStore::new(default_master_key_path()?);
    let keychain = KeychainStore::new();

    if let Some(file_key) = load_existing_file_master_key(&file)? {
        return migrate_file_key_to_keychain(&keychain, file_key);
    }

    match keychain.get() {
        Ok(key) => Ok(key),
        Err(err) if is_keychain_not_found(&err) => {
            create_keychain_key_or_fallback_file(&keychain, &file, MasterKey::generate_locked()?)
        }
        Err(err) if is_keychain_unavailable(&err) => file.get_or_create(),
        Err(err) => Err(err),
    }
}

#[cfg(not(target_os = "macos"))]
fn load_or_create_auto_master_key() -> anyhow::Result<MasterKey> {
    load_or_create_master_key(default_backend())
}

#[cfg(target_os = "macos")]
fn load_auto_master_key() -> anyhow::Result<MasterKey> {
    let file = FileStore::new(default_master_key_path()?);
    let keychain = KeychainStore::new();

    if let Some(file_key) = load_existing_file_master_key(&file)? {
        return migrate_file_key_to_keychain(&keychain, file_key);
    }

    match keychain.get() {
        Ok(key) => Ok(key),
        Err(err) if is_keychain_unavailable(&err) => file.get(),
        Err(err) => Err(err),
    }
}

#[cfg(not(target_os = "macos"))]
fn load_auto_master_key() -> anyhow::Result<MasterKey> {
    load_master_key(default_backend())
}

#[cfg(target_os = "macos")]
fn import_auto_master_key(key: &[u8; MASTER_KEY_BYTES], force: bool) -> anyhow::Result<()> {
    let file = FileStore::new(default_master_key_path()?);
    let keychain = KeychainStore::new();

    if file.path().exists() {
        file.import(key, force)
            .context("failed to store imported master key in file store")?;
        return match keychain.import(key, true) {
            Ok(()) => Ok(()),
            Err(err) if is_keychain_unavailable(&err) => Ok(()),
            Err(err) => Err(err).context("failed to mirror imported master key to Keychain"),
        };
    }

    match keychain.import(key, force) {
        Ok(()) => Ok(()),
        Err(err) if is_keychain_unavailable(&err) => FileStore::new(default_master_key_path()?)
            .import(key, force)
            .context("failed to store imported master key in file store"),
        Err(err) => Err(err),
    }
}

#[cfg(not(target_os = "macos"))]
fn import_auto_master_key(key: &[u8; MASTER_KEY_BYTES], force: bool) -> anyhow::Result<()> {
    import_master_key(default_backend(), key, force)
}

#[cfg(target_os = "macos")]
fn load_existing_file_master_key(file: &FileStore) -> anyhow::Result<Option<MasterKey>> {
    if file.path().exists() {
        return file.get().map(Some);
    }
    Ok(None)
}

#[cfg(target_os = "macos")]
fn migrate_file_key_to_keychain(
    keychain: &KeychainStore,
    file_key: MasterKey,
) -> anyhow::Result<MasterKey> {
    match keychain.get() {
        Ok(keychain_key) => {
            if keychain_key.as_bytes() == file_key.as_bytes() {
                Ok(keychain_key)
            } else {
                bail!(
                    "file master key differs from Keychain master key; refusing to choose automatically"
                )
            }
        }
        Err(err) if is_keychain_not_found(&err) => {
            match keychain.create_noclobber(file_key.as_bytes()) {
                Ok(()) => Ok(file_key),
                Err(err) if is_keychain_duplicate(&err) => {
                    let keychain_key = keychain.get()?;
                    if keychain_key.as_bytes() == file_key.as_bytes() {
                        Ok(keychain_key)
                    } else {
                        bail!(
                            "file master key differs from concurrently created Keychain master key"
                        )
                    }
                }
                Err(err) if is_keychain_unavailable(&err) => Ok(file_key),
                Err(err) => Err(err).context("failed to migrate file master key to Keychain"),
            }
        }
        Err(err) if is_keychain_unavailable(&err) => Ok(file_key),
        Err(err) => Err(err),
    }
}

#[cfg(target_os = "macos")]
fn create_keychain_key_or_fallback_file(
    keychain: &KeychainStore,
    file: &FileStore,
    key: MasterKey,
) -> anyhow::Result<MasterKey> {
    match keychain.create_noclobber(key.as_bytes()) {
        Ok(()) => Ok(key),
        Err(err) if is_keychain_duplicate(&err) => keychain.get(),
        Err(err) if is_keychain_unavailable(&err) => file.get_or_create(),
        Err(err) => Err(err).context("failed to create master key in Keychain"),
    }
}

/// Default standard-tier backend for this host.
pub fn default_backend() -> Backend {
    #[cfg(target_os = "macos")]
    {
        Backend::Keychain
    }
    #[cfg(not(target_os = "macos"))]
    {
        Backend::File
    }
}

/// Load or create the passphrase-wrapped master key with an explicit passphrase.
pub fn load_or_create_passphrase_master_key(passphrase: &[u8]) -> anyhow::Result<MasterKey> {
    PassphraseFileStore::new(default_passphrase_master_key_path()?).get_or_create(passphrase)
}

/// Unlock the existing passphrase-wrapped master key with an explicit passphrase.
pub fn load_passphrase_master_key(passphrase: &[u8]) -> anyhow::Result<MasterKey> {
    PassphraseFileStore::new(default_passphrase_master_key_path()?).get(passphrase)
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
        validate_parent_directory_mode(&self.path)?;
        validate_file_mode(&self.path)?;
        let mut file = File::open(&self.path).with_context(|| "master key not found")?;

        let mut key = MasterKey::zeroed_locked()?;
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

        let parent = writable_parent(&self.path);
        let tmp = write_synced_temp_secret_file(
            parent,
            ".machine.",
            ".tmp",
            key,
            CreatedFileOwner::SetCurrentUser,
        )?;

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

        let key = MasterKey::generate_locked()?;
        let parent = writable_parent(&self.path);
        let tmp = write_synced_temp_secret_file(
            parent,
            ".machine.",
            ".tmp",
            key.as_bytes(),
            CreatedFileOwner::SetCurrentUser,
        )?;
        drop(key);

        match tmp.persist_noclobber(&self.path) {
            Ok(_) => {
                validate_file_mode(&self.path)?;
                sync_parent_dir(&self.path)?;
                Ok(())
            }
            Err(err) if err.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(err) => Err(err.error).context("failed to install new master key"),
        }
    }

    fn ensure_parent(&self) -> anyhow::Result<()> {
        let parent = writable_parent(&self.path);
        ensure_secret_parent_directory(parent)?;
        validate_directory_mode(parent)?;
        Ok(())
    }
}

/// Standard-tier master-key store backed by macOS Keychain.
#[derive(Debug, Clone, Copy)]
pub struct KeychainStore;

impl KeychainStore {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KeychainStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
impl KeychainStore {
    /// Return the master key, creating it in the user's default Keychain if missing.
    ///
    /// This uses a regular generic-password item and does not attach a
    /// user-presence / biometry access-control policy. That keeps the standard
    /// tier headless after the OS session is unlocked.
    pub fn get_or_create(&self) -> anyhow::Result<MasterKey> {
        match self.get() {
            Ok(key) => Ok(key),
            Err(err) if is_keychain_not_found(&err) => {
                let key = MasterKey::generate_locked()?;
                match self.create_noclobber(key.as_bytes()) {
                    Ok(()) => Ok(key),
                    Err(err) if is_keychain_duplicate(&err) => self.get(),
                    Err(err) => Err(err).context("failed to store master key in Keychain"),
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Return the existing Keychain master key.
    pub fn get(&self) -> anyhow::Result<MasterKey> {
        harden_process_memory();
        let mut bytes = Zeroizing::new(
            get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
                .context("master key not found in Keychain")?,
        );
        let mut key_bytes: [u8; MASTER_KEY_BYTES] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("master key has invalid length"))?;
        bytes.zeroize();
        let key = MasterKey::from_bytes(&key_bytes);
        key_bytes.zeroize();
        key
    }

    /// Import a master key into Keychain, refusing to overwrite unless `force` is true.
    pub fn import(&self, key: &[u8; MASTER_KEY_BYTES], force: bool) -> anyhow::Result<()> {
        if force {
            return set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, key)
                .context("failed to store imported master key in Keychain");
        }

        match self.create_noclobber(key) {
            Ok(()) => Ok(()),
            Err(err) if is_keychain_duplicate(&err) => {
                Err(err).context("master key already exists")
            }
            Err(err) => Err(err).context("failed to store imported master key in Keychain"),
        }
    }

    fn create_noclobber(&self, key: &[u8; MASTER_KEY_BYTES]) -> anyhow::Result<()> {
        SecKeychain::default()?
            .add_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, key)
            .map_err(anyhow::Error::from)
    }
}

#[cfg(not(target_os = "macos"))]
impl KeychainStore {
    pub fn get_or_create(&self) -> anyhow::Result<MasterKey> {
        bail!("Keychain master-key backend is only available on macOS")
    }

    pub fn get(&self) -> anyhow::Result<MasterKey> {
        bail!("Keychain master-key backend is only available on macOS")
    }

    pub fn import(&self, _key: &[u8; MASTER_KEY_BYTES], _force: bool) -> anyhow::Result<()> {
        bail!("Keychain master-key backend is only available on macOS")
    }
}

#[cfg(target_os = "macos")]
fn is_keychain_not_found(err: &anyhow::Error) -> bool {
    keychain_error_code(err) == Some(ERR_SEC_ITEM_NOT_FOUND)
}

#[cfg(target_os = "macos")]
fn is_keychain_duplicate(err: &anyhow::Error) -> bool {
    keychain_error_code(err) == Some(ERR_SEC_DUPLICATE_ITEM)
}

#[cfg(target_os = "macos")]
fn is_keychain_unavailable(err: &anyhow::Error) -> bool {
    matches!(
        keychain_error_code(err),
        Some(ERR_SEC_NOT_AVAILABLE | ERR_SEC_NO_DEFAULT_KEYCHAIN | ERR_SEC_INTERACTION_NOT_ALLOWED)
    )
}

#[cfg(target_os = "macos")]
fn keychain_error_code(err: &anyhow::Error) -> Option<i32> {
    err.chain().find_map(|cause| {
        cause
            .downcast_ref::<KeychainError>()
            .map(|error| error.code())
    })
}

/// Passphrase-wrapped file store for the standard-tier master key.
///
/// Disk contains only a scrypt + AES-256-GCM wrapper. The plaintext master is
/// generated and unlocked only into [`MasterKey`]'s locked, zeroizing page.
#[derive(Debug, Clone)]
pub struct PassphraseFileStore {
    path: PathBuf,
}

impl PassphraseFileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return the master key, creating a wrapped store atomically if missing.
    pub fn get_or_create(&self, passphrase: &[u8]) -> anyhow::Result<MasterKey> {
        match self.get(passphrase) {
            Ok(key) => Ok(key),
            Err(_) => {
                self.create_atomic(passphrase)?;
                self.get(passphrase)
            }
        }
    }

    /// Unlock an existing passphrase-wrapped master key.
    pub fn get(&self, passphrase: &[u8]) -> anyhow::Result<MasterKey> {
        validate_passphrase(passphrase)?;
        validate_parent_directory_mode(&self.path)?;
        validate_file_mode(&self.path)?;
        let bytes = fs::read(&self.path).context("passphrase master key not found")?;
        let blob: PassphraseMasterBlob =
            serde_json::from_slice(&bytes).context("passphrase master key JSON is invalid")?;
        let mut key = unwrap_passphrase_master(&blob, passphrase)?;
        let locked = MasterKey::from_bytes(&key).context("failed to lock unlocked master key")?;
        key.zeroize();
        Ok(locked)
    }

    /// Import a master key into the wrapped store, refusing to overwrite unless `force` is true.
    pub fn import(
        &self,
        key: &[u8; MASTER_KEY_BYTES],
        passphrase: &[u8],
        force: bool,
    ) -> anyhow::Result<()> {
        validate_passphrase(passphrase)?;
        self.ensure_parent()?;
        if self.path.exists() && !force {
            bail!("passphrase master key already exists");
        }
        let blob = wrap_passphrase_master(key, passphrase)?;
        let bytes =
            Zeroizing::new(serde_json::to_vec(&blob).context("failed to encode passphrase store")?);
        let parent = writable_parent(&self.path);
        let tmp = write_synced_temp_secret_file(
            parent,
            ".machine-passphrase.",
            ".tmp",
            bytes.as_slice(),
            CreatedFileOwner::SetCurrentUser,
        )?;

        if force {
            tmp.persist(&self.path)
                .map_err(|err| err.error)
                .context("failed to install passphrase master key")?;
        } else {
            tmp.persist_noclobber(&self.path)
                .map_err(|err| err.error)
                .context("passphrase master key already exists")?;
        }
        validate_file_mode(&self.path)?;
        sync_parent_dir(&self.path)?;
        Ok(())
    }

    fn create_atomic(&self, passphrase: &[u8]) -> anyhow::Result<()> {
        validate_passphrase(passphrase)?;
        self.ensure_parent()?;

        let key = MasterKey::generate_locked()?;
        let blob = wrap_passphrase_master(key.as_bytes(), passphrase)?;
        let bytes =
            Zeroizing::new(serde_json::to_vec(&blob).context("failed to encode passphrase store")?);
        let parent = writable_parent(&self.path);
        let tmp = write_synced_temp_secret_file(
            parent,
            ".machine-passphrase.",
            ".tmp",
            bytes.as_slice(),
            CreatedFileOwner::SetCurrentUser,
        )?;
        drop(key);

        match tmp.persist_noclobber(&self.path) {
            Ok(_) => {
                validate_file_mode(&self.path)?;
                sync_parent_dir(&self.path)?;
                Ok(())
            }
            Err(err) if err.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(err) => Err(err.error).context("failed to install passphrase master key"),
        }
    }

    fn ensure_parent(&self) -> anyhow::Result<()> {
        let parent = writable_parent(&self.path);
        ensure_secret_parent_directory(parent)?;
        validate_directory_mode(parent)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassphraseMasterBlob {
    pub scheme: String,
    pub kdf: String,
    pub n: u32,
    pub r: u32,
    pub p: u32,
    pub salt: String,
    pub nonce: String,
    pub wrapped_master: String,
}

fn wrap_passphrase_master(
    master_key: &[u8; MASTER_KEY_BYTES],
    passphrase: &[u8],
) -> anyhow::Result<PassphraseMasterBlob> {
    validate_passphrase(passphrase)?;
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let kek = derive_kek_scrypt(passphrase, &salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)?;

    let mut nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let wrapped_master = encrypt_with_key(&kek, &nonce, master_key, &[])?;

    Ok(PassphraseMasterBlob {
        scheme: PASSPHRASE_STORE_SCHEME.to_string(),
        kdf: "scrypt".to_string(),
        n: SCRYPT_N,
        r: SCRYPT_R,
        p: SCRYPT_P,
        salt: b64(&salt),
        nonce: b64(&nonce),
        wrapped_master: b64(&wrapped_master),
    })
}

fn unwrap_passphrase_master(
    blob: &PassphraseMasterBlob,
    passphrase: &[u8],
) -> anyhow::Result<Zeroizing<[u8; MASTER_KEY_BYTES]>> {
    validate_passphrase(passphrase)?;
    if blob.scheme != PASSPHRASE_STORE_SCHEME || blob.kdf != "scrypt" {
        bail!("unrecognized passphrase master key");
    }
    validate_scrypt_params(blob.n, blob.r, blob.p)?;
    let salt = unb64(&blob.salt, "salt")?;
    let nonce = decode_nonce(&blob.nonce, "nonce")?;
    let wrapped_master = unb64(&blob.wrapped_master, "wrapped_master")?;
    let kek = derive_kek_scrypt(passphrase, &salt, blob.n, blob.r, blob.p)?;
    let key = Zeroizing::new(
        decrypt_with_key(&kek, &nonce, &wrapped_master, &[]).context("passphrase unlock failed")?,
    );
    if key.len() != MASTER_KEY_BYTES {
        bail!("unlocked master key has invalid length");
    }
    let mut out = Zeroizing::new([0u8; MASTER_KEY_BYTES]);
    out.as_mut().copy_from_slice(&key);
    Ok(out)
}

fn validate_passphrase(passphrase: &[u8]) -> anyhow::Result<()> {
    if passphrase.is_empty() {
        bail!("a non-empty passphrase is required");
    }
    Ok(())
}

fn derive_kek_scrypt(
    passphrase: &[u8],
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
) -> anyhow::Result<Zeroizing<[u8; MASTER_KEY_BYTES]>> {
    validate_scrypt_params(n, r, p)?;
    let log_n = n.checked_ilog2().context("invalid scrypt N")?;
    let params = scrypt::Params::new(log_n as u8, r, p, MASTER_KEY_BYTES)
        .context("invalid scrypt parameters")?;
    let mut out = Zeroizing::new([0u8; MASTER_KEY_BYTES]);
    scrypt::scrypt(passphrase, salt, &params, out.as_mut()).context("scrypt derivation failed")?;
    Ok(out)
}

fn validate_scrypt_params(n: u32, r: u32, p: u32) -> anyhow::Result<()> {
    if n < 2 || !n.is_power_of_two() || n > (1 << 17) {
        bail!("scrypt N out of bounds");
    }
    if !(1..=16).contains(&r) {
        bail!("scrypt r out of bounds");
    }
    if !(1..=16).contains(&p) {
        bail!("scrypt p out of bounds");
    }
    Ok(())
}

fn encrypt_with_key(
    key: &[u8; MASTER_KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    plaintext: &[u8],
    aad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("encryption failed"))
}

fn decrypt_with_key(
    key: &[u8; MASTER_KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("authentication failed"))
}

fn b64(raw: &[u8]) -> String {
    B64.encode(raw)
}

fn unb64(text: &str, field: &str) -> anyhow::Result<Vec<u8>> {
    B64.decode(text.as_bytes())
        .with_context(|| format!("{field} is not valid base64"))
}

fn decode_nonce(text: &str, field: &str) -> anyhow::Result<[u8; NONCE_BYTES]> {
    let raw = unb64(text, field)?;
    if raw.len() != NONCE_BYTES {
        bail!("{field} has invalid length");
    }
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&raw);
    Ok(nonce)
}

/// Atomically write a secret-bearing file using owner-only permissions / ACLs.
///
/// Unix callers get a 0600 file; Windows callers get a protected owner-only DACL.
/// This is for delivery targets such as `deliver inject`: the output file is
/// private, but an existing project directory is allowed to keep normal project
/// permissions. Windows preserves the file owner assigned by creation, so inject
/// does not require `WRITE_OWNER` on the containing directory.
pub fn atomic_write_secret_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = writable_parent(path);
    ensure_output_parent_directory(parent)?;
    let tmp =
        write_synced_temp_secret_file(parent, ".avault.", ".tmp", bytes, CreatedFileOwner::Keep)?;
    tmp.persist(path)
        .map_err(|err| err.error)
        .context("failed to install secret file")?;
    validate_file_mode(path)?;
    sync_parent_dir(path)?;
    Ok(())
}

fn write_synced_temp_secret_file(
    parent: &Path,
    prefix: &str,
    suffix: &str,
    bytes: &[u8],
    owner: CreatedFileOwner,
) -> anyhow::Result<tempfile::NamedTempFile> {
    let mut tmp = tempfile::Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .tempfile_in(parent)
        .context("failed to create temporary secret file")?;
    secure_created_file(tmp.path(), owner).context("failed to secure temporary secret file")?;
    tmp.as_file_mut()
        .write_all(bytes)
        .context("failed to write temporary secret file")?;
    tmp.as_file_mut()
        .sync_all()
        .context("failed to sync temporary secret file")?;
    Ok(tmp)
}

#[derive(Clone, Copy)]
enum CreatedFileOwner {
    SetCurrentUser,
    Keep,
}

fn writable_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn ensure_output_parent_directory(parent: &Path) -> anyhow::Result<()> {
    if parent.exists() {
        return Ok(());
    }
    fs::create_dir_all(parent).context("failed to create secret output directory")
}

fn ensure_secret_parent_directory(parent: &Path) -> anyhow::Result<()> {
    if parent.exists() {
        validate_directory_mode(parent)?;
        return Ok(());
    }

    let mut missing = Vec::new();
    let mut current = parent;
    while !current.exists() {
        missing.push(current.to_path_buf());
        current = match current.parent() {
            Some(next) if !next.as_os_str().is_empty() => next,
            _ => Path::new("."),
        };
    }

    for dir in missing.iter().rev() {
        match fs::create_dir(dir) {
            Ok(()) => secure_created_directory(dir).context("failed to secure secret directory")?,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                validate_directory_mode(dir)?
            }
            Err(err) => return Err(err).context("failed to create secret directory"),
        }
    }
    validate_directory_mode(parent)?;
    Ok(())
}

#[cfg(unix)]
fn secure_created_directory(path: &Path) -> anyhow::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .context("failed to secure secret directory")
}

#[cfg(unix)]
fn secure_created_file(path: &Path, _owner: CreatedFileOwner) -> anyhow::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .context("failed to secure secret file")
}

#[cfg(windows)]
fn secure_created_directory(path: &Path) -> anyhow::Result<()> {
    set_owner_only_acl(path, true)
}

#[cfg(windows)]
fn secure_created_file(path: &Path, owner: CreatedFileOwner) -> anyhow::Result<()> {
    match owner {
        CreatedFileOwner::SetCurrentUser => set_owner_only_acl(path, false),
        CreatedFileOwner::Keep => set_owner_only_dacl(path, false),
    }
}

fn sync_parent_dir(path: &Path) -> anyhow::Result<()> {
    sync_directory(writable_parent(path))
}

#[cfg(unix)]
fn sync_directory(parent: &Path) -> anyhow::Result<()> {
    File::open(parent)
        .context("failed to open master key directory")?
        .sync_all()
        .context("failed to sync master key directory")
}

#[cfg(windows)]
fn sync_directory(parent: &Path) -> anyhow::Result<()> {
    let wide = wide_path(parent);
    // Safety invariant: the path is NUL-terminated UTF-16 and points to a directory whose
    // metadata update installs a secret file. Opening/flushing it never exposes key bytes.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Ok(());
    }
    let _guard = HandleGuard(handle);
    // Safety invariant: `handle` is a live directory handle opened above. The secret file was
    // already fully written, fsync'd, and renamed; Windows directory flush failures are treated
    // as best-effort so a successful write is not reported as failed.
    unsafe {
        FlushFileBuffers(handle);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_file_mode(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::metadata(path).context("failed to stat master key")?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!("master key mode is too open");
    }
    Ok(())
}

#[cfg(windows)]
fn validate_file_mode(path: &Path) -> anyhow::Result<()> {
    validate_owner_only_acl(path, "master key")
}

#[cfg(unix)]
fn validate_directory_mode(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::metadata(path).context("failed to stat master key directory")?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!("master key directory mode is too open");
    }
    Ok(())
}

#[cfg(windows)]
fn validate_directory_mode(path: &Path) -> anyhow::Result<()> {
    validate_owner_only_acl(path, "master key directory")
}

fn validate_parent_directory_mode(path: &Path) -> anyhow::Result<()> {
    validate_directory_mode(writable_parent(path))
}

#[cfg(windows)]
struct HandleGuard(HANDLE);

#[cfg(windows)]
impl Drop for HandleGuard {
    fn drop(&mut self) {
        // Safety invariant: the handle was returned by a Windows open call in this module and is
        // no longer used after this guard drops. Closing it does not touch secret memory.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

#[cfg(windows)]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // Safety invariant: `GetNamedSecurityInfoW` allocated this security descriptor with
            // the Windows local allocator; freeing it releases ACL metadata only, not secrets.
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    OsStr::new(path).encode_wide().chain(Some(0)).collect()
}

#[cfg(windows)]
fn set_owner_only_acl(path: &Path, directory: bool) -> anyhow::Result<()> {
    set_owner_only_acl_impl(path, directory, true)
}

#[cfg(windows)]
fn set_owner_only_dacl(path: &Path, directory: bool) -> anyhow::Result<()> {
    set_owner_only_acl_impl(path, directory, false)
}

#[cfg(windows)]
fn set_owner_only_acl_impl(path: &Path, directory: bool, set_owner: bool) -> anyhow::Result<()> {
    let owner = current_user_sid().context("failed to read current user SID")?;
    let sid_len = unsafe_sid_len(owner.as_psid())?;
    let acl_len = std::mem::size_of::<ACL>() + std::mem::size_of::<ACCESS_ALLOWED_ACE>() + sid_len
        - std::mem::size_of::<u32>();
    let mut acl_buf = vec![0u8; acl_len];
    let acl = acl_buf.as_mut_ptr().cast::<ACL>();
    // Safety invariant: `acl_buf` is a writable buffer sized for one owner ACE. The ACL grants
    // only the current user access to the secret directory/file and blocks inherited ACEs when
    // installed with `PROTECTED_DACL_SECURITY_INFORMATION`.
    unsafe {
        if InitializeAcl(acl, acl_len as u32, ACL_REVISION) == 0 {
            bail!("failed to initialize secret file ACL");
        }
        let inheritance = if directory {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            0
        };
        if AddAccessAllowedAceEx(
            acl,
            ACL_REVISION,
            inheritance,
            FILE_ALL_ACCESS,
            owner.as_psid(),
        ) == 0
        {
            bail!("failed to build secret file ACL");
        }
    }

    let mut wide = wide_path(path);
    let security_information = if set_owner {
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
    };
    let owner_ptr = if set_owner {
        owner.as_psid()
    } else {
        std::ptr::null_mut()
    };
    // Safety invariant: `wide` is a NUL-terminated path to the just-created secret object, and
    // `acl` remains alive for the duration of the call. The protected DACL removes inherited
    // principals so only the current-user ACE above grants access. Inject-output files pass a
    // null owner pointer to avoid requiring `WRITE_OWNER`; key-store files set the owner because
    // avault created them inside its private store directory.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            security_information,
            owner_ptr,
            std::ptr::null_mut(),
            acl,
            std::ptr::null_mut(),
        )
    };
    if rc != 0 {
        bail!("failed to install owner-only ACL");
    }
    Ok(())
}

#[cfg(windows)]
fn validate_owner_only_acl(path: &Path, label: &str) -> anyhow::Result<()> {
    let owner = current_user_sid().context("failed to read current user SID")?;
    let system = well_known_sid(WinLocalSystemSid).context("failed to build SYSTEM SID")?;
    let administrators = well_known_sid(WinBuiltinAdministratorsSid)
        .context("failed to build Administrators SID")?;
    let allowed = [owner.as_psid(), system.as_psid(), administrators.as_psid()];

    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut object_owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut wide = wide_path(path);
    // Safety invariant: `wide` is a NUL-terminated object path. Windows returns a security
    // descriptor that this function only inspects to reject unsafe owners/ACLs before reading
    // secrets.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut object_owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        bail!("failed to read {label} ACL");
    }
    let _sd = LocalSecurityDescriptor(sd);
    if !equal_sid(object_owner, owner.as_psid()) {
        bail!("{label} owner is not the current user");
    }
    if dacl.is_null() {
        bail!("{label} ACL is missing");
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    // Safety invariant: `sd` is the live security descriptor returned above. This reads only
    // descriptor control flags so avault can reject inherited DACLs before trusting access.
    if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0 {
        bail!("failed to inspect {label} ACL protection");
    }
    if control & SE_DACL_PROTECTED == 0 {
        bail!("{label} ACL inheritance is enabled");
    }

    // Safety invariant: `dacl` is owned by the Windows security descriptor above and remains
    // valid while `_sd` is alive. The loop only reads ACE metadata to enforce owner-only access.
    let ace_count = unsafe { (*dacl).AceCount };
    for index in 0..ace_count {
        let mut ace_ptr = std::ptr::null_mut();
        // Safety invariant: `index < AceCount` and `ace_ptr` is an out-parameter. Windows fills
        // it with a pointer into `dacl`, which remains valid for this scope.
        if unsafe { GetAce(dacl, u32::from(index), &mut ace_ptr) } == 0 {
            bail!("failed to inspect {label} ACL");
        }
        let header = ace_ptr.cast::<windows_sys::Win32::Security::ACE_HEADER>();
        // Safety invariant: `ace_ptr` points to an ACE header returned by `GetAce`.
        let ace_type = unsafe { (*header).AceType };
        let ace_type = u32::from(ace_type);
        if ace_type != ACCESS_ALLOWED_ACE_TYPE {
            if is_unsupported_access_allowing_ace_type(ace_type) {
                bail!("{label} ACL contains unsupported access-allowing ACE");
            }
            continue;
        }
        let ace = ace_ptr.cast::<ACCESS_ALLOWED_ACE>();
        // Safety invariant: this is an access-allowed ACE; `SidStart` is the first u32 of the SID
        // embedded in the ACE, per the Windows ACL layout.
        let sid = unsafe { (&(*ace).SidStart as *const u32).cast::<core::ffi::c_void>() as PSID };
        if !allowed
            .iter()
            .any(|allowed_sid| equal_sid(sid, *allowed_sid))
        {
            bail!("{label} ACL grants access to another principal");
        }
    }

    Ok(())
}

#[cfg(windows)]
fn is_unsupported_access_allowing_ace_type(ace_type: u32) -> bool {
    matches!(
        ace_type,
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_COMPOUND_ACE_TYPE
            | ACCESS_ALLOWED_OBJECT_ACE_TYPE
    )
}

#[cfg(windows)]
struct Sid {
    bytes: Vec<u8>,
}

#[cfg(windows)]
impl Sid {
    fn as_psid(&self) -> PSID {
        self.bytes.as_ptr().cast::<core::ffi::c_void>() as PSID
    }
}

#[cfg(windows)]
fn current_user_sid() -> anyhow::Result<Sid> {
    let mut token: HANDLE = std::ptr::null_mut();
    // Safety invariant: this opens a query-only handle to the current process token so we can
    // derive the owner SID for the protected DACL. It does not access secret memory.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        bail!("failed to open process token");
    }
    let _token = HandleGuard(token);

    let mut needed = 0u32;
    // Safety invariant: this first call intentionally passes a null buffer to learn the size.
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 && unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        bail!("failed to size process token user");
    }
    let mut buf = vec![0u8; needed as usize];
    // Safety invariant: `buf` is writable for `needed` bytes and receives TOKEN_USER metadata,
    // which contains only the current user's SID, not key material.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        bail!("failed to read process token user");
    }
    let token_user = buf.as_ptr().cast::<TOKEN_USER>();
    // Safety invariant: `buf` was filled as TOKEN_USER above; the SID length is obtained from
    // Windows before copying it into owned Rust memory for later ACL calls.
    let user_sid = unsafe { (*token_user).User.Sid };
    copy_sid(user_sid)
}

#[cfg(windows)]
fn well_known_sid(kind: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE) -> anyhow::Result<Sid> {
    let mut needed = 0u32;
    // Safety invariant: this size-probe uses a null destination as documented by Windows and
    // does not access secret memory.
    unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut needed,
        );
    }
    if needed == 0 {
        bail!("failed to size well-known SID");
    }
    let mut bytes = vec![0u8; needed as usize];
    // Safety invariant: `bytes` is a writable SID buffer of the size requested by Windows.
    if unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            bytes.as_mut_ptr().cast(),
            &mut needed,
        )
    } == 0
    {
        bail!("failed to create well-known SID");
    }
    bytes.truncate(needed as usize);
    Ok(Sid { bytes })
}

#[cfg(windows)]
fn copy_sid(sid: PSID) -> anyhow::Result<Sid> {
    let len = unsafe_sid_len(sid)?;
    let mut bytes = vec![0u8; len];
    // Safety invariant: `sid` is a valid SID pointer returned by Windows and `bytes` is sized
    // from `GetLengthSid`; copying preserves only ACL identity metadata.
    unsafe {
        std::ptr::copy_nonoverlapping(sid.cast::<u8>(), bytes.as_mut_ptr(), len);
    }
    Ok(Sid { bytes })
}

#[cfg(windows)]
fn unsafe_sid_len(sid: PSID) -> anyhow::Result<usize> {
    if sid.is_null() {
        bail!("missing SID");
    }
    // Safety invariant: callers pass SIDs returned by Windows token/security APIs or owned SID
    // buffers previously created here. `GetLengthSid` reads SID metadata only.
    let len = unsafe { GetLengthSid(sid) };
    usize::try_from(len)
        .ok()
        .filter(|value| *value > 0)
        .context("invalid SID length")
}

#[cfg(windows)]
fn equal_sid(left: PSID, right: PSID) -> bool {
    if left.is_null() || right.is_null() {
        return false;
    }
    // Safety invariant: both pointers are valid SIDs for the current ACL validation scope.
    unsafe { EqualSid(left, right) != 0 }
}

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
    let (base, span) = page_span(ptr, len);
    // Safety invariant: the pointer/length describe the live master-key array owned by
    // `MasterKey`; the page-aligned range covers that array and `mlock` does not mutate
    // Rust-visible contents. macOS has no `MADV_DONTDUMP`, so this is best-effort only.
    unsafe {
        libc::mlock((base as *const u8).cast(), span);
    }
}

#[cfg(windows)]
fn lock_memory(ptr: *const u8, len: usize) {
    // Safety invariant: the pointer/length describe the live dedicated master-key page.
    // `VirtualLock` pins those pages for this process when the OS permits it and does not
    // mutate Rust-visible contents. Failure is best-effort like Unix `mlock`.
    unsafe {
        VirtualLock(ptr.cast(), len);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn lock_memory(_ptr: *const u8, _len: usize) {}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unlock_memory(ptr: *const u8, len: usize) {
    let (base, span) = page_span(ptr, len);
    // Safety invariant: the pointer/length still refer to the master-key array during
    // `Drop`; `munlock` releases the page-lock after the explicit zeroize in `Drop`.
    unsafe {
        libc::munlock((base as *const u8).cast(), span);
    }
}

#[cfg(windows)]
fn unlock_memory(ptr: *const u8, len: usize) {
    // Safety invariant: the pointer/length still refer to the dedicated key page during
    // `Drop`; `VirtualUnlock` releases the page lock after explicit zeroization.
    unsafe {
        VirtualUnlock(ptr.cast(), len);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn unlock_memory(_ptr: *const u8, _len: usize) {}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn page_span(ptr: *const u8, len: usize) -> (usize, usize) {
    let page = system_page_size();
    let start = (ptr as usize / page) * page;
    let end = (ptr as usize + len).div_ceil(page) * page;
    (start, end.saturating_sub(start))
}

fn system_page_size() -> usize {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // Safety invariant: `sysconf(_SC_PAGESIZE)` reads process configuration and does not
        // dereference user pointers. A bad return falls back to the common 4096-byte page.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(page)
            .ok()
            .filter(|p| *p > 0)
            .unwrap_or(4096)
    }
    #[cfg(windows)]
    {
        let mut info = std::mem::MaybeUninit::<SYSTEM_INFO>::zeroed();
        // Safety invariant: `GetSystemInfo` initializes the provided stack buffer and does not
        // touch Rust-owned secret memory. A bad value falls back to the common 4096-byte page.
        unsafe {
            GetSystemInfo(info.as_mut_ptr());
            let info = info.assume_init();
            usize::try_from(info.dwPageSize)
                .ok()
                .filter(|p| *p > 0)
                .unwrap_or(4096)
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        4096
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nested_store(tmp: &tempfile::TempDir) -> FileStore {
        FileStore::new(tmp.path().join("vault").join("machine.key"))
    }

    #[test]
    fn creates_and_reads_key_with_0600_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let store = nested_store(&tmp);
        let first = store.get_or_create().unwrap();
        assert_eq!(first.as_bytes().len(), MASTER_KEY_BYTES);
        #[cfg(unix)]
        {
            let mode = fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let second = store.get().unwrap();
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn get_errors_if_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = nested_store(&tmp);
        assert!(store.get().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_loose_mode_on_read() {
        let tmp = tempfile::tempdir().unwrap();
        let store = nested_store(&tmp);
        store.get_or_create().unwrap();
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.get().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_loose_parent_directory_on_read() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileStore::new(tmp.path().join("machine.key"));
        fs::write(store.path(), [1u8; MASTER_KEY_BYTES]).unwrap();
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o777)).unwrap();

        assert!(store.get().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn get_or_create_rejects_existing_loose_parent_without_chmod() {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let store = FileStore::new(tmp.path().join("machine.key"));

        assert!(store.get_or_create().is_err());
        let mode = fs::metadata(tmp.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o777);
        assert!(!store.path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_secret_file_allows_project_parent_without_chmod() {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let out = tmp.path().join("inject.env");

        atomic_write_secret_file(&out, b"SECRET='value'\n").unwrap();
        let mode = fs::metadata(tmp.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        let file_mode = fs::metadata(out).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
    }

    #[test]
    fn master_keys_use_dedicated_pages() {
        let first = MasterKey::generate_locked().unwrap();
        let second = MasterKey::generate_locked().unwrap();
        let page = system_page_size();
        let first_page = first.as_bytes().as_ptr() as usize / page;
        let second_page = second.as_bytes().as_ptr() as usize / page;

        assert_ne!(first_page, second_page);
    }

    #[test]
    fn import_refuses_overwrite_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let store = nested_store(&tmp);
        store.get_or_create().unwrap();
        let key = [9u8; MASTER_KEY_BYTES];
        assert!(store.import(&key, false).is_err());
        store.import(&key, true).unwrap();
        assert_eq!(store.get().unwrap().as_bytes(), &key);
    }

    #[test]
    fn passphrase_store_wraps_and_unlocks_master_key() {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            PassphraseFileStore::new(tmp.path().join("vault").join("machine.passphrase.json"));
        let first = store
            .get_or_create(b"correct horse battery staple")
            .unwrap();
        let second = store.get(b"correct horse battery staple").unwrap();

        assert_eq!(first.as_bytes(), second.as_bytes());
        #[cfg(unix)]
        {
            let mode = fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn passphrase_store_rejects_wrong_passphrase() {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            PassphraseFileStore::new(tmp.path().join("vault").join("machine.passphrase.json"));
        store
            .get_or_create(b"correct horse battery staple")
            .unwrap();

        assert!(store.get(b"wrong passphrase").is_err());
    }

    #[test]
    fn passphrase_store_never_writes_plaintext_master_to_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let store =
            PassphraseFileStore::new(tmp.path().join("vault").join("machine.passphrase.json"));
        let key = [0x41u8; MASTER_KEY_BYTES];
        store
            .import(&key, b"correct horse battery staple", false)
            .unwrap();

        let disk = fs::read(store.path()).unwrap();
        assert!(!disk.windows(key.len()).any(|window| window == key));
        let disk_text = String::from_utf8(disk.clone()).unwrap();
        assert!(!disk_text.contains(&b64(&key)));
        assert!(!disk_text.contains(
            &key.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        let blob: PassphraseMasterBlob = serde_json::from_slice(&disk).unwrap();
        assert_eq!(blob.scheme, PASSPHRASE_STORE_SCHEME);
        assert!(!blob.wrapped_master.is_empty());
    }

    #[test]
    fn auto_backend_selects_best_implemented_host_store() {
        #[cfg(target_os = "macos")]
        assert_eq!(default_backend(), Backend::Keychain);

        #[cfg(not(target_os = "macos"))]
        assert_eq!(default_backend(), Backend::File);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn auto_store_uses_file_backend_on_non_macos() {
        let tmp = tempfile::tempdir().unwrap();
        env::set_var("AVAULT_HOME", tmp.path());

        let key = load_or_create_master_key(Backend::Auto).unwrap();
        let path = default_master_key_path().unwrap();
        assert!(path.exists());
        assert_eq!(
            FileStore::new(path).get().unwrap().as_bytes(),
            key.as_bytes()
        );

        env::remove_var("AVAULT_HOME");
    }

    #[test]
    fn import_does_not_reuse_stale_temp_file() {
        let tmp = tempfile::tempdir().unwrap();
        let store = nested_store(&tmp);
        store.ensure_parent().unwrap();
        let stale_tmp = store.path().parent().unwrap().join("machine.tmp");
        fs::write(&stale_tmp, [3u8; MASTER_KEY_BYTES]).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&stale_tmp, fs::Permissions::from_mode(0o644)).unwrap();

        let key = [9u8; MASTER_KEY_BYTES];
        store.import(&key, false).unwrap();
        assert_eq!(store.get().unwrap().as_bytes(), &key);
        #[cfg(unix)]
        {
            let mode = fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(stale_tmp.exists());
    }

    #[test]
    fn create_does_not_reuse_stale_temp_file() {
        let tmp = tempfile::tempdir().unwrap();
        let store = nested_store(&tmp);
        store.ensure_parent().unwrap();
        let stale_tmp = store.path().parent().unwrap().join(".machine.stale.tmp");
        fs::write(&stale_tmp, [3u8; MASTER_KEY_BYTES]).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&stale_tmp, fs::Permissions::from_mode(0o644)).unwrap();

        let key = store.get_or_create().unwrap();
        assert_ne!(key.as_bytes(), &[3u8; MASTER_KEY_BYTES]);
        #[cfg(unix)]
        {
            let mode = fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(stale_tmp.exists());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn page_span_covers_unaligned_range() {
        let start = 0x12345usize;
        let len = MASTER_KEY_BYTES;
        let (base, span) = page_span(start as *const u8, len);

        assert!(base <= start);
        assert!(base + span >= start + len);
        assert!(span >= len);
    }
}
