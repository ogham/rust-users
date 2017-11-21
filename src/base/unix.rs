//! Integration with the C library’s users and groups.
//!
//! This module uses `extern` functions and types from `libc` that integrate
//! with the system’s C library, which integrates with the OS itself to get user
//! and group information. It’s where the “core” user handling is done.
//!
//!
//! ## Name encoding rules
//!
//! Under Unix, usernames and group names are considered to be
//! null-terminated, UTF-8 strings. These are `CString`s in Rust, although in
//! this library, they are just `String` values. Why?
//!
//! The reason is that any user or group values with invalid `CString` data
//! can instead just be assumed to not exist:
//!
//! - If you try to search for a user with a null character in their name,
//!   such a user could not exist anyway—so it’s OK to return `None`.
//! - If the OS returns user information with a null character in a field,
//!   then that field will just be truncated instead, which is valid behaviour
//!   for a `CString`.
//!
//! The downside is that we use `from_utf8_lossy` instead, which has a small
//! runtime penalty when it calculates and scans the length of the string for
//! invalid characters. However, this should not be a problem when dealing with
//! usernames of a few bytes each.
//!
//! In short, if you want to check for null characters in user fields, your
//! best bet is to check for them yourself before passing strings into any
//! functions.

#![allow(missing_copy_implementations)]  // for the C structs

#[cfg(not(target_os = "redox"))]
use std::ffi::{CStr, CString};
use std::ptr::read;
use std::sync::Arc;

use super::{User, Group};

use libc::{uid_t, gid_t};

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))]
use libc::{c_char, time_t};

#[cfg(any(target_os = "linux"))]
use libc::c_char;

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))]
#[repr(C)]
pub struct c_passwd {
    pub(crate) pw_name:    *const c_char,  // user name
    pub(crate) pw_passwd:  *const c_char,  // password field
    pub(crate) pw_uid:     uid_t,          // user ID
    pub(crate) pw_gid:     gid_t,          // group ID
    pub(crate) pw_change:  time_t,         // password change time
    pub(crate) pw_class:   *const c_char,
    pub(crate) pw_gecos:   *const c_char,
    pub(crate) pw_dir:     *const c_char,  // user's home directory
    pub(crate) pw_shell:   *const c_char,  // user's shell
    pub(crate) pw_expire:  time_t,         // password expiry time
}

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct c_passwd {
    pub(crate) pw_name:    *const c_char,  // user name
    pub(crate) pw_passwd:  *const c_char,  // password field
    pub(crate) pw_uid:     uid_t,          // user ID
    pub(crate) pw_gid:     gid_t,          // group ID
    pub(crate) pw_gecos:   *const c_char,
    pub(crate) pw_dir:     *const c_char,  // user's home directory
    pub(crate) pw_shell:   *const c_char,  // user's shell
}

#[repr(C)]
pub struct c_group {
    pub(crate) gr_name:   *const c_char,         // group name
    pub(crate) gr_passwd: *const c_char,         // password
    pub(crate) gr_gid:    gid_t,                 // group id
    pub(crate) gr_mem:    *const *const c_char,  // names of users in the group
}

extern {
    fn getpwuid(uid: uid_t) -> *const c_passwd;
    fn getpwnam(user_name: *const c_char) -> *const c_passwd;

    fn getgrgid(gid: gid_t) -> *const c_group;
    fn getgrnam(group_name: *const c_char) -> *const c_group;

    fn getuid() -> uid_t;
    fn geteuid() -> uid_t;

    fn getgid() -> gid_t;
    fn getegid() -> gid_t;

    fn setpwent();
    fn getpwent() -> *const c_passwd;
    fn endpwent();
}

/// Reads data from a `*char` field in `c_passwd` or `g_group` into a UTF-8
/// `String` for use in a user or group value.
///
/// Although `from_utf8_lossy` returns a clone-on-write string, we immediately
/// clone it anyway: the underlying buffer is managed by the C library, not by
/// us, so we *need* to move data out of it before the next user gets read.
pub(crate) unsafe fn from_raw_buf(p: *const c_char) -> String {
    CStr::from_ptr(p).to_string_lossy().into_owned()
}

/// Converts a raw pointer, which could be null, into a safe reference that
/// might be `None` instead.
///
/// This is basically the unstable `ptr_as_ref` feature:
/// https://github.com/rust-lang/rust/issues/27780
/// When that stabilises, this can be replaced.
pub(crate) unsafe fn ptr_as_ref<T>(pointer: *const T) -> Option<T> {
    if pointer.is_null() {
        None
    }
    else {
        Some(read(pointer))
    }
}

unsafe fn passwd_to_user(pointer: *const c_passwd) -> Option<User> {
    if let Some(passwd) = ptr_as_ref(pointer) {
        let name = Arc::new(from_raw_buf(passwd.pw_name));

        Some(User {
            uid:           passwd.pw_uid,
            name_arc:      name,
            primary_group: passwd.pw_gid,
            extras:        super::os::UserExtras::from_passwd(passwd),
        })
    }
    else {
        None
    }
}

unsafe fn struct_to_group(pointer: *const c_group) -> Option<Group> {
    if let Some(group) = ptr_as_ref(pointer) {
        let name = Arc::new(from_raw_buf(group.gr_name));

        Some(Group {
            gid:       group.gr_gid,
            name_arc:  name,
            extras:    super::os::GroupExtras::from_struct(group),
        })
    }
    else {
        None
    }
}

/// Expand a list of group members to a vector of strings.
///
/// The list of members is, in true C fashion, a pointer to a pointer of
/// characters, terminated by a null pointer. We check `members[0]`, then
/// `members[1]`, and so on, until that null pointer is reached. It doesn't
/// specify whether we should expect a null pointer or a pointer to a null
/// pointer, so we check for both here!
pub(crate) unsafe fn members(groups: *const *const c_char) -> Vec<String> {
    let mut members = Vec::new();

    for i in 0.. {
        let username = groups.offset(i);

        if username.is_null() || (*username).is_null() {
            break;
        }
        else {
            members.push(from_raw_buf(*username));
        }
    }

    members
}

/// Searches for a `User` with the given ID in the system’s user database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_user_by_uid(uid: uid_t) -> Option<User> {
    unsafe {
        let passwd = getpwuid(uid);
        passwd_to_user(passwd)
    }
}

/// Searches for a `User` with the given username in the system’s user database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_user_by_name(username: &str) -> Option<User> {
    if let Ok(username) = CString::new(username) {
        unsafe {
            let passwd = getpwnam(username.as_ptr());
            passwd_to_user(passwd)
        }
    }
    else {
        // The username that was passed in contained a null character.
        // This will *never* find anything, so just return `None`.
        // (I can’t figure out a pleasant way to signal an error here)
        None
    }
}

/// Searches for a `Group` with the given ID in the system’s group database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_group_by_gid(gid: gid_t) -> Option<Group> {
    unsafe {
        let group = getgrgid(gid);
        struct_to_group(group)
    }
}

/// Searches for a `Group` with the given group name in the system’s group database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_group_by_name(group_name: &str) -> Option<Group> {
    if let Ok(group_name) = CString::new(group_name) {
        unsafe {
            let group = getgrnam(group_name.as_ptr());
            struct_to_group(group)
        }
    }
    else {
        // The group name that was passed in contained a null character.
        // This will *never* find anything, so just return `None`.
        // (I can’t figure out a pleasant way to signal an error here)
        None
    }
}

/// Returns the user ID for the user running the process.
pub fn get_current_uid() -> uid_t {
    unsafe { getuid() }
}

/// Returns the username of the user running the process.
pub fn get_current_username() -> Option<String> {
    let uid = get_current_uid();
    get_user_by_uid(uid).map(|u| Arc::try_unwrap(u.name_arc).unwrap())
}

/// Returns the user ID for the effective user running the process.
pub fn get_effective_uid() -> uid_t {
    unsafe { geteuid() }
}

/// Returns the username of the effective user running the process.
pub fn get_effective_username() -> Option<String> {
    let uid = get_effective_uid();
    get_user_by_uid(uid).map(|u| Arc::try_unwrap(u.name_arc).unwrap())
}

/// Returns the group ID for the user running the process.
pub fn get_current_gid() -> gid_t {
    unsafe { getgid() }
}

/// Returns the groupname of the user running the process.
pub fn get_current_groupname() -> Option<String> {
    let gid = get_current_gid();
    get_group_by_gid(gid).map(|g| Arc::try_unwrap(g.name_arc).unwrap())
}

/// Returns the group ID for the effective user running the process.
pub fn get_effective_gid() -> gid_t {
    unsafe { getegid() }
}

/// Returns the groupname of the effective user running the process.
pub fn get_effective_groupname() -> Option<String> {
    let gid = get_effective_gid();
    get_group_by_gid(gid).map(|g| Arc::try_unwrap(g.name_arc).unwrap())
}

/// An iterator over every user present on the system.
///
/// This struct actually requires no fields, but has one hidden one to make it
/// `unsafe` to create.
pub struct AllUsers(());

impl AllUsers {

    /// Creates a new iterator over every user present on the system.
    ///
    /// ## Unsafety
    ///
    /// This constructor is marked as `unsafe`, which is odd for a crate
    /// that's meant to be a safe interface. It *has* to be unsafe because
    /// we cannot guarantee that the underlying C functions,
    /// `getpwent`/`setpwent`/`endpwent` that iterate over the system's
    /// `passwd` entries, are called in a thread-safe manner.
    ///
    /// These functions [modify a global
    /// state](http://man7.org/linux/man-pages/man3/getpwent.3.html#
    /// ATTRIBUTES), and if any are used at the same time, the state could
    /// be reset, resulting in a data race. We cannot even place it behind
    /// an internal `Mutex`, as there is nothing stopping another `extern`
    /// function definition from calling it!
    ///
    /// So to iterate all users, construct the iterator inside an `unsafe`
    /// block, then make sure to not make a new instance of it until
    /// iteration is over.
    pub unsafe fn new() -> AllUsers {
        setpwent();
        AllUsers(())
    }
}

impl Drop for AllUsers {
    fn drop(&mut self) {
        unsafe { endpwent() };
    }
}

impl Iterator for AllUsers {
    type Item = User;

    fn next(&mut self) -> Option<User> {
        unsafe { passwd_to_user(getpwent()) }
    }
}
