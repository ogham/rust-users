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

use std::ffi::{CStr, CString};
use std::path::Path;
use std::ptr::read;
use std::sync::Arc;

use libc::{uid_t, gid_t};

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "dragonfly"))]
use libc::{c_char, time_t};

#[cfg(target_os = "linux")]
use libc::c_char;

use os::*;


#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "dragonfly"))]
#[repr(C)]
struct c_passwd {
    pw_name:    *const c_char,  // user name
    pw_passwd:  *const c_char,  // password field
    pw_uid:     uid_t,          // user ID
    pw_gid:     gid_t,          // group ID
    pw_change:  time_t,         // password change time
    pw_class:   *const c_char,
    pw_gecos:   *const c_char,
    pw_dir:     *const c_char,  // user's home directory
    pw_shell:   *const c_char,  // user's shell
    pw_expire:  time_t,         // password expiry time
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct c_passwd {
    pw_name:    *const c_char,  // user name
    pw_passwd:  *const c_char,  // password field
    pw_uid:     uid_t,          // user ID
    pw_gid:     gid_t,          // group ID
    pw_gecos:   *const c_char,
    pw_dir:     *const c_char,  // user's home directory
    pw_shell:   *const c_char,  // user's shell
}

#[repr(C)]
struct c_group {
    gr_name:   *const c_char,         // group name
    gr_passwd: *const c_char,         // password
    gr_gid:    gid_t,                 // group id
    gr_mem:    *const *const c_char,  // names of users in the group
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
}

/// Information about a particular user.
#[derive(Clone)]
pub struct User {

    /// This user's ID
    pub uid: uid_t,

    /// This user's name
    pub name: Arc<String>,

    /// The ID of this user's primary group
    pub primary_group: gid_t,

    /// This user's home directory
    home_dir: String,

    /// This user's shell
    shell: String,
}

/// Information about a particular group.
#[derive(Clone)]
pub struct Group {

    /// This group's ID
    pub gid: gid_t,

    /// This group's name
    pub name: Arc<String>,

    /// Vector of the names of the users who belong to this group as a non-primary member
    pub members: Vec<String>,
}

impl unix::UserExt for User {
    fn home_dir(&self) -> &Path {
        Path::new(&self.home_dir)
    }

    fn with_home_dir(mut self, home_dir: &str) -> User {
        self.home_dir = home_dir.to_owned();
        self
    }

    fn shell(&self) -> &Path {
        Path::new(&self.shell)
    }

    fn with_shell(mut self, shell: &str) -> User {
        self.shell = shell.to_owned();
        self
    }

    fn new(uid: uid_t, name: &str, primary_group: gid_t) -> User {
        User {
            uid: uid,
            name: Arc::new(name.to_owned()),
            primary_group: primary_group,
            home_dir: "/var/empty".to_owned(),
            shell: "/bin/false".to_owned(),
        }
    }
}

impl unix::GroupExt for Group {
    fn members(&self) -> &[String] {
        &*self.members
    }

    fn new(gid: gid_t, name: &str) -> Group {
        Group {
            gid: gid,
            name: Arc::new(name.to_owned()),
            members: Vec::new(),
        }
    }
}

/// Reads data from a `*char` field in `c_passwd` or `g_group` into a UTF-8
/// `String` for use in a user or group value.
///
/// Although `from_utf8_lossy` returns a clone-on-write string, we immediately
/// clone it anyway: the underlying buffer is managed by the C library, not by
/// us, so we *need* to move data out of it before the next user gets read.
unsafe fn from_raw_buf(p: *const c_char) -> String {
    CStr::from_ptr(p).to_string_lossy().into_owned()
}

/// Converts a raw pointer, which could be null, into a safe reference that
/// might be `None` instead.
///
/// This is basically the unstable `ptr_as_ref` feature:
/// https://github.com/rust-lang/rust/issues/27780
/// When that stabilises, this can be replaced.
unsafe fn ptr_as_ref<T>(pointer: *const T) -> Option<T> {
    if pointer.is_null() {
        None
    }
    else {
        Some(read(pointer))
    }
}

unsafe fn passwd_to_user(pointer: *const c_passwd) -> Option<User> {
    if let Some(passwd) = ptr_as_ref(pointer) {
        let name     = Arc::new(from_raw_buf(passwd.pw_name));
        let home_dir = from_raw_buf(passwd.pw_dir);
        let shell    = from_raw_buf(passwd.pw_shell);

        Some(User {
            uid:           passwd.pw_uid,
            name:          name,
            primary_group: passwd.pw_gid,
            home_dir:      home_dir,
            shell:         shell,
        })
    }
    else {
        None
    }
}

unsafe fn struct_to_group(pointer: *const c_group) -> Option<Group> {
    if let Some(group) = ptr_as_ref(pointer) {
        let name    = Arc::new(from_raw_buf(group.gr_name));
        let members = members(group.gr_mem);

        Some(Group {
            gid:     group.gr_gid,
            name:    name,
            members: members,
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
unsafe fn members(groups: *const *const c_char) -> Vec<String> {
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
    get_user_by_uid(uid).map(|u| Arc::try_unwrap(u.name).unwrap())
}

/// Returns the user ID for the effective user running the process.
pub fn get_effective_uid() -> uid_t {
    unsafe { geteuid() }
}

/// Returns the username of the effective user running the process.
pub fn get_effective_username() -> Option<String> {
    let uid = get_effective_uid();
    get_user_by_uid(uid).map(|u| Arc::try_unwrap(u.name).unwrap())
}

/// Returns the group ID for the user running the process.
pub fn get_current_gid() -> gid_t {
    unsafe { getgid() }
}

/// Returns the groupname of the user running the process.
pub fn get_current_groupname() -> Option<String> {
    let gid = get_current_gid();
    get_group_by_gid(gid).map(|g| Arc::try_unwrap(g.name).unwrap())
}

/// Returns the group ID for the effective user running the process.
pub fn get_effective_gid() -> gid_t {
    unsafe { getegid() }
}

/// Returns the groupname of the effective user running the process.
pub fn get_effective_groupname() -> Option<String> {
    let gid = get_effective_gid();
    get_group_by_gid(gid).map(|g| Arc::try_unwrap(g.name).unwrap())
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn uid() {
        get_current_uid();
    }

    #[test]
    fn username() {
        let uid = get_current_uid();
        assert_eq!(&*get_current_username().unwrap(), &*get_user_by_uid(uid).unwrap().name);
    }

    #[test]
    fn uid_for_username() {
        let uid = get_current_uid();
        let user = get_user_by_uid(uid).unwrap();
        assert_eq!(user.uid, uid);
    }

    #[test]
    fn username_for_uid_for_username() {
        let uid = get_current_uid();
        let user = get_user_by_uid(uid).unwrap();
        let user2 = get_user_by_uid(user.uid).unwrap();
        assert_eq!(user2.uid, uid);
    }

    #[test]
    fn user_info() {
        let uid = get_current_uid();
        let user = get_user_by_uid(uid).unwrap();
        // Not a real test but can be used to verify correct results
        // Use with --nocapture on test executable to show output
        println!("HOME={}, SHELL={}", user.home_dir, user.shell);
    }

    #[test]
    fn user_by_name() {
        // We cannot really test for arbitrary user as they might not exist on the machine
        // Instead the name of the current user is used
        let name = get_current_username().unwrap();
        let user_by_name = get_user_by_name(&name);
        assert!(user_by_name.is_some());
        assert_eq!(&**user_by_name.unwrap().name, &*name);

        // User names containing '\0' cannot be used (for now)
        let user = get_user_by_name("user\0");
        assert!(user.is_none());
    }

    #[test]
    fn group_by_name() {
        // We cannot really test for arbitrary groups as they might not exist on the machine
        // Instead the primary group of the current user is used
        let cur_uid = get_current_uid();
        let cur_user = get_user_by_uid(cur_uid).unwrap();
        let cur_group = get_group_by_gid(cur_user.primary_group).unwrap();
        let group_by_name = get_group_by_name(&cur_group.name);

        assert!(group_by_name.is_some());
        assert_eq!(group_by_name.unwrap().name, cur_group.name);

        // Group names containing '\0' cannot be used (for now)
        let group = get_group_by_name("users\0");
        assert!(group.is_none());
    }
}
