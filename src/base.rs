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

unsafe fn passwd_to_user(pointer: *const c_passwd) -> Option<User> {
    if !pointer.is_null() {
        let pw = read(pointer);
        Some(User {
            uid: pw.pw_uid as uid_t,
            name: Arc::new(from_raw_buf(pw.pw_name)),
            primary_group: pw.pw_gid as gid_t,
            home_dir: from_raw_buf(pw.pw_dir),
            shell: from_raw_buf(pw.pw_shell)
        })
    }
    else {
        None
    }
}

unsafe fn struct_to_group(pointer: *const c_group) -> Option<Group> {
    if !pointer.is_null() {
        let gr = read(pointer);
        let name = from_raw_buf(gr.gr_name);
        let members = members(gr.gr_mem);
        Some(Group { gid: gr.gr_gid, name: Arc::new(name), members: members })
    }
    else {
        None
    }
}

unsafe fn members(groups: *const *const c_char) -> Vec<String> {
    let mut i = 0;
    let mut members = vec![];

    // The list of members is a pointer to a pointer of characters, terminated
    // by a null pointer.
    loop {
        let username = groups.offset(i);

        // The first null check here should be unnecessary, but if libc sends
        // us bad data, it's probably better to continue on than crashing...
        if username.is_null() || (*username).is_null() {
            return members;
        }

        members.push(from_raw_buf(*username));
        i += 1;
    }
}


/// Searches for a `User` with the given ID in the system’s user database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_user_by_uid(uid: uid_t) -> Option<User> {
    unsafe { passwd_to_user(getpwuid(uid)) }
}

/// Searches for a `User` with the given username in the system’s user database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_user_by_name(username: &str) -> Option<User> {
    let username_c = CString::new(username);

    if !username_c.is_ok() {
        // This usually means the given username contained a '\0' already
        // It is debatable what to do here
        return None;
    }

    unsafe { passwd_to_user(getpwnam(username_c.unwrap().as_ptr())) }
}

/// Searches for a `Group` with the given ID in the system’s group database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_group_by_gid(gid: gid_t) -> Option<Group> {
    unsafe { struct_to_group(getgrgid(gid)) }
}

/// Searches for a `Group` with the given group name in the system‘s group database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_group_by_name(group_name: &str) -> Option<Group> {
    let group_name_c = CString::new(group_name);

    if !group_name_c.is_ok() {
        // This usually means the given username contained a '\0' already
        // It is debatable what to do here
        return None;
    }

    unsafe { struct_to_group(getgrnam(group_name_c.unwrap().as_ptr())) }
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
