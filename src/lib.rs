#![crate_name = "users"]
#![crate_type = "rlib"]
#![crate_type = "dylib"]

//! This is a library for getting information on Unix users and groups. It
//! supports getting the system users, and creating your own mock tables.
//!
//! In Unix, each user has an individual *user ID*, and each process has an
//! *effective user ID* that says which user’s permissions it is using.
//! Furthermore, users can be the members of *groups*, which also have names and
//! IDs. This functionality is exposed in libc, the C standard library, but as
//! an unsafe Rust interface. This wrapper library provides a safe interface,
//! using User and Group objects instead of low-level pointers and strings. It
//! also offers basic caching functionality.
//!
//! It does not (yet) offer *editing* functionality; the objects returned are
//! read-only.
//!
//!
//! ## Users
//!
//! The function `get_current_uid` returns a `uid_t` value representing the user
//! currently running the program, and the `get_user_by_uid` function scans the
//! users database and returns a User object with the user’s information. This
//! function returns `None` when there is no user for that ID.
//!
//! A `User` object has the following public fields:
//!
//! - **uid:** The user’s ID
//! - **name:** The user’s name
//! - **primary_group:** The ID of this user’s primary group
//!
//! Here is a complete example that prints out the current user’s name:
//!
//! ```rust
//! use users::{get_user_by_uid, get_current_uid};
//! let user = get_user_by_uid(get_current_uid()).unwrap();
//! println!("Hello, {}!", user.name);
//! ```
//!
//! This code assumes (with `unwrap()`) that the user hasn’t been deleted after
//! the program has started running. For arbitrary user IDs, this is **not** a
//! safe assumption: it’s possible to delete a user while it’s running a
//! program, or is the owner of files, or for that user to have never existed.
//! So always check the return values from `user_to_uid`!
//!
//! There is also a `get_current_username` function, as it’s such a common
//! operation that it deserves special treatment.
//!
//!
//! ## Caching
//!
//! Despite the above warning, the users and groups database rarely changes.
//! While a short program may only need to get user information once, a
//! long-running one may need to re-query the database many times, and a
//! medium-length one may get away with caching the values to save on redundant
//! system calls.
//!
//! For this reason, this crate offers a caching interface to the database,
//! which offers the same functionality while holding on to every result,
//! caching the information so it can be re-used.
//!
//! To introduce a cache, create a new `OSUsers` object and call the same
//! methods on it. For example:
//!
//! ```rust
//! use users::{Users, OSUsers};
//! let mut cache = OSUsers::empty_cache();
//! let uid = cache.get_current_uid();
//! let user = cache.get_user_by_uid(uid).unwrap();
//! println!("Hello again, {}!", user.name);
//! ```
//!
//! This cache is **only additive**: it’s not possible to drop it, or erase
//! selected entries, as when the database may have been modified, it’s best to
//! start entirely afresh. So to accomplish this, just start using a new
//! `OSUsers` object.
//!
//!
//! ## Groups
//!
//! Finally, it’s possible to get groups in a similar manner.
//! A `Group` object has the following public fields:
//!
//! - **gid:** The group’s ID
//! - **name:** The group’s name
//! - **members:** Vector of names of the users that belong to this group
//!
//! And again, a complete example:
//!
//! ```rust
//! use users::{Users, OSUsers};
//! let mut cache = OSUsers::empty_cache();
//! let group = cache.get_group_by_name("admin").expect("No such group 'admin'!");
//! println!("The '{}' group has the ID {}", group.name, group.gid);
//! for member in group.members.into_iter() {
//!     println!("{} is a member of the group", member);
//! }
//! ```
//!
//!
//! ## Caveats
//!
//! You should be prepared for the users and groups tables to be completely
//! broken: IDs shouldn’t be assumed to map to actual users and groups, and
//! usernames and group names aren’t guaranteed to map either!
//!
//! Use the mocking module to create custom tables to test your code for these
//! edge cases.


use std::borrow::ToOwned;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{Error as IOError, Result as IOResult};
use std::ptr::read;
use std::str::from_utf8_unchecked;

extern crate libc;
pub use libc::{uid_t, gid_t, c_int};

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "dragonfly"))]
use libc::{c_char, time_t};

#[cfg(target_os = "linux")]
use libc::c_char;

pub mod mock;


/// The trait for the `OSUsers` object.
pub trait Users {

    /// Return a User object if one exists for the given user ID; otherwise, return None.
    fn get_user_by_uid(&mut self, uid: uid_t) -> Option<User>;

    /// Return a User object if one exists for the given username; otherwise, return None.
    fn get_user_by_name(&mut self, username: &str) -> Option<User>;

    /// Return a Group object if one exists for the given group ID; otherwise, return None.
    fn get_group_by_gid(&mut self, gid: gid_t) -> Option<Group>;

    /// Return a Group object if one exists for the given groupname; otherwise, return None.
    fn get_group_by_name(&mut self, group_name: &str) -> Option<Group>;

    /// Return the user ID for the user running the process.
    fn get_current_uid(&mut self) -> uid_t;

    /// Return the username of the user running the process.
    fn get_current_username(&mut self) -> Option<String>;

    /// Return the group ID for the user running the process.
    fn get_current_gid(&mut self) -> gid_t;

    /// Return the group name of the user running the process.
    fn get_current_groupname(&mut self) -> Option<String>;

    /// Return the effective user id.
    fn get_effective_uid(&mut self) -> uid_t;

    /// Return the effective group id.
    fn get_effective_gid(&mut self) -> gid_t;

    /// Return the effective username.
    fn get_effective_username(&mut self) -> Option<String>;

    /// Return the effective group name.
    fn get_effective_groupname(&mut self) -> Option<String>;
}

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "dragonfly"))]
#[repr(C)]
struct c_passwd {
    pub pw_name:    *const c_char,  // user name
    pub pw_passwd:  *const c_char,  // password field
    pub pw_uid:     uid_t,          // user ID
    pub pw_gid:     gid_t,          // group ID
    pub pw_change:  time_t,         // password change time
    pub pw_class:   *const c_char,
    pub pw_gecos:   *const c_char,
    pub pw_dir:     *const c_char,  // user's home directory
    pub pw_shell:   *const c_char,  // user's shell
    pub pw_expire:  time_t,         // password expiry time
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct c_passwd {
    pub pw_name:    *const c_char,  // user name
    pub pw_passwd:  *const c_char,  // password field
    pub pw_uid:     uid_t,          // user ID
    pub pw_gid:     gid_t,          // group ID
    pub pw_gecos:   *const c_char,
    pub pw_dir:     *const c_char,  // user's home directory
    pub pw_shell:   *const c_char,  // user's shell
}

#[repr(C)]
struct c_group {
    pub gr_name:   *const c_char,         // group name
    pub gr_passwd: *const c_char,         // password
    pub gr_gid:    gid_t,                 // group id
    pub gr_mem:    *const *const c_char,  // names of users in the group
}

extern {
    fn getpwuid(uid: uid_t) -> *const c_passwd;
    fn getpwnam(user_name: *const c_char) -> *const c_passwd;

    fn getgrgid(gid: gid_t) -> *const c_group;
    fn getgrnam(group_name: *const c_char) -> *const c_group;

    fn getuid() -> uid_t;
    fn geteuid() -> uid_t;

    fn setuid(uid: uid_t) -> c_int;
    fn seteuid(uid: uid_t) -> c_int;

    fn getgid() -> gid_t;
    fn getegid() -> gid_t;

    fn setgid(gid: gid_t) -> c_int;
    fn setegid(gid: gid_t) -> c_int;

    fn setreuid(ruid: uid_t, euid: uid_t) -> c_int;
    fn setregid(rgid: gid_t, egid: gid_t) -> c_int;
}

#[derive(Clone)]
/// Information about a particular user.
pub struct User {

    /// This user's ID
    pub uid: uid_t,

    /// This user's name
    pub name: String,

    /// The ID of this user's primary group
    pub primary_group: gid_t,

    /// This user's home directory
    pub home_dir: String,

    /// This user's shell
    pub shell: String,
}

/// Information about a particular group.
#[derive(Clone)]
pub struct Group {

    /// This group's ID
    pub gid: uid_t,

    /// This group's name
    pub name: String,

    /// Vector of the names of the users who belong to this group as a non-primary member
    pub members: Vec<String>,
}

/// A producer of user and group instances that caches every result.
#[derive(Clone)]
pub struct OSUsers {
    users: HashMap<uid_t, Option<User>>,
    users_back: HashMap<String, Option<uid_t>>,

    groups: HashMap<gid_t, Option<Group>>,
    groups_back: HashMap<String, Option<gid_t>>,

    uid: Option<uid_t>,
    gid: Option<gid_t>,
    euid: Option<uid_t>,
    egid: Option<gid_t>,
}

unsafe fn from_raw_buf(p: *const i8) -> String {
    from_utf8_unchecked(CStr::from_ptr(p).to_bytes()).to_string()
}

unsafe fn passwd_to_user(pointer: *const c_passwd) -> Option<User> {
    if !pointer.is_null() {
        let pw = read(pointer);
        Some(User {
            uid: pw.pw_uid as uid_t,
            name: from_raw_buf(pw.pw_name as *const i8),
            primary_group: pw.pw_gid as gid_t,
            home_dir: from_raw_buf(pw.pw_dir as *const i8),
            shell: from_raw_buf(pw.pw_shell as *const i8)
        })
    }
    else {
        None
    }
}

unsafe fn struct_to_group(pointer: *const c_group) -> Option<Group> {
    if !pointer.is_null() {
        let gr = read(pointer);
        let name = from_raw_buf(gr.gr_name as *const i8);
        let members = members(gr.gr_mem);
        Some(Group { gid: gr.gr_gid, name: name, members: members })
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

impl Users for OSUsers {
    fn get_user_by_uid(&mut self, uid: uid_t) -> Option<User> {
        match self.users.entry(uid) {
            Vacant(entry) => {
                let user = unsafe { passwd_to_user(getpwuid(uid)) };
                match user {
                    Some(user) => {
                        entry.insert(Some(user.clone()));
                        self.users_back.insert(user.name.clone(), Some(user.uid));
                        Some(user)
                    },
                    None => {
                        entry.insert(None);
                        None
                    }
                }
            },
            Occupied(entry) => entry.get().clone(),
        }
    }

    fn get_user_by_name(&mut self, username: &str) -> Option<User> {
        // to_owned() could change here:
        // https://github.com/rust-lang/rfcs/blob/master/text/0509-collections-reform-part-2.md#alternatives-to-toowned-on-entries
        match self.users_back.entry(username.to_owned()) {
            Vacant(entry) => {
                let username_c = CString::new(username);

                if !username_c.is_ok() {
                    // This usually means the given username contained a '\0' already
                    // It is debatable what to do here
                    return None;
                }

                let user = unsafe { passwd_to_user(getpwnam(username_c.unwrap().as_ptr())) };
                match user {
                    Some(user) => {
                        entry.insert(Some(user.uid));
                        self.users.insert(user.uid, Some(user.clone()));
                        Some(user)
                    },
                    None => {
                        entry.insert(None);
                        None
                    }
                }
            },
            Occupied(entry) => match entry.get() {
                &Some(uid) => self.users[&uid].clone(),
                &None => None,
            }
        }
    }

    fn get_group_by_gid(&mut self, gid: gid_t) -> Option<Group> {
        match self.groups.entry(gid) {
            Vacant(entry) => {
                let group = unsafe { struct_to_group(getgrgid(gid)) };
                match group {
                    Some(group) => {
                        entry.insert(Some(group.clone()));
                        self.groups_back.insert(group.name.clone(), Some(group.gid));
                        Some(group)
                    },
                    None => {
                        entry.insert(None);
                        None
                    }
                }
            },
            Occupied(entry) => entry.get().clone(),
        }
    }

    fn get_group_by_name(&mut self, group_name: &str) -> Option<Group> {
        // to_owned() could change here:
        // https://github.com/rust-lang/rfcs/blob/master/text/0509-collections-reform-part-2.md#alternatives-to-toowned-on-entries
        match self.groups_back.entry(group_name.to_owned()) {
            Vacant(entry) => {
                let group_name_c = CString::new(group_name);

                if !group_name_c.is_ok() {
                    // This usually means the given username contained a '\0' already
                    // It is debatable what to do here
                    return None;
                }

                let user = unsafe { struct_to_group(getgrnam(group_name_c.unwrap().as_ptr())) };
                match user {
                    Some(group) => {
                        entry.insert(Some(group.gid));
                        self.groups.insert(group.gid, Some(group.clone()));
                        Some(group)
                    },
                    None => {
                        entry.insert(None);
                        None
                    }
                }
            },
            Occupied(entry) => match entry.get() {
                &Some(gid) => self.groups[&gid].clone(),
                &None => None,
            }
        }
    }

    fn get_current_uid(&mut self) -> uid_t {
        match self.uid {
            Some(uid) => uid,
            None => {
                let uid = unsafe { getuid() };
                self.uid = Some(uid);
                uid
            }
        }
    }

    /// Return the username of the user running the process.
    fn get_current_username(&mut self) -> Option<String> {
        let uid = self.get_current_uid();
        self.get_user_by_uid(uid).map(|u| u.name)
    }

    fn get_current_gid(&mut self) -> gid_t {
        match self.gid {
            Some(gid) => gid,
            None => {
                let gid = unsafe { getgid() };
                self.gid = Some(gid);
                gid
            }
        }
    }

    fn get_current_groupname(&mut self) -> Option<String> {
        let gid = self.get_current_gid();
        self.get_group_by_gid(gid).map(|g| g.name)
    }

    fn get_effective_gid(&mut self) -> gid_t {
        match self.egid {
            Some(gid) => gid,
            None => {
                let gid = unsafe { getegid() };
                self.egid = Some(gid);
                gid
            }
        }
    }

    fn get_effective_groupname(&mut self) -> Option<String> {
        let gid = self.get_effective_gid();
        self.get_group_by_gid(gid).map(|g| g.name)
    }

    fn get_effective_uid(&mut self) -> uid_t {
        match self.euid {
            Some(uid) => uid,
            None => {
                let uid = unsafe { geteuid() };
                self.euid = Some(uid);
                uid
            }
        }
    }

    fn get_effective_username(&mut self) -> Option<String> {
        let uid = self.get_effective_uid();
        self.get_user_by_uid(uid).map(|u| u.name)
    }
}

impl OSUsers {
    /// Create a new empty OS Users object.
    pub fn empty_cache() -> OSUsers {
        OSUsers {
            users:       HashMap::new(),
            users_back:  HashMap::new(),
            groups:      HashMap::new(),
            groups_back: HashMap::new(),
            uid:         None,
            gid:         None,
            euid:        None,
            egid:        None,
        }
    }
}

/// Return a User object if one exists for the given user ID; otherwise, return None.
pub fn get_user_by_uid(uid: uid_t) -> Option<User> {
    OSUsers::empty_cache().get_user_by_uid(uid)
}

/// Return a User object if one exists for the given username; otherwise, return None.
pub fn get_user_by_name(username: &str) -> Option<User> {
    OSUsers::empty_cache().get_user_by_name(username)
}

/// Return a Group object if one exists for the given group ID; otherwise, return None.
pub fn get_group_by_gid(gid: gid_t) -> Option<Group> {
    OSUsers::empty_cache().get_group_by_gid(gid)
}

/// Return a Group object if one exists for the given groupname; otherwise, return None.
pub fn get_group_by_name(group_name: &str) -> Option<Group> {
    OSUsers::empty_cache().get_group_by_name(group_name)
}

/// Return the user ID for the user running the process.
pub fn get_current_uid() -> uid_t {
    OSUsers::empty_cache().get_current_uid()
}

/// Return the username of the user running the process.
pub fn get_current_username() -> Option<String> {
    OSUsers::empty_cache().get_current_username()
}

/// Return the user ID for the effective user running the process.
pub fn get_effective_uid() -> uid_t {
    OSUsers::empty_cache().get_effective_uid()
}

/// Return the username of the effective user running the process.
pub fn get_effective_username() -> Option<String> {
    OSUsers::empty_cache().get_effective_username()
}

/// Return the group ID for the user running the process.
pub fn get_current_gid() -> gid_t {
    OSUsers::empty_cache().get_current_gid()
}

/// Return the groupname of the user running the process.
pub fn get_current_groupname() -> Option<String> {
    OSUsers::empty_cache().get_current_groupname()
}

/// Return the group ID for the effective user running the process.
pub fn get_effective_gid() -> gid_t {
    OSUsers::empty_cache().get_effective_gid()
}

/// Return the groupname of the effective user running the process.
pub fn get_effective_groupname() -> Option<String> {
    OSUsers::empty_cache().get_effective_groupname()
}

/// Set current user for the running process, requires root priviledges.
pub fn set_current_uid(uid: uid_t) -> IOResult<()> {
    match unsafe { setuid(uid) } {
        0 => Ok(()),
        -1 => Err(IOError::last_os_error()),
        _ => unreachable!()
    }
}

/// Set current group for the running process, requires root priviledges.
pub fn set_current_gid(gid: gid_t) -> IOResult<()> {
    match unsafe { setgid(gid) } {
        0 => Ok(()),
        -1 => Err(IOError::last_os_error()),
        _ => unreachable!()
    }
}

/// Set effective user for the running process, requires root priviledges.
pub fn set_effective_uid(uid: uid_t) -> IOResult<()> {
    match unsafe { seteuid(uid) } {
        0 => Ok(()),
        -1 => Err(IOError::last_os_error()),
        _ => unreachable!()
    }
}

/// Set effective user for the running process, requires root priviledges.
pub fn set_effective_gid(gid: gid_t) -> IOResult<()> {
    match unsafe { setegid(gid) } {
        0 => Ok(()),
        -1 => Err(IOError::last_os_error()),
        _ => unreachable!()
    }
}

/// Atomically set current and effective user for the running process, requires root priviledges.
pub fn set_both_uid(ruid: uid_t, euid: uid_t) -> IOResult<()> {
    match unsafe { setreuid(ruid, euid) } {
        0 => Ok(()),
        -1 => Err(IOError::last_os_error()),
        _ => unreachable!()
    }
}

/// Atomically set current and effective group for the running process, requires root priviledges.
pub fn set_both_gid(rgid: gid_t, egid: gid_t) -> IOResult<()> {
    match unsafe { setregid(rgid, egid) } {
        0 => Ok(()),
        -1 => Err(IOError::last_os_error()),
        _ => unreachable!()
    }
}

pub struct SwitchUserGuard {
    uid: uid_t,
    gid: gid_t,
}

impl Drop for SwitchUserGuard {
    fn drop(&mut self) {
        // Panic on error here, as failing to set values back
        // is a possible security breach.
        set_effective_uid(self.uid).unwrap();
        set_effective_gid(self.gid).unwrap();
    }
}

/// Safely switch user and group for the current scope.
/// Requires root access.
///
/// ```ignore
/// {
///     let _guard = switch_user_group(1001, 1001);
///     // current and effective user and group ids are 1001
/// }
/// // back to the old values
/// ```
///
/// Use with care! Possible security issues can happen, as Rust doesn't
/// guarantee running the destructor! If in doubt run `drop()` method
/// on the guard value manually!
pub fn switch_user_group(uid: uid_t, gid: gid_t) -> Result<SwitchUserGuard, IOError> {
    let current_state = SwitchUserGuard {
        uid: get_effective_uid(),
        gid: get_effective_gid(),
    };

    try!(set_effective_uid(uid));
    try!(set_effective_gid(gid));
    Ok(current_state)
}

#[cfg(test)]
mod test {
    use super::{Users, OSUsers, get_current_username};

    #[test]
    fn uid() {
        OSUsers::empty_cache().get_current_uid();
    }

    #[test]
    fn username() {
        let mut users = OSUsers::empty_cache();
        let uid = users.get_current_uid();
        assert_eq!(get_current_username().unwrap(), users.get_user_by_uid(uid).unwrap().name);
    }

    #[test]
    fn uid_for_username() {
        let mut users = OSUsers::empty_cache();
        let uid = users.get_current_uid();
        let user = users.get_user_by_uid(uid).unwrap();
        assert_eq!(user.uid, uid);
    }

    #[test]
    fn username_for_uid_for_username() {
        let mut users = OSUsers::empty_cache();
        let uid = users.get_current_uid();
        let user = users.get_user_by_uid(uid).unwrap();
        let user2 = users.get_user_by_uid(user.uid).unwrap();
        assert_eq!(user2.uid, uid);
    }

    #[test]
    fn user_info() {
        let mut users = OSUsers::empty_cache();
        let uid = users.get_current_uid();
        let user = users.get_user_by_uid(uid).unwrap();
        // Not a real test but can be used to verify correct results
        // Use with --nocapture on test executable to show output
        println!("HOME={}, SHELL={}", user.home_dir, user.shell);
    }

    #[test]
    fn get_user_by_name() {
        // We cannot really test for arbitrary user as they might not exist on the machine
        // Instead the name of the current user is used
        let mut users = OSUsers::empty_cache();
        let name = users.get_current_username().unwrap();
        let user_by_name = users.get_user_by_name(&name);
        assert!(user_by_name.is_some());
        assert_eq!(user_by_name.unwrap().name, name);

        // User names containing '\0' cannot be used (for now)
        let user = users.get_user_by_name("user\0");
        assert!(user.is_none());
    }

    #[test]
    fn get_group_by_name() {
        // We cannot really test for arbitrary groups as they might not exist on the machine
        // Instead the primary group of the current user is used
        let mut users = OSUsers::empty_cache();
        let cur_uid = users.get_current_uid();
        let cur_user = users.get_user_by_uid(cur_uid).unwrap();
        let cur_group = users.get_group_by_gid(cur_user.primary_group).unwrap();
        let group_by_name = users.get_group_by_name(&cur_group.name);

        assert!(group_by_name.is_some());
        assert_eq!(group_by_name.unwrap().name, cur_group.name);

        // Group names containing '\0' cannot be used (for now)
        let group = users.get_group_by_name("users\0");
        assert!(group.is_none());
    }
}
