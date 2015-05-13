#![crate_name = "users"]
#![crate_type = "rlib"]
#![crate_type = "dylib"]
#![feature(collections, core)]

//! This is a library for getting information on Unix users and groups.
//!
//! In Unix, each user has an individual *user ID*, and each process has an
//! *effective user ID* that says which user's permissions it is using.
//! Furthermore, users can be the members of *groups*, which also have names
//! and IDs. This functionality is exposed in libc, the C standard library,
//! but this an unsafe Rust interface. This wrapper library provides a safe
//! interface, using User and Group objects instead of low-level pointers and
//! strings. It also offers basic caching functionality.
//!
//! It does not (yet) offer *editing* functionality; the objects returned are
//! read-only.
//!
//! Users
//! -----
//!
//! The function `get_current_uid` returns a `uid_t` value representing the user
//! currently running the program, and the `get_user_by_uid` function scans the
//! users database and returns a User object with the user's information. This
//! function returns `None` when there is no user for that ID.
//!
//! A `User` object has the following public fields:
//!
//! - **uid:** The user's ID
//! - **name:** The user's name
//! - **primary_group:** The ID of this user's primary group
//!
//! Here is a complete example that prints out the current user's name:
//!
//! ```rust
//! use users::{get_user_by_uid, get_current_uid};
//! let user = get_user_by_uid(get_current_uid()).unwrap();
//! println!("Hello, {}!", user.name);
//! ```
//!
//! This code assumes (with `unwrap()`) that the user hasn't been deleted
//! after the program has started running. For arbitrary user IDs, this is
//! **not** a safe assumption: it's possible to delete a user while it's
//! running a program, or is the owner of files, or for that user to have
//! never existed. So always check the return values from `user_to_uid`!
//!
//! There is also a `get_current_username` function, as it's such a common
//! operation that it deserves special treatment.
//!
//! Caching
//! -------
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
//! This cache is **only additive**: it's not possible to drop it, or erase
//! selected entries, as when the database may have been modified, it's best to
//! start entirely afresh. So to accomplish this, just start using a new
//! `OSUsers` object.
//!
//! Groups
//! ------
//!
//! Finally, it's possible to get groups in a similar manner. A `Group` object
//! has the following public fields:
//!
//! - **gid:** The group's ID
//! - **name:** The group's name
//! - **members:** Vector of names of the users that belong to this group
//!
//! And again, a complete example:
//!
//! ```rust
//! use users::{Users, OSUsers};
//! let mut cache = OSUsers::empty_cache();
//! match cache.get_group_by_name("admin") {
//!     None => {},
//!     Some(group) => {
//!         println!("The '{}' group has the ID {}", group.name, group.gid);
//!         for member in group.members.into_iter() {
//!             println!("{} is a member of the group", member);
//!         }
//!     }
//! }
//! ```
//!
//! Caveats
//! -------
//!
//! You should be prepared for the users and groups tables to be completely
//! broken: IDs shouldn't be assumed to map to actual users and groups, and
//! usernames and group names aren't guaranteed to map either!
//!
//! Use the mocking module to create custom tables to test your code for these
//! edge cases.

extern crate libc;
pub use libc::{uid_t, gid_t};
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
use libc::{c_char, time_t};
#[cfg(target_os = "linux")]
use libc::c_char;

extern crate collections;
use collections::borrow::ToOwned;

use std::ffi::CStr;
use std::ptr::read;
use std::str::from_utf8_unchecked;
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Occupied, Vacant};

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
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
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

    // The list of members is a pointer to a pointer of
    // characters, terminated by a null pointer.
    loop {
        match groups.offset(i).as_ref() {
            Some(&username) => {
                if !username.is_null() {
                    members.push(from_raw_buf(username as *const i8));
                }
                else {
                    return members;
                }

                i += 1;
            },

            // This should never happen, but if it does, this is the
            // sensible thing to do
            None => return members,
        }
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
                let user = unsafe { passwd_to_user(getpwnam(username.as_ptr() as *const i8)) };
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
        match self.groups.clone().entry(gid) {
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
        match self.groups_back.clone().entry(group_name.to_owned()) {
            Vacant(entry) => {
                let user = unsafe { struct_to_group(getgrnam(group_name.as_ptr() as *const i8)) };
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
}
