//! Integration with the Redox OS users and groups.
//!

#![allow(missing_copy_implementations)]  // for the C structs

use std::sync::Arc;
use std::convert::From;

use libc::{uid_t, gid_t};
use redox_users;
use super::{User, Group};

impl From<redox_users::User> for User {
    fn from(redox_user: redox_users::User) -> Self {
        User {
            uid: redox_user.uid as uid_t,
            name_arc: Arc::new(redox_user.user),
            primary_group: redox_user.gid as uid_t,
            extras: super::os::UserExtras {
                home_dir:  redox_user.home,
                shell: redox_user.shell
            }
        }
    }
}

impl From<redox_users::Group> for Group {
    fn from(redox_group: redox_users::Group) -> Self {
        Group::new(redox_group.gid as gid_t, &redox_group.group)
    }
}

/// Searches for a `User` with the given ID in the system’s user database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_user_by_uid(uid: uid_t) -> Option<User> {
    match redox_users::get_user_by_id(uid) {
        None => None,
        Some(redox_user) => Some(User::from(redox_user))
    }
}

/// Searches for a `User` with the given username in the system’s user database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_user_by_name(username: &str) -> Option<User> {
    match redox_users::get_user_by_name(username) {
        None => None,
        Some(redox_user) => Some(User::from(redox_user))
    }
}

/// Searches for a `Group` with the given ID in the system’s group database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_group_by_gid(gid: gid_t) -> Option<Group> {
    match redox_users::get_group_by_id(gid) {
        None => None,
        Some(redox_group) => Some(Group::from(redox_group))
    }
}

/// Searches for a `Group` with the given group name in the system’s group database.
/// Returns it if one is found, otherwise returns `None`.
pub fn get_group_by_name(group_name: &str) -> Option<Group> {
    match redox_users::get_group_by_name(group_name) {
        None => None,
        Some(redox_group) => Some(Group::from(redox_group))
    }
}

/// Returns the user ID for the user running the process.
pub fn get_current_uid() -> uid_t {
    redox_users::get_uid()
}

/// Returns the username of the user running the process.
pub fn get_current_username() -> Option<String> {
    let uid = get_current_uid();

    redox_users::get_user_by_id(uid).map(|u| u.user)
}

/// Returns the user ID for the effective user running the process.
pub fn get_effective_uid() -> uid_t {
    redox_users::get_euid()
}

/// Returns the username of the effective user running the process.
pub fn get_effective_username() -> Option<String> {
    let uid = get_effective_uid();

    redox_users::get_user_by_id(uid).map(|u| u.user)
}

/// Returns the group ID for the user running the process.
pub fn get_current_gid() -> gid_t {
    redox_users::get_gid()
}

/// Returns the groupname of the user running the process.
pub fn get_current_groupname() -> Option<String> {
    let gid = get_current_gid();

    redox_users::get_group_by_id(gid).map(|g| g.group)
}

/// Returns the group ID for the effective user running the process.
pub fn get_effective_gid() -> gid_t {
    redox_users::get_egid()
}

/// Returns the groupname of the effective user running the process.
pub fn get_effective_groupname() -> Option<String> {
    let gid = get_effective_gid();

    redox_users::get_group_by_id(gid).map(|g| g.group)
}

/// An iterator over every user present on the system.
///
/// This struct actually requires no fields, but has one hidden one to make it
/// `unsafe` to create.
pub struct AllUsers(redox_users::AllUsers);

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
        AllUsers(redox_users::all_users())
    }
}

impl Iterator for AllUsers {
    type Item = User;

    fn next(&mut self) -> Option<User> {
        self.0.next().map(|redox_user| User::from(redox_user))
    }
}