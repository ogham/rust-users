use std::io::{Error as IOError, Result as IOResult};
use libc::{uid_t, gid_t, c_int};

use base::{get_effective_uid, get_effective_gid};


extern {
    fn setuid(uid: uid_t) -> c_int;
    fn seteuid(uid: uid_t) -> c_int;

    fn setgid(gid: gid_t) -> c_int;
    fn setegid(gid: gid_t) -> c_int;

    fn setreuid(ruid: uid_t, euid: uid_t) -> c_int;
    fn setregid(rgid: gid_t, egid: gid_t) -> c_int;
}


/// Sets current user for the running process, requires root priviledges.
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
