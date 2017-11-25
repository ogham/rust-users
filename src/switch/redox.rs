
//! Functions for switching the running process’s user or group in Redox OS.

use redox_syscall;

use std::io::Result as IOResult;
use libc::{uid_t, gid_t};

use base::{get_effective_uid, get_effective_gid};
use super::SwitchUserGuard;

/// Sets the **current user** for the running process to the one with the
/// given user ID. Uses `setreuid` internally.
///
/// Typically, trying to switch to anyone other than the user already running
/// the process requires root privileges.
pub fn set_current_uid(uid: uid_t) -> IOResult<()> {
    match redox_syscall::setreuid(uid, -1 as _) {
         Ok(_) => Ok(()),
         Err(n) => unreachable!("setreuid returned {}", n)
    }
}

/// Sets the **current group** for the running process to the one with the
/// given group ID. Uses `setregid` internally.
///
/// Typically, trying to switch to any group other than the group already
/// running the process requires root privileges.
pub fn set_current_gid(gid: gid_t) -> IOResult<()> {
    match redox_syscall::setregid(gid, -1 as _) {
         Ok(_) => Ok(()),
         Err(n) => unreachable!("setregid returned {}", n)
    }
}

/// Sets the **effective user** for the running process to the one with the
/// given user ID. Uses `setreuid` internally.
///
/// Typically, trying to switch to anyone other than the user already running
/// the process requires root privileges.
pub fn set_effective_uid(uid: uid_t) -> IOResult<()> {
    match redox_syscall::setreuid(-1 as _, uid) {
         Ok(_) => Ok(()),
         Err(n) => unreachable!("setreuid returned {}", n)
    }
}

/// Sets the **effective group** for the running process to the one with the
/// given group ID. Uses `setregid` internally.
///
/// Typically, trying to switch to any group other than the group already
/// running the process requires root privileges.
pub fn set_effective_gid(gid: gid_t) -> IOResult<()> {
    match redox_syscall::setregid(-1 as _, gid) {
         Ok(_) => Ok(()),
         Err(n) => unreachable!("setregid returned {}", n)
    }
}

/// Sets both the **current user** and the **effective user** for the running
/// process to the ones with the given user IDs. Uses `setreuid` internally.
///
/// Typically, trying to switch to anyone other than the user already running
/// the process requires root privileges.
pub fn set_both_uid(ruid: uid_t, euid: uid_t) -> IOResult<()> {
    match redox_syscall::setreuid(ruid, euid) {
         Ok(_) => Ok(()),
         Err(n) => unreachable!("setreuid returned {}", n)
    }
}

/// Sets both the **current group** and the **effective group** for the
/// running process to the ones with the given group IDs. Uses `setregid`
/// internally.
///
/// Typically, trying to switch to any group other than the group already
/// running the process requires root privileges.
pub fn set_both_gid(rgid: gid_t, egid: gid_t) -> IOResult<()> {
    match redox_syscall::setregid(rgid, egid) {
         Ok(_) => Ok(()),
         Err(n) => unreachable!("setregid returned {}", n)
    }
}

/// Sets the **effective user** and the **effective group** for the current
/// scope.
///
/// Typically, trying to switch to any user or group other than the ones already
/// running the process requires root privileges.
///
/// **Use with care!** Possible security issues can happen, as Rust doesn't
/// guarantee running the destructor! If in doubt run `drop()` method on the
/// guard value manually!
///
/// ### Examples
///
/// ```no_run
/// use users::switch::switch_user_group;
///
/// {
///     let _guard = switch_user_group(1001, 1001);
///     // current and effective user and group ids are 1001
/// }
/// // back to the old values
/// ```
pub fn switch_user_group(uid: uid_t, gid: gid_t) -> IOResult<SwitchUserGuard> {
    let current_state = SwitchUserGuard {
        uid: get_effective_uid(),
        gid: get_effective_gid(),
    };

    set_effective_gid(gid)?;
    set_effective_uid(uid)?;

    Ok(current_state)
}