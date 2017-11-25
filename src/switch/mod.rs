//! Functions for switching the running process’s user or group.

#[cfg(target_os = "redox")]
pub mod redox;
#[cfg(unix)]
pub mod unix;

#[cfg(unix)]
pub use self::unix::*;
#[cfg(target_os = "redox")]
pub use self::redox::*;

use libc::{uid_t, gid_t};

/// Guard returned from a `switch_user_group` call.
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