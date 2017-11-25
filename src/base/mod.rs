#[cfg(target_os = "redox")]
pub mod redox;
#[cfg(unix)]
pub mod unix;

#[cfg(unix)]
pub use self::unix::{get_user_by_uid, get_user_by_name};
#[cfg(unix)]
pub use self::unix::{get_group_by_gid, get_group_by_name};
#[cfg(unix)]
pub use self::unix::{get_current_uid, get_current_username};
#[cfg(unix)]
pub use self::unix::{get_effective_uid, get_effective_username};
#[cfg(unix)]
pub use self::unix::{get_current_gid, get_current_groupname};
#[cfg(unix)]
pub use self::unix::{get_effective_gid, get_effective_groupname};
#[cfg(unix)]
pub use self::unix::AllUsers;

#[cfg(target_os = "redox")]
pub use self::redox::{get_user_by_uid, get_user_by_name};
#[cfg(target_os = "redox")]
pub use self::redox::{get_group_by_gid, get_group_by_name};
#[cfg(target_os = "redox")]
pub use self::redox::{get_current_uid, get_current_username};
#[cfg(target_os = "redox")]
pub use self::redox::{get_effective_uid, get_effective_username};
#[cfg(target_os = "redox")]
pub use self::redox::{get_current_gid, get_current_groupname};
#[cfg(target_os = "redox")]
pub use self::redox::{get_effective_gid, get_effective_groupname};
#[cfg(target_os = "redox")]
pub use self::redox::AllUsers;

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use libc::{uid_t, gid_t};

/// Information about a particular user.
#[derive(Clone)]
pub struct User {
    pub(crate) uid: uid_t,
    pub(crate) primary_group: gid_t,
    pub(crate) extras: super::os::UserExtras,

    /// This user’s name, as an owned `String` possibly shared with a cache.
    /// Prefer using the `name()` accessor to using this field, if possible.
    pub name_arc: Arc<String>,
}

impl User {

    /// Create a new `User` with the given user ID, name, and primary
    /// group ID, with the rest of the fields filled with dummy values.
    ///
    /// This method does not actually create a new user on the system—it
    /// should only be used for comparing users in tests.
    pub fn new(uid: uid_t, name: &str, primary_group: gid_t) -> User {
        User {
            uid: uid,
            name_arc: Arc::new(name.to_owned()),
            primary_group: primary_group,
            extras: super::os::UserExtras::default(),
        }
    }

    /// Returns this user’s ID.
    pub fn uid(&self) -> uid_t {
        self.uid.clone()
    }

    /// Returns this user’s name.
    pub fn name(&self) -> &str {
        &**self.name_arc
    }

    /// Returns the ID of this user’s primary group.
    pub fn primary_group_id(&self) -> gid_t {
        self.primary_group.clone()
    }
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            f.debug_struct("User")
             .field("uid", &self.uid)
             .field("name_arc", &self.name_arc)
             .field("primary_group", &self.primary_group)
             .field("extras", &self.extras)
             .finish()
        }
        else {
            write!(f, "User({}, {})", self.uid(), self.name())
        }
    }
}

/// Information about a particular group.
#[derive(Clone)]
pub struct Group {
    pub(crate) gid: gid_t,
    pub(crate) extras: super::os::GroupExtras,

    /// This group’s name, as an owned `String` possibly shared with a cache.
    /// Prefer using the `name()` accessor to using this field, if possible.
    pub name_arc: Arc<String>,
}

impl Group {

    /// Create a new `Group` with the given group ID and name, with the
    /// rest of the fields filled in with dummy values.
    ///
    /// This method does not actually create a new group on the system—it
    /// should only be used for comparing groups in tests.
    pub fn new(gid: gid_t, name: &str) -> Self {
        Group {
            gid: gid,
            name_arc: Arc::new(String::from(name)),
            extras: super::os::GroupExtras::default(),
        }
    }

    /// Returns this group’s ID.
    pub fn gid(&self) -> gid_t {
        self.gid.clone()
    }

    /// Returns this group's name.
    pub fn name(&self) -> &str {
        &**self.name_arc
    }
}

impl fmt::Debug for Group {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            f.debug_struct("Group")
             .field("gid", &self.gid)
             .field("name_arc", &self.name_arc)
             .field("extras", &self.extras)
             .finish()
        }
        else {
            write!(f, "Group({}, {})", self.gid(), self.name())
        }
    }
}

pub trait UserExt {
    /// Returns a path to this user’s home directory.
    fn home_dir(&self) -> &Path;

    /// Sets this user value’s home directory to the given string.
    /// Can be used to construct test users, which by default come with a
    /// dummy home directory string.
    fn with_home_dir(self, home_dir: &str) -> Self;

    /// Returns a path to this user’s shell.
    fn shell(&self) -> &Path;

    /// Sets this user’s shell path to the given string.
    /// Can be used to construct test users, which by default come with a
    /// dummy shell field.
    fn with_shell(self, shell: &str) -> Self;

    // TODO(ogham): Isn’t it weird that the setters take string slices, but
    // the getters return paths?
}

pub trait GroupExt {

    /// Returns a slice of the list of users that are in this group as
    /// their non-primary group.
    fn members(&self) -> &[String];

    /// Adds a new member to this group.
    fn add_member(self, name: &str) -> Self;
}

/// OS-specific extensions to users and groups.
///
/// Every OS has a different idea of what data a user or a group comes with.
/// Although they all provide a *username*, some OS’ users have an *actual name*
/// too, or a set of permissions or directories or timestamps associated with
/// them.
///
/// This module provides extension traits for users and groups that allow
/// implementors of this library to access this data *as long as a trait is
/// available*, which requires the OS they’re using to support this data.
///
/// It’s the same method taken by `Metadata` in the standard Rust library,
/// which has a few cross-platform fields and many more OS-specific fields:
/// traits in `std::os` provides access to any data that is not guaranteed to
/// be there in the actual struct.
pub mod os {

    /// Extensions to users and groups for Unix platforms.
    ///
    /// Although the `passwd` struct is common among Unix systems, its actual
    /// format can vary. See the definitions in the `base` module to check which
    /// fields are actually present.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))]
    pub mod unix {
        use std::path::Path;

        use super::super::Group;
        use super::super::unix::{c_passwd, c_group, members, from_raw_buf};

        /// Unix-specific extensions for `User`s.
        pub trait UserExt {

            /// Returns a path to this user’s home directory.
            fn home_dir(&self) -> &Path;

            /// Sets this user value’s home directory to the given string.
            /// Can be used to construct test users, which by default come with a
            /// dummy home directory string.
            fn with_home_dir(self, home_dir: &str) -> Self;

            /// Returns a path to this user’s shell.
            fn shell(&self) -> &Path;

            /// Sets this user’s shell path to the given string.
            /// Can be used to construct test users, which by default come with a
            /// dummy shell field.
            fn with_shell(self, shell: &str) -> Self;

            // TODO(ogham): Isn’t it weird that the setters take string slices, but
            // the getters return paths?
        }

        /// Unix-specific extensions for `Group`s.
        pub trait GroupExt {

            /// Returns a slice of the list of users that are in this group as
            /// their non-primary group.
            fn members(&self) -> &[String];

            /// Adds a new member to this group.
            fn add_member(self, name: &str) -> Self;
        }

        /// Unix-specific fields for `User`s.
        #[derive(Clone, Debug)]
        pub struct UserExtras {

            /// The path to the user’s home directory.
            pub home_dir: String,

            /// The path to the user’s shell.
            pub shell: String,
        }

        impl Default for UserExtras {
            fn default() -> UserExtras {
                UserExtras {
                    home_dir: String::from("/var/empty"),
                    shell:    String::from("/bin/false"),
                }
            }
        }

        impl UserExtras {
            /// Extract the OS-specific fields from the C `passwd` struct that
            /// we just read.
            pub unsafe fn from_passwd(passwd: c_passwd) -> UserExtras {
                let home_dir = from_raw_buf(passwd.pw_dir);
                let shell    = from_raw_buf(passwd.pw_shell);

                UserExtras {
                    home_dir:  home_dir,
                    shell:     shell,
                }
            }
        }

        #[cfg(any(target_os = "linux"))]
        use super::super::User;

        #[cfg(any(target_os = "linux"))]
        impl UserExt for User {
            fn home_dir(&self) -> &Path {
                Path::new(&self.extras.home_dir)
            }

            fn with_home_dir(mut self, home_dir: &str) -> User {
                self.extras.home_dir = home_dir.to_owned();
                self
            }

            fn shell(&self) -> &Path {
                Path::new(&self.extras.shell)
            }

            fn with_shell(mut self, shell: &str) -> User {
                self.extras.shell = shell.to_owned();
                self
            }
        }

        /// Unix-specific fields for `Group`s.
        #[derive(Clone, Default, Debug)]
        pub struct GroupExtras {

            /// Vector of usernames that are members of this group.
            pub members: Vec<String>,
        }

        impl GroupExtras {
            /// Extract the OS-specific fields from the C `group` struct that
            /// we just read.
            pub unsafe fn from_struct(group: c_group) -> GroupExtras {
                let members = members(group.gr_mem);

                GroupExtras {
                    members: members,
                }
            }
        }

        impl GroupExt for Group {
            fn members(&self) -> &[String] {
                &*self.extras.members
            }

            fn add_member(mut self, member: &str) -> Group {
                self.extras.members.push(member.to_owned());
                self
            }
        }
    }

    /// Extensions to users and groups for BSD platforms.
    ///
    /// These platforms have `change` and `expire` fields in their `passwd`
    /// C structs.
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))]
    pub mod bsd {
        use std::path::Path;
        use libc::time_t;
        use super::super::User;
        use super::super::unix::c_passwd;

        /// BSD-specific fields for `User`s.
        #[derive(Clone, Debug)]
        pub struct UserExtras {

            /// Fields specific to Unix, rather than just BSD. (This struct is
            /// a superset, so it has to have all the other fields in it, too).
            pub extras: super::unix::UserExtras,

            /// Password change time.
            pub change: time_t,

            /// Password expiry time.
            pub expire: time_t,
        }

        impl UserExtras {
            /// Extract the OS-specific fields from the C `passwd` struct that
            /// we just read.
            pub unsafe fn from_passwd(passwd: c_passwd) -> UserExtras {
                UserExtras {
                    change: passwd.pw_change,
                    expire: passwd.pw_expire,
                    extras: super::unix::UserExtras::from_passwd(passwd),
                }
            }
        }

        impl super::unix::UserExt for User {
            fn home_dir(&self) -> &Path {
                Path::new(&self.extras.extras.home_dir)
            }

            fn with_home_dir(mut self, home_dir: &str) -> User {
                self.extras.extras.home_dir = home_dir.to_owned();
                self
            }

            fn shell(&self) -> &Path {
                Path::new(&self.extras.extras.shell)
            }

            fn with_shell(mut self, shell: &str) -> User {
                self.extras.extras.shell = shell.to_owned();
                self
            }
        }

        /// BSD-specific accessors for `User`s.
        pub trait UserExt {

            /// Returns this user's password change timestamp.
            fn password_change_time(&self) -> time_t;

            /// Returns this user's password expiry timestamp.
            fn password_expire_time(&self) -> time_t;
        }

        impl UserExt for User {
            fn password_change_time(&self) -> time_t {
                self.extras.change.clone()
            }

            fn password_expire_time(&self) -> time_t {
                self.extras.expire.clone()
            }
        }

        impl Default for UserExtras {
            fn default() -> UserExtras {
                UserExtras {
                    extras: super::unix::UserExtras::default(),
                    change: 0,
                    expire: 0,
                }
            }
        }
    }


    /// Extensions to users and groups for Redox.
    #[cfg(target_os = "redox")]
    pub mod redox {
        use std::path::Path;

        use super::super::Group;

        /// Redox-specific extensions for `User`s.
        pub trait UserExt {
            /// Returns a path to this user’s home directory.
            fn home_dir(&self) -> &Path;

            /// Sets this user value’s home directory to the given string.
            /// Can be used to construct test users, which by default come with a
            /// dummy home directory string.
            fn with_home_dir(self, home_dir: &str) -> Self;

            /// Returns a path to this user’s shell.
            fn shell(&self) -> &Path;

            /// Sets this user’s shell path to the given string.
            /// Can be used to construct test users, which by default come with a
            /// dummy shell field.
            fn with_shell(self, shell: &str) -> Self;

            // TODO(ogham): Isn’t it weird that the setters take string slices, but
            // the getters return paths?
        }

        /// Unix-specific extensions for `Group`s.
        pub trait GroupExt {

            /// Returns a slice of the list of users that are in this group as
            /// their non-primary group.
            fn members(&self) -> &[String];

            /// Adds a new member to this group.
            fn add_member(self, name: &str) -> Self;
        }

        /// Redox-specific fields for `User`s.
        #[derive(Clone, Debug)]
        pub struct UserExtras {
            /// The path to the user’s home directory.
            pub home_dir: String,

            /// The path to the user’s shell.
            pub shell: String,
        }

        impl Default for UserExtras {
            fn default() -> UserExtras {
                UserExtras {
                    home_dir: String::from("/var/empty"),
                    shell:    String::from("/bin/ion"),
                }
            }
        }

        use super::super::User;

        impl UserExt for User {
            fn home_dir(&self) -> &Path {
                Path::new(&self.extras.home_dir)
            }

            fn with_home_dir(mut self, home_dir: &str) -> User {
                self.extras.home_dir = home_dir.to_owned();
                self
            }

            fn shell(&self) -> &Path {
                Path::new(&self.extras.shell)
            }

            fn with_shell(mut self, shell: &str) -> User {
                self.extras.shell = shell.to_owned();
                self
            }
        }

        /// Unix-specific fields for `Group`s.
        #[derive(Clone, Default, Debug)]
        pub struct GroupExtras {

            /// Vector of usernames that are members of this group.
            pub members: Vec<String>,
        }

        impl GroupExt for Group {
            fn members(&self) -> &[String] {
                &*self.extras.members
            }

            fn add_member(mut self, member: &str) -> Group {
                self.extras.members.push(member.to_owned());
                self
            }
        }
    }

    /// Any extra fields on a `User` specific to the current platform.
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))]
    pub type UserExtras = bsd::UserExtras;

    /// Any extra fields on a `User` specific to the current platform.
    #[cfg(any(target_os = "linux"))]
    pub type UserExtras = unix::UserExtras;

    /// Any extra fields on a `Group` specific to the current platform.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))]
    pub type GroupExtras = unix::GroupExtras;

    /// Any extra fields on a `User` specific to the current platform.
    #[cfg(any(target_os = "redox"))]
    pub type UserExtras = redox::UserExtras;

    /// Any extra fields on a `Group` specific to the current platform.
    #[cfg(target_os = "redox")]
    pub type GroupExtras = redox::GroupExtras;
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
        assert_eq!(&*get_current_username().unwrap(), &*get_user_by_uid(uid).unwrap().name());
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
        #[cfg(unix)]
        use base::os::unix::UserExt;

        #[cfg(target_os = "redox")]
        use base::os::redox::UserExt;

        let uid = get_current_uid();
        let user = get_user_by_uid(uid).unwrap();
        // Not a real test but can be used to verify correct results
        // Use with --nocapture on test executable to show output
        println!("HOME={:?}, SHELL={:?}", user.home_dir(), user.shell());
    }

    #[test]
    fn user_by_name() {
        // We cannot really test for arbitrary user as they might not exist on the machine
        // Instead the name of the current user is used
        let name = get_current_username().unwrap();
        let user_by_name = get_user_by_name(&name);
        assert!(user_by_name.is_some());
        assert_eq!(user_by_name.unwrap().name(), &*name);

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
        let group_by_name = get_group_by_name(&cur_group.name());

        assert!(group_by_name.is_some());
        assert_eq!(group_by_name.unwrap().name(), cur_group.name());

        // Group names containing '\0' cannot be used (for now)
        let group = get_group_by_name("users\0");
        assert!(group.is_none());
    }
}


