//! OS-specific extensions to users and groups.
//!
//! Every OS has a different idea of what data a user or a group comes with.
//! Although they all provide a *username*, some OS’ users have an *actual name*
//! too, or a set of permissions or directories or timestamps associated with
//! them.
//!
//! This module provides extension traits for users and groups that allow
//! implementors of this library to access this data *as long as a trait is
//! available*, which requires the OS they’re using to support this data.
//!
//! It’s the same method taken by `Metadata` in the standard Rust library,
//! which has a few cross-platform fields and many more OS-specific fields:
//! traits in `std::os` provides access to any data that is not guaranteed to
//! be there in the actual struct.


/// Extensions to users and groups for Unix platforms.
///
/// Although the `passwd` struct is common among Unix systems, its actual
/// format can vary. See the definitions in the `base` module to check which
/// fields are actually present.
pub mod unix {
    use std::path::Path;
    use libc::{uid_t, gid_t};

    /// Unix-specific extensions for `User`s.
    pub trait UserExt {

        /// Returns a path to this user’s home directory.
        fn home_dir(&self) -> &Path;

        /// Sets this user value’s home directory to the given string.
        /// Can be used to construct test users, which by default come with a
        /// dummy home directory string.
        fn with_home_dir(mut self, home_dir: &str) -> Self;

        /// Returns a path to this user’s shell.
        fn shell(&self) -> &Path;

        /// Sets this user’s shell path to the given string.
        /// Can be used to construct test users, which by default come with a
        /// dummy shell field.
        fn with_shell(mut self, shell: &str) -> Self;

        // TODO(ogham): Isn’t it weird that the setters take string slices, but
        // the getters return paths?

        /// Create a new `User` with the given user ID, name, and primary
        /// group ID, with the rest of the fields filled with dummy values.
        ///
        /// This method does not actually create a new user on the system—it
        /// should only be used for comparing users in tests.
        fn new(uid: uid_t, name: &str, primary_group: gid_t) -> Self;
    }

    /// Unix-specific extensions for `Group`s.
    pub trait GroupExt {

        /// Returns a slice of the list of users that are in this group as
        /// their non-primary group.
        fn members(&self) -> &[String];

        /// Create a new `Group` with the given group ID and name, with the
        /// rest of the fields filled in with dummy values.
        ///
        /// This method does not actually create a new group on the system—it
        /// should only be used for comparing groups in tests.
        fn new(gid: gid_t, name: &str) -> Self;
    }
}
