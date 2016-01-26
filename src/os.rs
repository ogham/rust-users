
pub mod unix {
    use std::path::Path;
    use libc::{uid_t, gid_t};

    pub trait UserExt {
        fn home_dir(&self) -> &Path;
        fn with_home_dir(mut self, home_dir: &str) -> Self;

        fn shell(&self) -> &Path;
        fn with_shell(mut self, shell: &str) -> Self;

        // TODO(ogham): Isn't it weird that the setters take a string slice, but
        // the getters return a Path?

        fn new(uid: uid_t, name: &str, primary_group: gid_t) -> Self;
    }

    pub trait GroupExt {
        fn members(&self) -> &[String];
        fn new(gid: gid_t, name: &str) -> Self;
    }
}