//! Mockable users and groups.
//!
//! When you’re testing your code, you don’t want to actually rely on the
//! system actually having various users and groups present - it’s much better
//! to have a custom set of users that are *guaranteed* to be there, so you can
//! test against them.
//!
//! This sub-library allows you to create these custom users and groups
//! definitions, then access them using the same `Users` trait as in the main
//! library, with few changes to your code.
//!
//!
//! ## Creating Mock Users
//!
//! The only thing a mock users object needs to know in advance is the UID of
//! the current user. Aside from that, you can add users and groups with
//! `add_user` and `add_group` to the object:
//!
//! ```rust
//! use users::mock::{MockUsers, User, Group};
//! use std::sync::Arc;
//!
//! let mut users = MockUsers::with_current_uid(1000);
//! users.add_user(User { uid: 1000, name: Arc::new("Bobbins".to_string()), primary_group: 100, home_dir: "/home/bobbins".to_string(), shell: "/bin/bash".to_string() });
//! users.add_group(Group { gid: 100, name: Arc::new("funkyppl".to_string()), members: vec![ "other_person".to_string() ] });
//! ```
//!
//! The exports get re-exported into the mock module, for simpler `use` lines.
//!
//!
//! ## Using Mock Users
//!
//! To set your program up to use either type of Users object, make your
//! functions and structs accept a generic parameter that implements the `Users`
//! trait. Then, you can pass in an object of either OS or Mock type.
//!
//! Here's a complete example:
//!
//! ```rust
//! use users::{Users, OSUsers, User};
//! use users::mock::MockUsers;
//! use std::sync::Arc;
//!
//! fn print_current_username<U: Users>(users: &mut U) {
//!     println!("Current user: {:?}", users.get_current_username());
//! }
//!
//! let mut users = MockUsers::with_current_uid(1001);
//! users.add_user(User { uid: 1001, name: Arc::new("fred".to_string()), primary_group: 101 , home_dir: "/home/fred".to_string(), shell: "/bin/bash".to_string()});
//! print_current_username(&mut users);
//!
//! let mut actual_users = OSUsers::empty_cache();
//! print_current_username(&mut actual_users);
//! ```

use std::collections::HashMap;
use std::sync::Arc;

pub use libc::{uid_t, gid_t};
pub use base::{User, Group};
pub use traits::{Users, Groups};


/// A mocking users object that you can add your own users and groups to.
pub struct MockUsers {
    users: HashMap<uid_t, Arc<User>>,
    groups: HashMap<gid_t, Arc<Group>>,
    uid: uid_t,
}

impl MockUsers {

    /// Create a new, empty mock users object.
    pub fn with_current_uid(current_uid: uid_t) -> MockUsers {
        MockUsers {
            users: HashMap::new(),
            groups: HashMap::new(),
            uid: current_uid,
        }
    }

    /// Add a user to the users table.
    pub fn add_user(&mut self, user: User) -> Option<Arc<User>> {
        self.users.insert(user.uid, Arc::new(user))
    }

    /// Add a group to the groups table.
    pub fn add_group(&mut self, group: Group) -> Option<Arc<Group>> {
        self.groups.insert(group.gid, Arc::new(group))
    }
}

impl Users for MockUsers {
    fn get_user_by_uid(&self, uid: uid_t) -> Option<Arc<User>> {
        self.users.get(&uid).cloned()
    }

    fn get_user_by_name(&self, username: &str) -> Option<Arc<User>> {
        self.users.values().find(|u| &*u.name == username).cloned()
    }

    fn get_current_uid(&self) -> uid_t {
        self.uid
    }

    fn get_current_username(&self) -> Option<Arc<String>> {
        self.users.get(&self.uid).map(|u| u.name.clone())
    }

    fn get_effective_uid(&self) -> uid_t {
        self.uid
    }

    fn get_effective_username(&self) -> Option<Arc<String>> {
        self.users.get(&self.uid).map(|u| u.name.clone())
    }
}

impl Groups for MockUsers {
    fn get_group_by_gid(&self, gid: gid_t) -> Option<Arc<Group>> {
        self.groups.get(&gid).cloned()
    }

    fn get_group_by_name(&self, group_name: &str) -> Option<Arc<Group>> {
        self.groups.values().find(|g| &*g.name == group_name).cloned()
    }

    fn get_current_gid(&self) -> uid_t {
        self.uid
    }

    fn get_current_groupname(&self) -> Option<Arc<String>> {
        self.groups.get(&self.uid).map(|u| u.name.clone())
    }

    fn get_effective_gid(&self) -> uid_t {
        self.uid
    }

    fn get_effective_groupname(&self) -> Option<Arc<String>> {
        self.groups.get(&self.uid).map(|u| u.name.clone())
    }
}

#[cfg(test)]
mod test {
    use super::{MockUsers};
    use base::{User, Group};
    use traits::{Users, Groups};
    use std::sync::Arc;

    #[test]
    fn current_username() {
        let mut users = MockUsers::with_current_uid(1337);
        users.add_user(User { uid: 1337, name: Arc::new("fred".to_string()), primary_group: 101, home_dir: "/home/fred".to_string(), shell: "/bin/bash".to_string() });
        assert_eq!(Some(Arc::new("fred".into())), users.get_current_username())
    }

    #[test]
    fn no_current_username() {
        let users = MockUsers::with_current_uid(1337);
        assert_eq!(None, users.get_current_username())
    }

    #[test]
    fn uid() {
        let mut users = MockUsers::with_current_uid(0);
        users.add_user(User { uid: 1337, name: Arc::new("fred".to_string()), primary_group: 101, home_dir: "/home/fred".to_string(), shell: "/bin/bash".to_string() });
        assert_eq!(Some(Arc::new("fred".into())), users.get_user_by_uid(1337).map(|u| u.name.clone()))
    }

    #[test]
    fn username() {
        let mut users = MockUsers::with_current_uid(1337);
        users.add_user(User { uid: 1440, name: Arc::new("fred".to_string()), primary_group: 101, home_dir: "/home/fred".to_string(), shell: "/bin/bash".to_string() });
        assert_eq!(Some(1440), users.get_user_by_name("fred").map(|u| u.uid))
    }

    #[test]
    fn no_username() {
        let mut users = MockUsers::with_current_uid(1337);
        users.add_user(User { uid: 1440, name: Arc::new("fred".to_string()), primary_group: 101, home_dir: "/home/fred".to_string(), shell: "/bin/bash".to_string() });
        assert_eq!(None, users.get_user_by_name("criminy").map(|u| u.uid))
    }

    #[test]
    fn no_uid() {
        let users = MockUsers::with_current_uid(0);
        assert_eq!(None, users.get_user_by_uid(1337).map(|u| u.name.clone()))
    }

    #[test]
    fn gid() {
        let mut users = MockUsers::with_current_uid(0);
        users.add_group(Group { gid: 1337, name: Arc::new("fred".to_string()), members: vec![], });
        assert_eq!(Some(Arc::new("fred".into())), users.get_group_by_gid(1337).map(|g| g.name.clone()))
    }

    #[test]
    fn group_name() {
        let mut users = MockUsers::with_current_uid(0);
        users.add_group(Group { gid: 1337, name: Arc::new("fred".to_string()), members: vec![], });
        assert_eq!(Some(1337), users.get_group_by_name("fred").map(|g| g.gid))
    }

    #[test]
    fn no_group_name() {
        let mut users = MockUsers::with_current_uid(0);
        users.add_group(Group { gid: 1337, name: Arc::new("fred".to_string()), members: vec![], });
        assert_eq!(None, users.get_group_by_name("santa").map(|g| g.gid))
    }

    #[test]
    fn no_gid() {
        let users = MockUsers::with_current_uid(0);
        assert_eq!(None, users.get_group_by_gid(1337).map(|g| g.name.clone()))
    }
}
