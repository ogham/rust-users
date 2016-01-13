use libc::{uid_t, gid_t};
use std::borrow::ToOwned;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;

use super::{User, Group, Users};


/// A producer of user and group instances that caches every result.
#[derive(Clone)]
pub struct OSUsers {
    users: BiMap<uid_t, User>,
    groups: BiMap<gid_t, Group>,

    uid: Option<uid_t>,
    gid: Option<gid_t>,
    euid: Option<uid_t>,
    egid: Option<gid_t>,
}

/// A kinda-bi-directional HashMap that associates keys to values, and then
/// strings back to keys. It doesn’t go the full route and offer
/// *values*-to-keys lookup, because we only want to search based on
/// usernames and group names. There wouldn’t be much point offering a “User
/// to uid” map, as the uid is present in the user struct!
#[derive(Clone)]
struct BiMap<K, V> {
    forward:  HashMap<K, Option<V>>,
    backward: HashMap<String, Option<K>>,
}

impl OSUsers {
    /// Create a new empty OS Users object.
    pub fn empty_cache() -> OSUsers {
        OSUsers {
            users: BiMap {
                forward:  HashMap::new(),
                backward: HashMap::new(),
            },

            groups: BiMap {
                forward:  HashMap::new(),
                backward: HashMap::new(),
            },

            uid:         None,
            gid:         None,
            euid:        None,
            egid:        None,
        }
    }
}

impl Users for OSUsers {
    fn get_user_by_uid(&mut self, uid: uid_t) -> Option<User> {
        match self.users.forward.entry(uid) {
            Vacant(entry) => {
                let user = super::get_user_by_uid(uid);
                match user {
                    Some(user) => {
                        entry.insert(Some(user.clone()));
                        self.users.backward.insert(user.name.clone(), Some(user.uid));
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
        match self.users.backward.entry(username.to_owned()) {
            Vacant(entry) => {
                let user = super::get_user_by_name(username);
                match user {
                    Some(user) => {
                        entry.insert(Some(user.uid));
                        self.users.forward.insert(user.uid, Some(user.clone()));
                        Some(user)
                    },
                    None => {
                        entry.insert(None);
                        None
                    }
                }
            },
            Occupied(entry) => match entry.get() {
                &Some(uid) => self.users.forward[&uid].clone(),
                &None => None,
            }
        }
    }

    fn get_group_by_gid(&mut self, gid: gid_t) -> Option<Group> {
        match self.groups.forward.entry(gid) {
            Vacant(entry) => {
                let group = super::get_group_by_gid(gid);
                match group {
                    Some(group) => {
                        entry.insert(Some(group.clone()));
                        self.groups.backward.insert(group.name.clone(), Some(group.gid));
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
        match self.groups.backward.entry(group_name.to_owned()) {
            Vacant(entry) => {
                let user = super::get_group_by_name(group_name);
                match user {
                    Some(group) => {
                        entry.insert(Some(group.gid));
                        self.groups.forward.insert(group.gid, Some(group.clone()));
                        Some(group)
                    },
                    None => {
                        entry.insert(None);
                        None
                    }
                }
            },
            Occupied(entry) => match entry.get() {
                &Some(gid) => self.groups.forward[&gid].clone(),
                &None => None,
            }
        }
    }

    fn get_current_uid(&mut self) -> uid_t {
        match self.uid {
            Some(uid) => uid,
            None => {
                let uid = super::get_current_uid();
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
                let gid = super::get_current_gid();
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
                let gid = super::get_effective_gid();
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
                let uid = super::get_effective_uid();
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
