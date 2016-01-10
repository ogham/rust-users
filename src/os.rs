use libc::{uid_t, gid_t};
use std::borrow::ToOwned;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;

use super::{User, Group, Users};


/// A producer of user and group instances that caches every result.
#[derive(Clone)]
pub struct OSUsers {
    users: HashMap<uid_t, Option<User>>,
    users_back: HashMap<String, Option<uid_t>>,

    groups: HashMap<gid_t, Option<Group>>,
    groups_back: HashMap<String, Option<gid_t>>,

    uid: Option<uid_t>,
    gid: Option<gid_t>,
    euid: Option<uid_t>,
    egid: Option<gid_t>,
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
            gid:         None,
            euid:        None,
            egid:        None,
        }
    }
}

impl Users for OSUsers {
    fn get_user_by_uid(&mut self, uid: uid_t) -> Option<User> {
        match self.users.entry(uid) {
            Vacant(entry) => {
                let user = super::get_user_by_uid(uid);
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
                let user = super::get_user_by_name(username);
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
        match self.groups.entry(gid) {
            Vacant(entry) => {
                let group = super::get_group_by_gid(gid);
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
        match self.groups_back.entry(group_name.to_owned()) {
            Vacant(entry) => {
                let user = super::get_group_by_name(group_name);
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
