//! Support structs for managing a group's state.

use crate::proto::{DecryptedGroup, DecryptedGroupChange};

pub struct GroupState {}

#[derive(thiserror::Error, Debug)]
pub enum GroupStateTransitionError {}

impl GroupState {
    pub fn new_from_state(_group: DecryptedGroup) -> Self {
        GroupState {}
    }

    pub fn decrypt_and_apply(
        &mut self,
        _change: Vec<u8>,
    ) -> Result<(), GroupStateTransitionError> {
        Ok(())
    }

    pub fn apply(
        &mut self,
        _change: DecryptedGroupChange,
    ) -> Result<(), GroupStateTransitionError> {
        Ok(())
    }
}
