//! Causal version-vector primitives for vault synchronization.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use syncthing_core::DeviceId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionOrdering {
    Equal,
    Dominates,
    DominatedBy,
    Concurrent,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VersionVectorError {
    #[error("version counter overflow for device {0}")]
    CounterOverflow(DeviceId),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionVector {
    counters: HashMap<DeviceId, u64>,
}

impl VersionVector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, device_id: &DeviceId) -> u64 {
        self.counters.get(device_id).copied().unwrap_or(0)
    }

    pub fn increment(&mut self, device_id: DeviceId) -> Result<u64, VersionVectorError> {
        let next = self
            .get(&device_id)
            .checked_add(1)
            .ok_or(VersionVectorError::CounterOverflow(device_id))?;
        self.counters.insert(device_id, next);
        Ok(next)
    }

    pub fn observe(&mut self, device_id: DeviceId, counter: u64) {
        if counter > self.get(&device_id) {
            self.counters.insert(device_id, counter);
        }
    }

    pub fn merge(&mut self, other: &Self) {
        for (device_id, counter) in &other.counters {
            let current = self.get(device_id);
            if *counter > current {
                self.counters.insert(*device_id, *counter);
            }
        }
    }

    pub fn dominates(&self, other: &Self) -> bool {
        self.compare(other) == VersionOrdering::Dominates
            || self.compare(other) == VersionOrdering::Equal
    }

    pub fn is_concurrent(&self, other: &Self) -> bool {
        self.compare(other) == VersionOrdering::Concurrent
    }

    pub fn compare(&self, other: &Self) -> VersionOrdering {
        let self_greater = self.has_greater_counter(other);
        let other_greater = other.has_greater_counter(self);
        match (self_greater, other_greater) {
            (false, false) => VersionOrdering::Equal,
            (true, false) => VersionOrdering::Dominates,
            (false, true) => VersionOrdering::DominatedBy,
            (true, true) => VersionOrdering::Concurrent,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&DeviceId, &u64)> {
        self.counters.iter()
    }

    fn has_greater_counter(&self, other: &Self) -> bool {
        self.counters
            .iter()
            .any(|(device_id, counter)| *counter > other.get(device_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_equal_vectors() {
        let device = DeviceId::random();
        let mut left = VersionVector::new();
        let mut right = VersionVector::new();
        left.increment(device).unwrap();
        right.increment(device).unwrap();

        assert_eq!(left.compare(&right), VersionOrdering::Equal);
        assert!(left.dominates(&right));
        assert!(!left.is_concurrent(&right));
    }

    #[test]
    fn detects_ancestor_and_descendant() {
        let device = DeviceId::random();
        let mut ancestor = VersionVector::new();
        ancestor.increment(device).unwrap();
        let mut descendant = ancestor.clone();
        descendant.increment(device).unwrap();

        assert_eq!(descendant.compare(&ancestor), VersionOrdering::Dominates);
        assert!(descendant.dominates(&ancestor));
        assert_eq!(ancestor.compare(&descendant), VersionOrdering::DominatedBy);
    }

    #[test]
    fn detects_concurrent_vectors() {
        let left_device = DeviceId::random();
        let right_device = DeviceId::random();
        let mut left = VersionVector::new();
        let mut right = VersionVector::new();
        left.increment(left_device).unwrap();
        right.increment(right_device).unwrap();

        assert_eq!(left.compare(&right), VersionOrdering::Concurrent);
        assert!(left.is_concurrent(&right));
    }

    #[test]
    fn merge_keeps_maximum_counter_for_missing_devices() {
        let left_device = DeviceId::random();
        let right_device = DeviceId::random();
        let mut left = VersionVector::new();
        let mut right = VersionVector::new();
        left.increment(left_device).unwrap();
        right.increment(right_device).unwrap();
        right.increment(right_device).unwrap();

        left.merge(&right);
        assert_eq!(left.get(&left_device), 1);
        assert_eq!(left.get(&right_device), 2);
        assert!(left.dominates(&right));
    }
}
