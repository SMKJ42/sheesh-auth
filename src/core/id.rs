use std::{fmt::Debug, ops::Shl};

use scrypt::password_hash::rand_core::{OsRng, RngCore};

pub trait IdGenerator: Debug {
    fn new_u64(&self) -> u64;
    fn new_u128(&self) -> u128;
}

#[derive(Clone, Copy, Debug)]
pub struct DefaultIdGenerator {}

impl IdGenerator for DefaultIdGenerator {
    fn new_u128(&self) -> u128 {
        let sm = OsRng.next_u64() as u128;
        let lg: u128 = sm.shl(64);
        return lg + (OsRng.next_u64() as u128);
    }
    fn new_u64(&self) -> u64 {
        OsRng.next_u64()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ZerodIdGenerator {}

impl IdGenerator for ZerodIdGenerator {
    fn new_u128(&self) -> u128 {
        return 0;
    }
    fn new_u64(&self) -> u64 {
        return 0;
    }
}
