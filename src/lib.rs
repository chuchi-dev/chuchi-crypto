#![doc = include_str!("../README.md")]
#![allow(clippy::new_without_default)]

use rand::RngCore;

/// used internally when b64
#[cfg(feature = "b64")]
use std::str::FromStr;

use crate::utils::OsRngPanic;

#[cfg(feature = "cipher")]
pub mod cipher;

#[cfg(feature = "signature")]
pub mod signature;

#[cfg(feature = "hash")]
pub mod hash;

pub mod token;

pub mod error;

mod utils;

// from https://docs.rs/crate/chacha20/0.3.4/source/src/cipher.rs
/// Xors two buffers. Both buffers need to have the same length.
///
/// ## Panics
/// When the buffers don't have the same length.
pub fn xor(buf: &mut [u8], key: &[u8]) {
	assert_eq!(buf.len(), key.len());

	for (a, b) in buf.iter_mut().zip(key) {
		*a ^= *b;
	}
}

/// Fills a slice with random bytes.
///
/// ## OsRng
/// This a cryptographically secure random number generator.
/// Which uses the operating system's random number generator.
/// [See](https://docs.rs/rand/latest/rand/rngs/struct.OsRng.html)
pub fn fill_random(buf: &mut [u8]) {
	OsRngPanic.fill_bytes(buf)
}

/// Since this function multiplies s with 4
/// s needs to be 1/4 of usize::MAX in practice this should not be a problem
/// since the tokens won't be that long.
#[inline(always)]
const fn calculate_b64_len(s: usize) -> usize {
	(4 * s).div_ceil(3)
}
