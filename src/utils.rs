use rand::{CryptoRng, RngCore, TryRngCore, rngs::OsRng};

/// This is a wrapper around the `OsRng` that may panic.
pub struct OsRngPanic;

impl RngCore for OsRngPanic {
	fn next_u32(&mut self) -> u32 {
		OsRng.try_next_u32().unwrap()
	}

	fn next_u64(&mut self) -> u64 {
		OsRng.try_next_u64().unwrap()
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		OsRng.try_fill_bytes(dest).unwrap();
	}
}

impl CryptoRng for OsRngPanic {}
