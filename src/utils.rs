use std::convert::Infallible;

use rand::{TryCryptoRng, TryRng, rngs::SysRng};

/// This is a wrapper around the `OsRng` that may panic.
pub struct SysRngPanic;

impl TryRng for SysRngPanic {
	type Error = Infallible;

	fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
		Ok(SysRng.try_next_u32().unwrap())
	}

	fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
		Ok(SysRng.try_next_u64().unwrap())
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
		Ok(SysRng.try_fill_bytes(dest).unwrap())
	}
}

impl TryCryptoRng for SysRngPanic {}
