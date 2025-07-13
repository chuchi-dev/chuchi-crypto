//! Contains structs used for hashing.
//!
//! ## Note
//! **Do not** use this hasher for hashing password
//! or other sensitive data since this hash does not
//! use any salt, it is vulnerable to a rainbow table
//! attack.

#[cfg(feature = "b64")]
use crate::error::DecodeError;
use crate::error::TryFromError;

use std::convert::{TryFrom, TryInto};
use std::fmt;

use blake2::{Blake2b512, Digest};

#[cfg(feature = "b64")]
use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};

pub fn hash(data: impl AsRef<[u8]>) -> Hash {
	Hasher::hash(data)
}

pub struct Hasher {
	inner: Blake2b512,
}

impl Hasher {
	pub fn new() -> Self {
		Self {
			inner: Blake2b512::new(),
		}
	}

	pub fn update(&mut self, data: impl AsRef<[u8]>) {
		self.inner.update(data);
	}

	pub fn finalize(self) -> Hash {
		let arr = self.inner.finalize();
		Hash { bytes: arr.into() }
	}

	pub fn hash(data: impl AsRef<[u8]>) -> Hash {
		let mut hasher = Hasher::new();
		hasher.update(data);
		hasher.finalize()
	}
}

#[derive(Clone, PartialEq, Eq)]
pub struct Hash {
	bytes: [u8; 64],
}

impl Hash {
	pub const LEN: usize = 64;

	/// ## Panics
	/// if the slice is not 64 bytes long.
	pub fn from_slice(slice: &[u8]) -> Self {
		slice.try_into().unwrap()
	}

	pub fn to_bytes(&self) -> [u8; 64] {
		self.bytes
	}
}

#[cfg(not(feature = "b64"))]
impl fmt::Debug for Hash {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("Hash").field(&self.as_ref()).finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Debug for Hash {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("Hash").field(&self.to_string()).finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Display for Hash {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		base64::display::Base64Display::new(self.as_ref(), &URL_SAFE_NO_PAD)
			.fmt(f)
	}
}

impl From<[u8; 64]> for Hash {
	fn from(bytes: [u8; 64]) -> Self {
		Self { bytes }
	}
}

impl TryFrom<&[u8]> for Hash {
	type Error = TryFromError;

	fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
		<[u8; 64]>::try_from(v)
			.map_err(TryFromError::from_any)
			.map(Self::from)
	}
}

#[cfg(feature = "b64")]
impl crate::FromStr for Hash {
	type Err = DecodeError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.len() != crate::calculate_b64_len(Self::LEN) {
			return Err(DecodeError::InvalidLength);
		}

		let mut bytes = [0u8; Self::LEN];
		URL_SAFE_NO_PAD
			.decode_slice_unchecked(s, &mut bytes)
			.map_err(DecodeError::inv_bytes)
			.and_then(|_| {
				Self::try_from(bytes.as_ref()).map_err(DecodeError::inv_bytes)
			})
	}
}

impl AsRef<[u8]> for Hash {
	fn as_ref(&self) -> &[u8] {
		&self.bytes
	}
}

#[cfg(all(feature = "b64", feature = "serde"))]
mod impl_serde {

	use super::*;

	use std::borrow::Cow;
	use std::str::FromStr;

	use _serde::de::Error;
	use _serde::{Deserialize, Deserializer, Serialize, Serializer};

	impl Serialize for Hash {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
			serializer.collect_str(&self)
		}
	}

	impl<'de> Deserialize<'de> for Hash {
		fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where
			D: Deserializer<'de>,
		{
			let s: Cow<'_, str> = Deserialize::deserialize(deserializer)?;
			Self::from_str(s.as_ref()).map_err(D::Error::custom)
		}
	}
}

#[cfg(test)]
mod tests {

	use super::*;

	#[test]
	fn hash_something() {
		let bytes: Vec<u8> = (0..=255).collect();

		let hash = Hasher::hash(bytes);

		let hash_bytes = [
			30, 204, 137, 111, 52, 211, 249, 202, 196, 132, 199, 63, 117, 246,
			165, 251, 88, 238, 103, 132, 190, 65, 179, 95, 70, 6, 123, 156,
			101, 198, 58, 103, 148, 211, 215, 68, 17, 44, 101, 63, 115, 221,
			125, 235, 102, 102, 32, 76, 90, 155, 250, 91, 70, 8, 31, 193, 15,
			219, 231, 136, 79, 165, 203, 248,
		];
		assert_eq!(hash.to_bytes(), hash_bytes);
	}

	#[test]
	#[cfg(feature = "b64")]
	fn hash_b64() {
		let bytes: Vec<u8> = (0..=255).collect();

		let hash = Hasher::hash(bytes);

		assert_eq!(
			hash.to_string(),
			"HsyJbzTT-crEhMc_dfal-1juZ4S-QbNfRgZ7nGXGOme\
			U09dEESxlP3PdfetmZiBMWpv6W0YIH8EP2-eIT6XL-A"
		);
	}
}
