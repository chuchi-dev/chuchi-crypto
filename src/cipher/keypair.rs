use super::{PublicKey, SharedSecret};
#[cfg(feature = "b64")]
use crate::error::DecodeError;
use crate::error::TryFromError;
use crate::utils::OsRngPanic;

use std::convert::{TryFrom, TryInto};
use std::fmt;

use x25519_dalek as x;

#[cfg(feature = "b64")]
use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};

/// A Keypair that can only be used once.
pub struct EphemeralKeypair {
	secret: x::EphemeralSecret,
	public: PublicKey,
}

impl EphemeralKeypair {
	pub fn new() -> Self {
		let secret = x::EphemeralSecret::random_from_rng(&mut OsRngPanic);
		let public = PublicKey::from_ephemeral_secret(&secret);

		Self { secret, public }
	}

	// maybe return a Key??
	pub fn diffie_hellman(self, public_key: &PublicKey) -> SharedSecret {
		let secret = self.secret.diffie_hellman(public_key.inner());
		SharedSecret::from_shared_secret(secret)
	}

	pub fn public(&self) -> &PublicKey {
		&self.public
	}
}

impl fmt::Debug for EphemeralKeypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("EphemeralKeypair")
			.field("public", &self.public)
			.finish()
	}
}

// Keypair

/// A Keypair that can be used multiple times.
#[derive(Clone)]
pub struct Keypair {
	pub secret: x::StaticSecret,
	pub public: PublicKey,
}

impl Keypair {
	pub const LEN: usize = 32;

	fn from_static_secret(secret: x::StaticSecret) -> Self {
		let public = PublicKey::from_static_secret(&secret);

		Self { secret, public }
	}

	pub fn new() -> Self {
		Self::from_static_secret(x::StaticSecret::random_from_rng(
			&mut OsRngPanic,
		))
	}

	/// ## Panics
	/// if the slice is not 32 bytes long.
	pub fn from_slice(slice: &[u8]) -> Self {
		slice.try_into().unwrap()
	}

	pub fn to_bytes(&self) -> [u8; 32] {
		self.secret.to_bytes()
	}

	pub fn as_slice(&self) -> &[u8] {
		self.secret.as_ref()
	}

	pub fn public(&self) -> &PublicKey {
		&self.public
	}

	pub fn diffie_hellman(&self, public_key: &PublicKey) -> SharedSecret {
		let secret = self.secret.diffie_hellman(public_key.inner());
		SharedSecret::from_shared_secret(secret)
	}
}

impl AsRef<[u8]> for Keypair {
	fn as_ref(&self) -> &[u8] {
		self.secret.as_bytes()
	}
}

#[cfg(not(feature = "b64"))]
impl fmt::Debug for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Keypair")
			.field("secret", &self.to_bytes())
			.field("public", &self.public)
			.finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Debug for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Keypair")
			.field("secret", &self.to_string())
			.field("public", &self.public)
			.finish()
	}
}

// Display
#[cfg(feature = "b64")]
impl fmt::Display for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		base64::display::Base64Display::new(&self.to_bytes(), &URL_SAFE_NO_PAD)
			.fmt(f)
	}
}

impl From<[u8; 32]> for Keypair {
	fn from(bytes: [u8; 32]) -> Self {
		Self::from_static_secret(x::StaticSecret::from(bytes))
	}
}

impl TryFrom<&[u8]> for Keypair {
	type Error = TryFromError;

	fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
		<[u8; 32]>::try_from(v)
			.map(Self::from)
			.map_err(TryFromError::from_any)
	}
}

#[cfg(feature = "b64")]
impl crate::FromStr for Keypair {
	type Err = DecodeError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.len() != crate::calculate_b64_len(Self::LEN) {
			return Err(DecodeError::InvalidLength);
		}

		let mut bytes = [0u8; Self::LEN];
		URL_SAFE_NO_PAD
			.decode_slice_unchecked(s, &mut bytes)
			.map(|_| Self::from(bytes))
			.map_err(DecodeError::inv_bytes)
	}
}

#[cfg(all(feature = "b64", feature = "serde"))]
mod impl_serde {
	use super::*;

	use std::borrow::Cow;
	use std::str::FromStr;

	use _serde::de::Error;
	use _serde::{Deserialize, Deserializer, Serialize, Serializer};

	impl Serialize for Keypair {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
			serializer.collect_str(&self)
		}
	}

	impl<'de> Deserialize<'de> for Keypair {
		fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where
			D: Deserializer<'de>,
		{
			let s: Cow<'_, str> = Deserialize::deserialize(deserializer)?;
			Self::from_str(s.as_ref()).map_err(D::Error::custom)
		}
	}
}

#[cfg(all(feature = "b64", feature = "postgres"))]
mod impl_postgres {
	use super::*;

	use bytes::BytesMut;
	use postgres_types::{FromSql, IsNull, ToSql, Type, to_sql_checked};

	impl ToSql for Keypair {
		fn to_sql(
			&self,
			ty: &Type,
			out: &mut BytesMut,
		) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>>
		where
			Self: Sized,
		{
			self.to_string().to_sql(ty, out)
		}

		fn accepts(ty: &Type) -> bool
		where
			Self: Sized,
		{
			<&str as ToSql>::accepts(ty)
		}

		to_sql_checked!();
	}

	impl<'r> FromSql<'r> for Keypair {
		fn from_sql(
			ty: &Type,
			raw: &'r [u8],
		) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
			let s = <&str as FromSql>::from_sql(ty, raw)?;
			s.parse().map_err(Into::into)
		}

		fn accepts(ty: &Type) -> bool {
			<&str as FromSql>::accepts(ty)
		}
	}
}
