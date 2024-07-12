use super::{PublicKey, Signature};
#[cfg(feature = "b64")]
use crate::error::DecodeError;
use crate::error::TryFromError;

use std::convert::{TryFrom, TryInto};
use std::fmt;

use rand::rngs::OsRng;

use ed::Signer;
use ed25519_dalek as ed;

#[cfg(feature = "b64")]
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};

pub struct Keypair {
	secret: ed::SigningKey,
}

impl Keypair {
	pub const LEN: usize = 32;

	pub fn new() -> Self {
		Self::from_keypair(ed::SigningKey::generate(&mut OsRng))
	}

	pub(crate) fn from_keypair(keypair: ed::SigningKey) -> Self {
		Self { secret: keypair }
	}

	pub(crate) fn from_secret(secret: ed::SecretKey) -> Self {
		Self::from_keypair(ed::SigningKey::from_bytes(&secret))
	}

	/// ## Panics
	/// if the slice is not valid.
	pub fn from_slice(slice: &[u8]) -> Self {
		slice.try_into().unwrap()
	}

	pub fn to_bytes(&self) -> [u8; 32] {
		self.secret.to_bytes()
	}

	pub fn public(&self) -> &PublicKey {
		PublicKey::from_ref(self.secret.as_ref())
	}

	pub fn sign(&self, msg: impl AsRef<[u8]>) -> Signature {
		let sign = self.secret.sign(msg.as_ref());
		Signature::from_sign(sign)
	}

	pub fn verify(&self, msg: impl AsRef<[u8]>, signature: &Signature) -> bool {
		self.public().verify(msg, signature)
	}
}

#[cfg(not(feature = "b64"))]
impl fmt::Debug for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Keypair")
			.field("secret", &self.to_bytes())
			.field("public", self.public())
			.finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Debug for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Keypair")
			.field("secret", &self.to_string())
			.field("public", self.public())
			.finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Display for Keypair {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		base64::display::Base64Display::new(&self.to_bytes(), &URL_SAFE_NO_PAD)
			.fmt(f)
	}
}

impl TryFrom<&[u8]> for Keypair {
	type Error = TryFromError;

	fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
		ed::SecretKey::try_from(v)
			.map_err(TryFromError::from_any)
			.map(Self::from_secret)
	}
}

impl From<[u8; 32]> for Keypair {
	fn from(bytes: [u8; 32]) -> Self {
		Self::from_secret(bytes)
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
			.map_err(DecodeError::inv_bytes)
			.and_then(|_| {
				Self::try_from(bytes.as_ref()).map_err(DecodeError::inv_bytes)
			})
	}
}

// todo add again
// impl AsRef<[u8]> for Keypair {
// 	fn as_ref(&self) -> &[u8] {
// 		self.secret.as_bytes()
// 	}
// }

impl Clone for Keypair {
	fn clone(&self) -> Self {
		self.to_bytes().into()
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

#[cfg(feature = "protobuf")]
mod impl_protobuf {
	use super::*;

	use protopuffer::{
		bytes::BytesWrite,
		decode::{DecodeError, DecodeMessage, FieldKind},
		encode::{
			EncodeError, EncodeMessage, FieldOpt, MessageEncoder, SizeBuilder,
		},
		WireType,
	};

	impl EncodeMessage for Keypair {
		const WIRE_TYPE: WireType = WireType::Len;

		fn is_default(&self) -> bool {
			false
		}

		fn encoded_size(
			&mut self,
			field: Option<FieldOpt>,
			builder: &mut SizeBuilder,
		) -> Result<(), EncodeError> {
			self.to_bytes().encoded_size(field, builder)
		}

		fn encode<B>(
			&mut self,
			field: Option<FieldOpt>,
			encoder: &mut MessageEncoder<B>,
		) -> Result<(), EncodeError>
		where
			B: BytesWrite,
		{
			self.to_bytes().encode(field, encoder)
		}
	}

	impl<'m> DecodeMessage<'m> for Keypair {
		const WIRE_TYPE: WireType = WireType::Len;

		fn decode_default() -> Self {
			Self::from([0u8; 32])
		}

		fn merge(
			&mut self,
			kind: FieldKind<'m>,
			is_field: bool,
		) -> Result<(), DecodeError> {
			let mut t = self.to_bytes();
			t.merge(kind, is_field)?;

			*self = Self::from(t);

			Ok(())
		}
	}
}

#[cfg(all(feature = "b64", feature = "postgres"))]
mod impl_postgres {
	use super::*;

	use bytes::BytesMut;
	use postgres_types::{to_sql_checked, FromSql, IsNull, ToSql, Type};

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
