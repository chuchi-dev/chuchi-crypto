use super::Signature;
#[cfg(feature = "b64")]
use crate::error::DecodeError;
use crate::error::TryFromError;

use ed25519_dalek as ed;

use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::hash::{Hash, Hasher};

#[cfg(feature = "b64")]
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};

#[derive(Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct PublicKey {
	inner: ed::VerifyingKey,
}

impl PublicKey {
	pub const LEN: usize = 32;

	pub(crate) fn from_ref(inner: &ed::VerifyingKey) -> &Self {
		// This is safe because PublicKey is transparent
		unsafe { &*(inner as *const _ as *const _) }
	}

	pub(crate) fn from_raw(inner: ed::VerifyingKey) -> Self {
		Self { inner }
	}

	/// ## Panics
	/// if the slice is not 32 bytes long.
	pub fn from_slice(slice: &[u8]) -> Self {
		slice.try_into().unwrap()
	}

	pub fn to_bytes(&self) -> [u8; 32] {
		self.inner.to_bytes()
	}

	pub fn verify(&self, msg: impl AsRef<[u8]>, signature: &Signature) -> bool {
		self.inner
			.verify_strict(msg.as_ref(), signature.inner())
			.is_ok()
	}
}

#[cfg(not(feature = "b64"))]
impl fmt::Debug for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("PublicKey").field(&self.as_ref()).finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Debug for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("PublicKey").field(&self.to_string()).finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Display for PublicKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		base64::display::Base64Display::new(self.as_ref(), &URL_SAFE_NO_PAD)
			.fmt(f)
	}
}

impl Hash for PublicKey {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.as_ref().hash(state)
	}
}

impl TryFrom<&[u8]> for PublicKey {
	type Error = TryFromError;

	fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
		ed::VerifyingKey::try_from(v)
			.map_err(TryFromError::from_any)
			.map(Self::from_raw)
	}
}

#[cfg(feature = "b64")]
impl crate::FromStr for PublicKey {
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

impl AsRef<[u8]> for PublicKey {
	fn as_ref(&self) -> &[u8] {
		self.inner.as_bytes()
	}
}

#[cfg(all(feature = "b64", feature = "serde"))]
mod impl_serde {

	use super::*;

	use std::borrow::Cow;
	use std::str::FromStr;

	use _serde::de::Error;
	use _serde::{Deserialize, Deserializer, Serialize, Serializer};

	impl Serialize for PublicKey {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
			serializer.collect_str(&self)
		}
	}

	impl<'de> Deserialize<'de> for PublicKey {
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

	impl EncodeMessage for PublicKey {
		const WIRE_TYPE: WireType = WireType::Len;

		fn is_default(&self) -> bool {
			false
		}

		fn encoded_size(
			&mut self,
			field: Option<FieldOpt>,
			builder: &mut SizeBuilder,
		) -> Result<(), EncodeError> {
			self.as_ref().encoded_size(field, builder)
		}

		fn encode<B>(
			&mut self,
			field: Option<FieldOpt>,
			encoder: &mut MessageEncoder<B>,
		) -> Result<(), EncodeError>
		where
			B: BytesWrite,
		{
			self.as_ref().encode(field, encoder)
		}
	}

	impl<'m> DecodeMessage<'m> for PublicKey {
		const WIRE_TYPE: WireType = WireType::Len;

		fn decode_default() -> Self {
			Self {
				inner: Default::default(),
			}
		}

		fn merge(
			&mut self,
			kind: FieldKind<'m>,
			is_field: bool,
		) -> Result<(), DecodeError> {
			let mut t = self.to_bytes();
			t.merge(kind, is_field)?;

			self.inner = ed::VerifyingKey::from_bytes(&t)
				.map_err(|e| DecodeError::Other(e.to_string()))?;

			Ok(())
		}
	}
}

#[cfg(all(feature = "b64", feature = "postgres"))]
mod impl_postgres {
	use super::*;

	use bytes::BytesMut;
	use postgres_types::{to_sql_checked, FromSql, IsNull, ToSql, Type};

	impl ToSql for PublicKey {
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

	impl<'r> FromSql<'r> for PublicKey {
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
