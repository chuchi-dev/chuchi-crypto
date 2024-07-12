#[cfg(feature = "b64")]
use crate::error::DecodeError;
use crate::error::TryFromError;

use std::convert::{TryFrom, TryInto};
use std::fmt;

use ed25519_dalek as ed;

#[cfg(feature = "b64")]
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};

#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
	inner: ed::Signature,
}

impl Signature {
	pub const LEN: usize = 64;

	pub(crate) fn from_sign(inner: ed::Signature) -> Self {
		Self { inner }
	}

	/// ## Panics
	/// if the slice is not 64 bytes long.
	pub fn from_slice(slice: &[u8]) -> Self {
		slice.try_into().unwrap()
	}

	pub fn to_bytes(&self) -> [u8; 64] {
		self.inner.to_bytes()
	}

	pub(crate) fn inner(&self) -> &ed::Signature {
		&self.inner
	}
}

#[cfg(not(feature = "b64"))]
impl fmt::Debug for Signature {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("Signature").field(&self.to_bytes()).finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Debug for Signature {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("Signature").field(&self.to_string()).finish()
	}
}

#[cfg(feature = "b64")]
impl fmt::Display for Signature {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		base64::display::Base64Display::new(&self.to_bytes(), &URL_SAFE_NO_PAD)
			.fmt(f)
	}
}

impl TryFrom<&[u8]> for Signature {
	type Error = TryFromError;

	fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
		ed::Signature::try_from(v)
			.map_err(TryFromError::from_any)
			.map(Self::from_sign)
	}
}

#[cfg(feature = "b64")]
impl crate::FromStr for Signature {
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

#[cfg(all(feature = "b64", feature = "serde"))]
mod impl_serde {

	use super::*;

	use std::borrow::Cow;
	use std::str::FromStr;

	use _serde::de::Error;
	use _serde::{Deserialize, Deserializer, Serialize, Serializer};

	impl Serialize for Signature {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
			serializer.collect_str(&self)
		}
	}

	impl<'de> Deserialize<'de> for Signature {
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

	impl EncodeMessage for Signature {
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

	impl<'m> DecodeMessage<'m> for Signature {
		const WIRE_TYPE: WireType = WireType::Len;

		fn decode_default() -> Self {
			Self::from_slice(&[0u8; 32])
		}

		fn merge(
			&mut self,
			kind: FieldKind<'m>,
			is_field: bool,
		) -> Result<(), DecodeError> {
			let mut t = self.to_bytes();
			t.merge(kind, is_field)?;

			*self = Self::try_from(t.as_slice())
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

	impl ToSql for Signature {
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

	impl<'r> FromSql<'r> for Signature {
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
