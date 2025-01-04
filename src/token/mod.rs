#[cfg(feature = "b64")]
use crate::error::DecodeError;
use crate::error::TryFromError;

use std::convert::{TryFrom, TryInto};
use std::fmt;

use rand::rngs::OsRng;
use rand::RngCore;

#[cfg(feature = "b64")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "b64")]
use base64::Engine;

/// A random Token
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Token<const S: usize> {
	bytes: [u8; S],
}

impl<const S: usize> Token<S> {
	pub const LEN: usize = S;

	pub const STR_LEN: usize = crate::calculate_b64_len(S);

	/// Creates a new random Token
	pub fn new() -> Self {
		let mut bytes = [0u8; S];

		OsRng.fill_bytes(&mut bytes);

		Self { bytes }
	}

	/// ## Panics
	/// if the slice is not `S` bytes long.
	pub fn from_slice(slice: &[u8]) -> Self {
		slice.try_into().unwrap()
	}

	pub fn to_bytes(&self) -> [u8; S] {
		self.bytes
	}
}

#[cfg(not(feature = "b64"))]
impl<const S: usize> fmt::Debug for Token<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("Token").field(&self.as_ref()).finish()
	}
}

#[cfg(feature = "b64")]
impl<const S: usize> fmt::Debug for Token<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("Token").field(&self.to_string()).finish()
	}
}

#[cfg(feature = "b64")]
impl<const S: usize> fmt::Display for Token<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		base64::display::Base64Display::new(self.as_ref(), &URL_SAFE_NO_PAD)
			.fmt(f)
	}
}

impl<const S: usize> From<[u8; S]> for Token<S> {
	fn from(bytes: [u8; S]) -> Self {
		Self { bytes }
	}
}

impl<const S: usize> TryFrom<&[u8]> for Token<S> {
	type Error = TryFromError;

	fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
		<[u8; S]>::try_from(v)
			.map_err(TryFromError::from_any)
			.map(Self::from)
	}
}

#[cfg(feature = "b64")]
impl<const S: usize> crate::FromStr for Token<S> {
	type Err = DecodeError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.len() != crate::calculate_b64_len(S) {
			return Err(DecodeError::InvalidLength);
		}

		let mut bytes = [0u8; S];
		URL_SAFE_NO_PAD
			.decode_slice_unchecked(s, &mut bytes)
			.map_err(DecodeError::inv_bytes)
			.map(|_| Self::from(bytes))
	}
}

impl<const S: usize> AsRef<[u8]> for Token<S> {
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

	impl<const SI: usize> Serialize for Token<SI> {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
			serializer.collect_str(&self)
		}
	}

	impl<'de, const S: usize> Deserialize<'de> for Token<S> {
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
mod protobuf {
	use super::*;

	use protopuffer::{
		bytes::BytesWrite,
		decode::{DecodeError, DecodeMessage, FieldKind},
		encode::{
			EncodeError, EncodeMessage, FieldOpt, MessageEncoder, SizeBuilder,
		},
		WireType,
	};

	impl<const SI: usize> EncodeMessage for Token<SI> {
		const WIRE_TYPE: WireType = WireType::Len;

		fn is_default(&self) -> bool {
			false
		}

		fn encoded_size(
			&mut self,
			field: Option<FieldOpt>,
			builder: &mut SizeBuilder,
		) -> Result<(), EncodeError> {
			self.bytes.encoded_size(field, builder)
		}

		fn encode<B>(
			&mut self,
			field: Option<FieldOpt>,
			encoder: &mut MessageEncoder<B>,
		) -> Result<(), EncodeError>
		where
			B: BytesWrite,
		{
			self.bytes.encode(field, encoder)
		}
	}

	impl<'m, const SI: usize> DecodeMessage<'m> for Token<SI> {
		const WIRE_TYPE: WireType = WireType::Len;

		fn decode_default() -> Self {
			[0; SI].into()
		}

		fn merge(
			&mut self,
			kind: FieldKind<'m>,
			is_field: bool,
		) -> Result<(), DecodeError> {
			self.bytes.merge(kind, is_field)
		}
	}
}

#[cfg(all(feature = "b64", feature = "postgres"))]
mod impl_postgres {
	use super::*;

	use bytes::BytesMut;
	use postgres_types::{to_sql_checked, FromSql, IsNull, ToSql, Type};

	impl<const SI: usize> ToSql for Token<SI> {
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

	impl<'r, const SI: usize> FromSql<'r> for Token<SI> {
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

#[cfg(all(test, feature = "b64"))]
mod tests {

	use super::*;

	use std::str::FromStr;

	pub fn b64<const S: usize>() {
		let tok = Token::<S>::new();

		let b64 = tok.to_string();
		let tok_2 = Token::<S>::from_str(&b64).unwrap();

		assert_eq!(b64, tok_2.to_string());
	}

	#[test]
	pub fn test_b64() {
		b64::<1>();
		b64::<2>();
		b64::<3>();
		b64::<13>();
		b64::<24>();
		b64::<200>();
		b64::<213>();
	}
}
