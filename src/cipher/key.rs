use super::{Mac, MacNotEqual};
use crate::xor;

use std::sync::atomic::{AtomicU64, Ordering};

use std::fmt;

use zeroize::Zeroize;

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{Rounds, XChaCha20, hchacha};

use poly1305::Poly1305;
use universal_hash::{KeyInit, UniversalHash};

// KEY

const BLOCK_SIZE: u64 = 64;

/// Not sure this is the right aproach or we should move to
/// maybe 12.
/// The 10 originally came from https://github.com/RustCrypto/nacl-compat/blob/20be967430389e4df9dc0c1c8920eda8681b5dca/crypto_secretstream/src/stream.rs#L50
#[derive(Debug, Clone, Copy)]
pub struct R10;

impl Rounds for R10 {
	const COUNT: usize = 10;
}

/// A Key that allows to encrypt and decrypt messages.
pub struct Key {
	shared_secret: [u8; 32],
	initial_nonce: [u8; 24],
	count: u64,
}

impl Key {
	/// Creates a new key.  
	/// And modifying the shared_secret to be a uniformly random key.
	pub(crate) fn new(
		shared_secret: [u8; 32],
		initial_nonce: [u8; 24],
	) -> Self {
		// is this really necessary See: https://github.com/RustCrypto/AEADs/pull/295
		let shared_secret =
			hchacha::<R10>(&shared_secret.into(), &Default::default()).into();

		Self {
			shared_secret,
			initial_nonce,
			count: 0,
		}
	}

	/// Encrypts bytes generating returning the generated Mac-
	pub fn encrypt(&mut self, msg: &mut [u8]) -> Mac {
		self.new_cipher().encrypt(msg)
	}

	/// Decrypts data, returning an Error if the Mac's do not
	/// match.
	pub fn decrypt(
		&mut self,
		msg: &mut [u8],
		recv_mac: &Mac,
	) -> Result<(), MacNotEqual> {
		self.new_cipher().decrypt(msg, recv_mac)
	}

	/// the cipher should only be used once
	fn new_cipher(&mut self) -> Cipher {
		self.count += 1;
		Cipher::new(&self.shared_secret, &self.initial_nonce, self.count)
	}

	pub fn into_sync(self) -> SyncKey {
		SyncKey::new(self.shared_secret, self.initial_nonce, self.count)
	}

	/// This should only be used in test.
	///
	/// Using the same key can lead to nonce reuse
	/// which makes the encryption or decryption
	/// unsecure.
	pub fn dublicate(&self) -> Self {
		Self {
			shared_secret: self.shared_secret,
			initial_nonce: self.initial_nonce,
			count: self.count,
		}
	}
}

impl fmt::Debug for Key {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("Key")
	}
}

impl Drop for Key {
	fn drop(&mut self) {
		self.shared_secret.zeroize();
		self.initial_nonce.zeroize();
	}
}

/// A Key that allows to encrypt and decrypt messages.  
/// Without having to borrow mutably.
pub struct SyncKey {
	shared_secret: [u8; 32],
	initial_nonce: [u8; 24],
	count: AtomicU64,
}

impl SyncKey {
	/// Creates a new key.  
	/// And modifying the shared_secret to be a uniformly random key.
	fn new(
		shared_secret: [u8; 32],
		initial_nonce: [u8; 24],
		count: u64,
	) -> Self {
		Self {
			shared_secret,
			initial_nonce,
			// + 1 since the values that will be used are before adding
			count: AtomicU64::new(count + 1),
		}
	}

	/// Encrypts bytes generating returning the generated Mac-
	pub fn encrypt(&self, msg: &mut [u8]) -> Mac {
		self.new_cipher().encrypt(msg)
	}

	/// Decrypts data, returning an Error if the Mac's do not
	/// match.
	pub fn decrypt(
		&self,
		msg: &mut [u8],
		recv_mac: &Mac,
	) -> Result<(), MacNotEqual> {
		self.new_cipher().decrypt(msg, recv_mac)
	}

	/// the cipher should only be used once
	fn new_cipher(&self) -> Cipher {
		Cipher::new(
			&self.shared_secret,
			&self.initial_nonce,
			// relaxed since we only need to guarantee a number get's used once.
			self.count.fetch_add(1, Ordering::Relaxed),
		)
	}
}

impl fmt::Debug for SyncKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("SyncKey")
	}
}

impl Drop for SyncKey {
	fn drop(&mut self) {
		self.shared_secret.zeroize();
		self.initial_nonce.zeroize();
	}
}

trait ToMac {
	fn to_mac(self, msg_len: usize) -> Mac;
}

impl ToMac for Poly1305 {
	fn to_mac(self, msg_len: usize) -> Mac {
		// like https://docs.rs/crate/chacha20poly1305/0.5.1/source/src/cipher.rs
		let bytes = (msg_len as u64).to_be_bytes();

		// assuming no aad needs to be set
		Mac::new(self.compute_unpadded(&bytes))
	}
}

fn xor_nonce_with_u64(nonce: &mut [u8; 24], count: u64) {
	let bytes = count.to_be_bytes();
	xor(&mut nonce[..8], &bytes);
	xor(&mut nonce[8..16], &bytes);
	xor(&mut nonce[16..], &bytes);
}

struct Cipher {
	cipher: XChaCha20,
	poly: Poly1305,
}

impl Cipher {
	fn new(
		shared_secret: &[u8; 32],
		initial_nonce: &[u8; 24],
		count: u64,
	) -> Self {
		// new chacha
		let mut iv = *initial_nonce;
		xor_nonce_with_u64(&mut iv, count);

		let mut cipher =
			<XChaCha20 as KeyIvInit>::new(shared_secret.into(), &iv.into());

		// Derive Poly1305 key from the first 32-bytes of the ChaCha20 keystream
		let mut mac_key = [0u8; 32];
		cipher.apply_keystream(&mut mac_key);

		let poly = Poly1305::new(&mac_key.into());

		mac_key.zeroize();

		// set ChaCha20 counter to 1
		cipher.seek(BLOCK_SIZE);

		Self { cipher, poly }
	}

	/// Encrypts bytes generating returning the generated Mac-
	fn encrypt(mut self, msg: &mut [u8]) -> Mac {
		self.cipher.apply_keystream(msg);
		self.poly.update_padded(msg);
		self.poly.to_mac(msg.len())
	}

	fn decrypt(
		mut self,
		msg: &mut [u8],
		recv_mac: &Mac,
	) -> Result<(), MacNotEqual> {
		self.poly.update_padded(msg);
		let mac = self.poly.to_mac(msg.len());

		// This performs a constant-time comparison using the `subtle` crate
		// via Poly1305 `Tag` Struct
		if recv_mac == &mac {
			self.cipher.apply_keystream(msg);

			Ok(())
		} else {
			Err(MacNotEqual)
		}
	}
}
