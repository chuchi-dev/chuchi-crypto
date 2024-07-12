//! Contains structs used for encryption and decryption.
//!
//! ## Example
//! ```
//! use chuchi_crypto::cipher::{Keypair, Nonce};
//!
//! // Alice creates a key only she knows.
//! let alice_privkey = Keypair::new();
//! // Bob creates a key only he knows.
//! let bob_privkey = Keypair::new();
//!
//! // Alice sends it's public key to bob.
//! let alice_pubkey = alice_privkey.public();
//! // Bob sends it's public to alice.
//! let bob_pubkey = bob_privkey.public();
//!
//! // Alice creates a shared key from bob public key.
//! let alice_sharedkey = alice_privkey.diffie_hellman(&bob_pubkey);
//! // Bob creates a shared key from alice public key.
//! let bob_sharedkey = bob_privkey.diffie_hellman(&alice_pubkey);
//! assert_eq!(alice_sharedkey, bob_sharedkey);
//!
//! // To finally create a key so they can talk securely
//! // alice or bob needs to send the other a random nonce.
//! let nonce = Nonce::new();
//!
//! let mut alice_key = alice_sharedkey.to_key(nonce.clone());
//! let mut bob_key = bob_sharedkey.to_key(nonce);
//!
//! // Both have the same key and can talk securely with each other.
//!
//! let mut msg = *b"Hey Bob";
//! let mac = alice_key.encrypt(msg.as_mut());
//! assert_ne!(&msg, b"Hey Bob");
//! // The encrypted message and the mac can be sent to bob
//! // with an unsecure channel.
//! bob_key.decrypt(msg.as_mut(), &mac).expect("mac invalid");
//! assert_eq!(&msg, b"Hey Bob");
//! // Alice securely said hi to bob.
//! ```

mod key;
pub use key::{Key, SyncKey};

mod keypair;
pub use keypair::{EphemeralKeypair, Keypair};

mod mac;
pub use mac::Mac;

mod public_key;
pub use public_key::PublicKey;

mod shared_secret;
pub use shared_secret::SharedSecret;

mod nonce;
pub use nonce::Nonce;

/// Get's returned as an error if the generated mac and the received
/// MAC are not equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacNotEqual;

// TESTS

#[cfg(test)]
#[allow(deprecated)]
mod tests {

	use super::*;

	#[cfg(feature = "b64")]
	use std::str::FromStr;

	#[test]
	pub fn diffie_keypair() {
		let alice = Keypair::new();
		let bob = Keypair::new();

		let alice_ssk = alice.diffie_hellman(bob.public());
		let bob_ssk = bob.diffie_hellman(alice.public());

		assert_eq!(alice_ssk, bob_ssk);
	}

	#[test]
	pub fn diffie_ephemeral_keypair() {
		let alice = EphemeralKeypair::new();
		let bob = EphemeralKeypair::new();

		let alice_public_key = alice.public().clone();

		let alice_ssk = alice.diffie_hellman(bob.public());
		let bob_ssk = bob.diffie_hellman(&alice_public_key);

		assert_eq!(alice_ssk, bob_ssk);
	}

	#[cfg(feature = "b64")]
	#[test]
	pub fn b64() {
		let alice = Keypair::new();

		let b64 = alice.to_string();
		let alice_2 = Keypair::from_str(&b64).unwrap();

		assert_eq!(b64, alice_2.to_string());
	}

	#[test]
	pub fn to_key() {
		let alice = Keypair::new();
		let bob = Keypair::new();

		let alice_ssk = alice.diffie_hellman(bob.public());
		let bob_ssk = bob.diffie_hellman(alice.public());

		let nonce = Nonce::ones();

		let mut alice_key = alice_ssk.to_key(nonce.clone());
		let mut bob_key = bob_ssk.to_key(nonce);

		// alice sends two messages

		let msg = b"hey thats a nice message";
		let mut msg1 = msg.clone();
		let mut msg2 = msg.clone();

		let mac1 = alice_key.encrypt(&mut msg1);
		let mac2 = alice_key.encrypt(&mut msg2);

		assert_ne!(msg1, msg2);
		assert_ne!(mac1, mac2);

		assert!(bob_key.decrypt(&mut msg1, &mac1).is_ok());
		assert!(bob_key.decrypt(&mut msg2, &mac2).is_ok());

		assert_eq!(msg, &msg1);
		assert_eq!(msg, &msg2);

		// now bob sends two messages
		let mac3 = bob_key.encrypt(&mut msg1);
		let mac4 = bob_key.encrypt(&mut msg2);

		assert_ne!(msg1, msg2);
		assert_ne!(mac1, mac2);
		assert_ne!(mac1, mac3);
		assert_ne!(mac2, mac4);

		assert!(alice_key.decrypt(&mut msg1, &mac3).is_ok());
		assert!(alice_key.decrypt(&mut msg2, &mac4).is_ok());

		assert_eq!(msg, &msg1);
		assert_eq!(msg, &msg2);
	}

	#[cfg(feature = "b64")]
	#[test]
	pub fn static_encrypt_decrypt() {
		let alice =
			Keypair::from_str("4KbU6aVELDln5wCADIA53wBrldKuaoRFA4Pw0WB73XQ")
				.unwrap();
		let bob =
			Keypair::from_str("WG1CTI9LGEtUZbLFI1glU-8jIsfh3VkzrUKrmUqeqU8")
				.unwrap();

		let alice_ssk = alice.diffie_hellman(bob.public());
		let bob_ssk = bob.diffie_hellman(alice.public());

		let ssk = base64::encode(alice_ssk.as_slice());
		assert_eq!(ssk, "1+4cB2I8Gq2kgtRO4BtVJXdpyZtUIfIUEd1F63PDfmE=");

		let nonce = Nonce::ones();

		let mut alice_key = alice_ssk.to_key(nonce.clone());
		let mut bob_key = bob_ssk.to_key(nonce);

		// alice sends two messages with the same key

		let msg = b"hey thats a nice message";
		let mut msg1 = msg.clone();
		let mut msg2 = msg.clone();

		let mac1 = alice_key.encrypt(&mut msg1);
		let b64_msg1 = base64::encode(&msg1);
		assert_eq!(b64_msg1, "FOu4ZRRo6yKfAiXQU2xcOm9vDm7WmhLP");
		let b64_mac1 = base64::encode(&mac1.clone().into_bytes());
		assert_eq!(b64_mac1, "RKm3Qw36yEUK3nzYE6dPYQ==");

		let mac2 = alice_key.encrypt(&mut msg2);
		let b64_msg2 = base64::encode(&msg2);
		assert_eq!(b64_msg2, "TZl9ZfKUMlOtZxTHkAFIkl2t2l2K6YHG");
		let b64_mac2 = base64::encode(&mac2.clone().into_bytes());
		assert_eq!(b64_mac2, "EwvenIiLVd/luXHXisfRKw==");

		assert!(bob_key.decrypt(&mut msg1, &mac1).is_ok());
		assert!(bob_key.decrypt(&mut msg2, &mac2).is_ok());

		assert_eq!(msg, &msg1);
		assert_eq!(msg, &msg2);
	}
}
