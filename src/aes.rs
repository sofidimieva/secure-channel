extern crate aes_gcm;
extern crate curve25519_dalek;
extern crate rand;

use aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit}; // Use KeyInit for the `new` method
use aes_gcm::{Aes256Gcm, Nonce}; // AES-GCM with 256-bit key
use curve25519_dalek::scalar::Scalar;
use rand::{rngs::OsRng, Rng};

const AES_KEY_SIZE: usize = 32; // AES-256 requires a 256-bit key (32 bytes)
pub const AES_NONCE_SIZE: usize = 12; // Recommended nonce size for AES-GCM is 12 bytes

/// Struct to hold the AES ciphertext and nonce
pub struct AESCiphertext {
    pub nonce: [u8; AES_NONCE_SIZE], // The nonce used for encryption
    pub ciphertext: Vec<u8>,         // The encrypted message
}

impl AESCiphertext {
    /// Display nonce and ciphertext as hex for readability
    #[allow(dead_code)]
    pub fn display(&self) {
        println!("Nonce: {:?}", self.nonce);
        println!("Ciphertext: {:?}", self.ciphertext);
    }

    /// Generates a random scalar to be used as an AES key
    pub fn keygen() -> Scalar {
        Scalar::random(&mut OsRng)
    }

    /// Converts a Scalar into a 32-byte array to be used as an AES key
    fn scalar_to_aes_key(scalar: &Scalar) -> [u8; AES_KEY_SIZE] {
        scalar.to_bytes() // Scalar provides a 32-byte output
    }

    /// Encrypts a plaintext message using AES-256-GCM with a Scalar as the AES key
    pub fn encrypt(scalar_key: &Scalar, message: &[u8]) -> Result<AESCiphertext, String> {
          // Derive a 32-byte AES key from the scalar
        let key_bytes = Self::scalar_to_aes_key(scalar_key);

        // Initialize AES-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .expect("Failed to initialize AES-GCM cipher");

        // Generate a random nonce
        let mut rng = OsRng;
        let mut nonce = [0u8; AES_NONCE_SIZE];
        rng.fill(&mut nonce);

        // Encrypt the message
        let nonce_instance = Nonce::from_slice(&nonce);
        match cipher.encrypt(nonce_instance, message) {
            Ok(ciphertext) => Ok(AESCiphertext {
                nonce,
                ciphertext,
            }),
            Err(_) => Err("Encryption failed".to_string()),
        }
    }

    /// Decrypts a ciphertext using AES-256-GCM with a Scalar as the AES key
    pub fn decrypt(scalar_key: &Scalar, aes_ciphertext: &AESCiphertext) -> Result<Vec<u8>, String> {
        // Derive a 32-byte AES key from the scalar
        let key_bytes = Self::scalar_to_aes_key(scalar_key);

        // Initialize AES-GCM cipher
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .expect("Failed to initialize AES-GCM cipher");

        // Decrypt the ciphertext
        let nonce_instance = Nonce::from_slice(&aes_ciphertext.nonce);
        match cipher.decrypt(nonce_instance, aes_ciphertext.ciphertext.as_ref()) {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => Err("Decryption failed".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_correctness() {
        let key = AESCiphertext::keygen();
        // Message to encrypt
        let message = b"Hello, AES-GCM encryption using Scalar as the key!";

        // Encrypt the message
        let aes_ciphertext = AESCiphertext::encrypt(&key, message).expect("Encryption failed");

        // Decrypt the message
        let decrypted_message =
            AESCiphertext::decrypt(&key, &aes_ciphertext).expect("Decryption failed");

        // Ensure the decrypted message matches the original message
        assert_eq!(
            decrypted_message, message,
            "Decrypted message should match the original plaintext"
        );
    }
}
