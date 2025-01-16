use base64::prelude::*;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use std::fs::File;
use std::io::Write;
use std::io::{self, Read};

/// Struct to hold public and private key pair
#[derive(Debug)]
pub struct KeyPair {
    pub private_key: Scalar,
    pub public_key: RistrettoPoint,
}

impl KeyPair {
    /// Generate a Schnorr signature key pair
    pub fn generate() -> KeyPair {
        let mut rng = OsRng; // Secure random number generator
        let private_key = Scalar::random(&mut rng); // Generate random scalar sk
        let public_key = &private_key * &RISTRETTO_BASEPOINT_POINT; // pk = g^sk

        KeyPair {
            private_key,
            public_key,
        }
    }
    pub fn write_sk_to_file(&self, filepath: &str) -> Result<(), String> {
        let mut file = File::create(filepath).map_err(|e| format!("Failed to create file: {}", e))?;
        file.write_all(self.private_key.as_bytes())
            .map_err(|e| format!("Failed to write private key to file: {}", e))?;
        Ok(())
    }

    pub fn write_pk_to_file(&self, filepath: &str) -> Result<(), String> {
        let mut file = File::create(filepath).map_err(|e| format!("Failed to create file: {}", e))?;
        file.write_all(self.public_key.compress().as_bytes())
            .map_err(|e| format!("Failed to write public key to file: {}", e))?;
        Ok(())
    }

    pub fn from_file(filepath: &str) -> Result<KeyPair, String> {
        let mut file = File::open(filepath).map_err(|e| format!("Failed to open file: {}", e))?;
        let mut buffer = [0u8; 32];
        file.read_exact(&mut buffer)
            .map_err(|e| format!("Failed to read private key: {}", e))?;
        let private_key = Scalar::from_bytes_mod_order(buffer);
        let public_key = &private_key * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        Ok(KeyPair {
            private_key,
            public_key,
        })
    }

    pub fn pk_from_file(filepath: &str) -> Result<RistrettoPoint, String> {
        let mut file = File::open(filepath).map_err(|e| format!("Failed to open file: {}", e))?;
        let mut buffer = [0u8; 32];
        file.read_exact(&mut buffer)
            .map_err(|e| format!("Failed to read public key: {}", e))?;
        let compressed_point = CompressedRistretto(buffer);
        compressed_point
            .decompress()
            .ok_or_else(|| "Failed to decompress RistrettoPoint".to_string())
    }

}

// Unit tests for keys module
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_generate_keypair() {
        let keypair = KeyPair::generate();
        assert!(
            keypair.public_key != RistrettoPoint::default(),
            "Public key should not be default"
        );
        assert!(
            keypair.private_key != Scalar::default(),
            "Private key should not be default"
        );
        assert!(
            keypair.private_key * &RISTRETTO_BASEPOINT_POINT == keypair.public_key,
            "Public key should be g^private_key"
        )
    }


    #[test]
    fn test_write_and_read_keypair() {
        let keypair = KeyPair::generate();
        let pk_filepath = "pk_test.txt";
        let sk_filepath = "sk_test.txt";

        // Write the keypair to a file
        keypair
            .write_sk_to_file(&sk_filepath)
            .expect("Failed to write sk to file");
        keypair
            .write_pk_to_file(&pk_filepath)
            .expect("Failed to write pk to file");

        // Read the keypair back from the file
        let read_keypair =
            KeyPair::from_file(&sk_filepath).expect("Failed to read keypair from file");

        let read_pk = KeyPair::pk_from_file(&pk_filepath).expect("Failed to read pk from file");

        // Check if the written and read key pairs are equal
        assert_eq!(
            keypair.private_key, read_keypair.private_key,
            "Private keys should match"
        );
        assert_eq!(
            keypair.public_key, read_keypair.public_key,
            "Public keys should match"
        );
        assert_eq!(keypair.public_key, read_pk, "Public keys should match");

        // Clean up the test file
        fs::remove_file(&sk_filepath).expect("Failed to remove sk test file");
        fs::remove_file(&pk_filepath).expect("Failed to remove pk test file");
    }
}
