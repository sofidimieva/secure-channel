use std::fs::File;
use std::io::{Read, Write};

#[cfg(test)]
mod tests {
    use curve25519_dalek::RistrettoPoint;

    use crate::{keys::KeyPair, message::Message, schnorr::SchnorrSignature};

    use super::*;

    #[test]
    fn test_keypair_generation_and_message_encryption_decryption() {
        // Generate keypair
        let keypair = KeyPair::generate();

        // Save signing key (private key)
        let mut signing_key_file = File::create("signing_key.txt").expect("Failed to create signing key file");
        signing_key_file.write_all(&keypair.private_key.to_bytes()).expect("Failed to write signing key to file");

        // Save encryption public key
        let mut encryption_key_file = File::create("encryption_key.txt").expect("Failed to create encryption public key file");
        encryption_key_file.write_all(keypair.public_key.compress().as_bytes()).expect("Failed to write encryption public key to file");

        // Load the signing key from file
        let signing_key = KeyPair::from_file("signing_key.txt").expect("Failed to load signing key");

        // Load the encryption public key from file
        let encryption_key = KeyPair::pk_from_file("encryption_key.txt").expect("Failed to load encryption public key");

        // Create a new message with your group ID
        let mut message = Message::new(
            1,                                  // Initial version
            b"Group ID: 172".to_vec(),       // Message payload
            RistrettoPoint::default().compress(), // Placeholder sender (set during signing)
            encryption_key.compress(),          // Recipient
            SchnorrSignature::emty_signature(), // Placeholder signature
        );

        // Encrypt the message using the public key
        message.encrypt(&encryption_key).expect("Failed to encrypt the message");

        // Sign the encrypted message using the private signing key
        message.sign(&signing_key.private_key);

        // Save the signed and encrypted message to a file
        message.to_file("signed_encrypted_message.json").expect("Failed to save the message to a file");

        // Load the signed and encrypted message from the file
        let mut file = File::open("signed_encrypted_message.json").expect("Failed to open the message file");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Failed to read the message file");
        let mut loaded_message: Message = serde_json::from_str(&contents).expect("Failed to deserialize the message");
                // Verify the signature
        assert!(loaded_message.verify(), "Failed to verify the message signature");

        // Decrypt the message
         loaded_message.decrypt(&signing_key.private_key).expect("Failed to decrypt the message");

        // Check if the decrypted message payload matches the original payload
        assert_eq!(loaded_message.payload, b"Group ID: 172".to_vec(), "Decrypted message payload does not match the original payload");
    }
}