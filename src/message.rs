use crate::hybrid_enc::HybridCiphertext;
use crate::keys::KeyPair;
use crate::schnorr::SchnorrSignature;
use crate::serializers::*;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use serde::{de, Deserialize, Serialize};
use serde_json;
use std::default;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub version: u8, // The version number of the message (1 byte)

    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub payload: Vec<u8>, // The message content (or payload) stored as a Base64-encoded string in JSON.
    #[serde(
        serialize_with = "serialize_fixed_base64",
        deserialize_with = "deserialize_fixed_base64"
    )]
    pub recipient: [u8; 32], // The recipient's identifier (stored as Vec<u8> to serialize easily)
    #[serde(
        serialize_with = "serialize_fixed_base64",
        deserialize_with = "deserialize_fixed_base64"
    )]
    pub sender: [u8; 32], // The recipient's identifier (stored as Vec<u8> to serialize easily)
    #[serde(
        serialize_with = "serialize_schnorr_signature",
        deserialize_with = "deserialize_schnorr_signature"
    )]
    pub signature: SchnorrSignature,
}

impl Message {
    pub fn new(
        version: u8,
        payload: Vec<u8>,
        sender: CompressedRistretto,
        recipient: CompressedRistretto,
        signature: SchnorrSignature,
    ) -> Self {
        Message {
            version,
            payload,
            recipient: recipient.to_bytes(),
            sender: sender.to_bytes(),
            signature,
        }
    }

    /// Writes the message to a JSON file
    pub fn to_file(&self, filepath: &str) -> std::io::Result<()> {
        let file = File::create(filepath)?;
        serde_json::to_writer_pretty(file, &self)?; // Write JSON in a human-readable format
        Ok(())
    }

    pub fn encrypt(&mut self, elgamal_public_key: &RistrettoPoint) -> Result<(), String> {

        // prit original payload
        println!("Original payload: {:?}", self.payload);
        // Step 1: Serialize the entire message using `serialize_message_to_bytes`
        let serialized_message = serialize_message_to_bytes(self)?;
    
        // Step 2: Encrypt the serialized message
        let hybrid_ciphertext = HybridCiphertext::encrypt(&serialized_message, elgamal_public_key)?;
    
        // Step 3: Update the fields of the message
        self.payload = hybrid_ciphertext.serialize(); // Replace payload with encrypted data
        self.version += 1; // Increment the version
        self.signature = SchnorrSignature::emty_signature(); // Clear signature
        self.sender = CompressedRistretto::default().to_bytes(); // Clear sender
        self.recipient = elgamal_public_key.compress().to_bytes(); // Set recipient
     
        self.display();
        Ok(())
    }
    
    pub fn decrypt(&mut self, elgamal_private_key: &Scalar) -> Result<(), String> {
        //Deserialize the hybrid ciphertext from the payload
        let hybrid_ciphertext = HybridCiphertext::deserialize(&self.payload)?;
    
        //Decrypt the ciphertext to obtain the serialized plaintext
        let plaintext = hybrid_ciphertext.decrypt(elgamal_private_key)?;
    
        //Deserialize the plaintext back into a Message using `deserialize_message_from_bytes`
        let decrypted_message = deserialize_message_from_bytes(&plaintext)?;
        
        decrypted_message.display();
        // Step 4: Update the current message's fields
        //i want to print the verison of the decrypted message
        println!("The version of the decrypted message is: {}", self.version);
        self.version = decrypted_message.version;
        self.payload = decrypted_message.payload;
        self.sender = decrypted_message.sender;
        self.recipient = decrypted_message.recipient;
        self.signature = decrypted_message.signature;
    
        Ok(())
    }
    
    
    /// signs the payload using Schnorr signatures, sets the signing public key as sender
    pub fn sign(&mut self, signing_key: &Scalar) {
        let signature = SchnorrSignature::sign(&self.payload, signing_key);
        let sender_public_key = signing_key * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        self.sender = sender_public_key.compress().to_bytes();
        self.signature = signature;
    }

    pub fn verify(&self) -> bool {
        //Extract the sender's public key (vk)
        let sender_public_key = CompressedRistretto(self.sender)
            .decompress()
            .expect("Failed to decompress sender's public key");

        //Verify the signature
        SchnorrSignature::verify(&self.signature, &self.payload, &sender_public_key)
    }

    /// Display the message for debugging purposes
    pub fn display(&self) {
        println!("Version: {}", self.version);
        println!("Payload: {:?}", self.payload);
        println!("Recipient: {:?}", self.recipient);
        println!("Sender: {:?}", self.sender);
        println!("Signature: {:?}", self.signature);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand::rngs::OsRng;
    use std::fs;

    #[test]
    fn test_message_creation() {
        // Create a sample payload and recipient
        let payload = b"Hello, this is a message!".to_vec();
        let mut csprng = OsRng;
        let recipient = RistrettoPoint::random(&mut csprng).compress();

        // Create a new message
        let version: u8 = 1;
        let message = Message::new(
            version,
            payload.clone(),
            recipient,
            recipient,
            SchnorrSignature::emty_signature(),
        );

        // Check if the fields match
        assert_eq!(message.version, version);
        assert_eq!(message.payload, payload);
        assert_eq!(message.recipient, recipient.to_bytes());

        // Display the message
        message.display();
    }

    #[test]
    fn test_message_verification_failure() {
        // Create a sample payload and recipient
        let payload = b"Hello, this is a message!".to_vec();
        let mut csprng = OsRng;
        let recipient = RistrettoPoint::random(&mut csprng).compress();
        let sender = RistrettoPoint::random(&mut csprng).compress();

        // Generate a random signing key
        let signing_key = Scalar::random(&mut csprng);

        // Create a new message
        let mut message = Message::new(
            1,
            payload.clone(),
            sender,
            recipient,
            SchnorrSignature::emty_signature(),
        );

        // Sign the message with the signing key
        message.sign(&signing_key);

        // Tamper with the payload to make the signature invalid
        message.payload[0] ^= 0xFF;

        // Verify the message, which should fail
        assert!(!message.verify(), "Verification should fail for tampered message");
    }



    #[test]
    fn test_message_encryption_and_decryption() {
        // Sample message to encrypt
        let payload = b"Hello, hybrid encryption!".to_vec();

        // Generate ElGamal keypair
        let keypair = KeyPair::generate();

        // Create a new message with version 0
        let mut message = Message::new(
            0,
            payload.clone(),
            keypair.public_key.compress(),
            keypair.public_key.compress(),
            SchnorrSignature::emty_signature(),
        );

        // Encrypt the message
        message
            .encrypt(&keypair.public_key)
            .expect("Encryption failed");

        // Ensure the message version is 1 after encryption
        assert_eq!(message.version, 1, "Version should be 1 after encryption");

        // Ensure the payload is not the same as the original (it should be encrypted)
        assert_ne!(
            message.payload, payload,
            "Encrypted payload should not match the original payload"
        );

        // Decrypt the message
        message
            .decrypt(&keypair.private_key)
            .expect("Decryption failed");

        // Ensure the message version is back to 0 after decryption
        assert_eq!(message.version, 0, "Version should be 0 after decryption");

        // Ensure the decrypted message matches the original payload
        assert_eq!(
            message.payload, payload,
            "Decrypted payload should match the original payload"
        );
    }

    #[test]
fn test_versioning_during_encryption_decryption() {
    // Sample message to encrypt
    let payload = b"Message with versioning".to_vec();

    // Generate ElGamal keypair
    let keypair = KeyPair::generate();

    // Create a new message with version 0
    let mut message = Message::new(
        0,
        payload.clone(),
        keypair.public_key.compress(),
        keypair.public_key.compress(),
        SchnorrSignature::emty_signature(),
    );

    // Ensure initial version is 0
    assert_eq!(message.version, 0, "Initial version should be 0");

    // Encrypt the message
    message
        .encrypt(&keypair.public_key)
        .expect("Encryption failed");

    // Ensure version is incremented after encryption
    assert_eq!(message.version, 1, "Version should be 1 after encryption");

    // Decrypt the message
    message
        .decrypt(&keypair.private_key)
        .expect("Decryption failed");

    // Ensure version is reset after decryption
    assert_eq!(message.version, 0, "Version should be reset to 0 after decryption");
}

#[test]
fn test_signature_verification() {
    // Sample payload
    let payload = b"Message to verify signature".to_vec();

    // Generate signing keypair
    let signing_key = Scalar::random(&mut rand::rngs::OsRng);
    let sender_public_key = signing_key * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    // Create a new message
    let mut message = Message::new(
        0,
        payload.clone(),
        sender_public_key.compress(),
        sender_public_key.compress(),
        SchnorrSignature::emty_signature(),
    );

    // Sign the message
    message.sign(&signing_key);

    // Verify the message
    assert!(
        message.verify(),
        "Message verification failed for correct payload and signature"
    );
}

#[test]
fn test_signature_verification_failure_on_tampered_signature() {
    // Sample payload
    let payload = b"Original message".to_vec();

    // Generate signing keypair
    let signing_key = Scalar::random(&mut rand::rngs::OsRng);
    let sender_public_key = signing_key * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    // Create a new message
    let mut message = Message::new(
        0,
        payload.clone(),
        sender_public_key.compress(),
        sender_public_key.compress(),
        SchnorrSignature::emty_signature(),
    );

    // Sign the message
    message.sign(&signing_key);

    // Tamper with the signature by modifying the scalar 's'
    message.signature.s += Scalar::random(&mut rand::rngs::OsRng);

    // Verify the tampered message
    assert!(
        !message.verify(),
        "Message verification should fail for tampered signature"
    );
}

}
