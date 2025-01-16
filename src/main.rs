mod aes;
mod elgamal;
mod hybrid_enc;
mod keys;
mod message;
mod schnorr;
mod serializers;
mod tests;

use std::fs::File;
use std::io::Write;
use base64::decode;



use crate::keys::KeyPair;
use crate::message::Message;
use crate::schnorr::SchnorrSignature;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use serde_json::Serializer;
use serializers::deserialize_base64;
use curve25519_dalek::traits::Identity;

fn main() -> Result<(), String> {
    //since I was not sure where to load the signing keys from 
    // I am generating them for testing purposes here :

    // let keypair = KeyPair::generate();

    // // Save signing key (private key)
    // let mut signing_key_file = File::create("signing_key.txt").expect("Failed to create signing key file");
    // signing_key_file.write_all(&keypair.private_key.to_bytes()).expect("Failed to write signing key to file");

    // // Save encryption public key
    // let mut encryption_key_file = File::create("encryption_key.txt").expect("Failed to create encryption public key file");
    // encryption_key_file.write_all(keypair.public_key.compress().as_bytes()).expect("Failed to write encryption public key to file");



    // // Load the signing key from file
    // let signing_key = KeyPair::from_file("signing_key.txt")
    //     .expect("Failed to load signing key");

    // // Load the encryption public key from file
    // let encryption_key = KeyPair::pk_from_file("encryption_key.txt")
    //     .expect("Failed to load encryption public key");

    //Here I am trying to parse the keys from the description
    let public_key_base64 = "HIn1HpHqWUR1bzTRmCjdpbqTB5RUFu7eERX0yi/rcR8=";
    let signing_key_base64 = "EHeUgpnf1ymdHHcdW6e+yit5dV/dZ6UmU7uHbYCWnQ4=";
    
    let public_key_bytes = base64::decode(public_key_base64).expect("Failed to decode public key");
    if public_key_bytes.len() != 32 {
        panic!("Public key must be 32 bytes");
    }

    let encryption_key = CompressedRistretto(public_key_bytes.try_into().unwrap())
        .decompress()
        .expect("Invalid RistrettoPoint for public key");

    let signing_key_bytes = base64::decode(signing_key_base64).expect("Failed to decode signing key");
    if signing_key_bytes.len() != 32 {
        panic!("Signing key must be 32 bytes");
    }

    let signing_key = Scalar::from_canonical_bytes(signing_key_bytes.try_into().unwrap())
        .expect("Invalid Scalar for signing key");

    // Create a new message
    let mut message = Message::new(
        0,                                  // Initial version
        b"Group ID: 246".to_vec(),       // Message payload
        RistrettoPoint::default().compress(), // Placeholder sender (set during signing)
        encryption_key.compress(),          // Recipient
        SchnorrSignature::emty_signature(), // Placeholder signature
    );

    // Encrypt the message using the public key
    message
        .encrypt(&encryption_key)
        .expect("Failed to encrypt the message");

    // Sign the encrypted message using the private signing key
    message.sign(&signing_key);

    // Save the signed and encrypted message to a file
    message
        .to_file("signed_encrypted_message.json")
        .expect("Failed to save the message to a file");

    println!("Message successfully signed, encrypted, and saved!");

    Ok(())
    
}
