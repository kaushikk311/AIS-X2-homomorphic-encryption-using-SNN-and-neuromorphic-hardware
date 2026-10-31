use std::io::{self, Write};
use std::time::Instant;

use tfhe::core_crypto::prelude::*;

fn main() {
    println!("==============================================");
    println!(" TFHE-RS 1.8.1 - LOW-LEVEL LWE INSPECTOR");
    println!("==============================================");
    println!("Educational demonstration only.");
    println!("The parameters used here are NOT secure.\n");

    print!("Enter an integer from 0 to 15: ");
    io::stdout().flush().expect("Could not flush prompt");

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Could not read input");

    let message: u64 = match input.trim().parse() {
        Ok(value) if value <= 15 => value,
        _ => {
            eprintln!("Enter a whole number from 0 to 15.");
            return;
        }
    };

    let lwe_dimension = LweDimension(16);
    let ciphertext_modulus = CiphertextModulus::new_native();

    println!("\n[1] Generating random generators");

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();

    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            seeder.seed(),
            seeder,
        );

    let mut secret_generator =
        SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    println!("\n[2] Generating the LWE secret key");

    let start = Instant::now();

    let secret_key =
        allocate_and_generate_new_binary_lwe_secret_key(
            lwe_dimension,
            &mut secret_generator,
        );

    println!("Key generation time: {:?}", start.elapsed());
    println!("LWE dimension: {}", lwe_dimension.0);
    println!("Secret-key coefficients (educational demo only):");

    for (i, coefficient) in secret_key.as_ref().iter().enumerate() {
        println!("s[{i}] = {coefficient}");
    }

    let encoded_plaintext = Plaintext(message << 60);

    println!("\n[3] Encoding the plaintext");
    println!("Original message: {message}");
    println!("Encoding rule: message << 60");
    println!(
        "Encoded plaintext: 0x{:016X}",
        encoded_plaintext.0
    );

    let noise_distribution =
        Gaussian::from_dispersion_parameter(
            StandardDev(0.000007069849454709433),
            0.0,
        );

    println!("\n[4] Encrypting with the TFHE-RS LWE primitive");

    let mut ciphertext = LweCiphertext::new(
        0u64,
        lwe_dimension.to_lwe_size(),
        ciphertext_modulus,
    );

    let start = Instant::now();

    encrypt_lwe_ciphertext(
        &secret_key,
        &mut ciphertext,
        encoded_plaintext,
        noise_distribution,
        &mut encryption_generator,
    );

    println!("Encryption time: {:?}", start.elapsed());

    println!("\n[5] Actual ciphertext values");

    println!("Mask coefficients:");

    for (i, coefficient) in ciphertext.get_mask().as_ref().iter().enumerate() {
        println!(
            "a[{i}] = {coefficient} (hex: 0x{coefficient:016X})"
        );
    }

    let body = *ciphertext.get_body().data;

    println!("Ciphertext body: {body}");
    println!("Ciphertext body (hex): 0x{body:016X}");

    println!("\n[6] Noise-related calculation");

    let mask_secret_dot = ciphertext
        .get_mask()
        .as_ref()
        .iter()
        .zip(secret_key.as_ref().iter())
        .fold(0u64, |acc, (&a, &s)| {
            acc.wrapping_add(a.wrapping_mul(s))
        });

    let residual = body
        .wrapping_sub(mask_secret_dot)
        .wrapping_sub(encoded_plaintext.0);

    println!(
        "Dot product <a,s> modulo 2^64: 0x{mask_secret_dot:016X}"
    );

    println!(
        "Residual b - <a,s> - encoded message: 0x{residual:016X}"
    );

    println!(
        "This residual represents the encryption error modulo 2^64."
    );

    println!("\n[7] Decrypting");

    let start = Instant::now();

    let decrypted_plaintext =
        decrypt_lwe_ciphertext(&secret_key, &ciphertext);

    println!("Decryption time: {:?}", start.elapsed());

    println!(
        "Decrypted torus value: 0x{:016X}",
        decrypted_plaintext.0
    );

    let decomposer = SignedDecomposer::new(
        DecompositionBaseLog(4),
        DecompositionLevelCount(1),
    );

    let rounded =
        decomposer.closest_representable(decrypted_plaintext.0);

    let recovered_message = rounded >> 60;

    println!(
        "Rounded encoded value: 0x{rounded:016X}"
    );

    println!("Recovered message: {recovered_message}");
    println!("Original message: {message}");

    if recovered_message == message {
        println!("\nSUCCESS: The original message was recovered.");
    } else {
        println!("\nWARNING: The recovered value differs from the input.");
    }

    println!("\n==============================================");
    println!("End of LWE inspection.");
    println!("Never expose secret keys in a real application.");
}