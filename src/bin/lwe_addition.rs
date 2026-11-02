use std::io::{self, Write};
use std::time::Instant;

use tfhe::core_crypto::prelude::*;

const DELTA: u64 = 1u64 << 59;
const MESSAGE_MODULUS: u64 = 8;
const NOISE_STD_DEV: f64 = 0.000007069849454709433;

fn read_integer(prompt: &str) -> Option<u64> {
    print!("{prompt}");
    io::stdout().flush().expect("Could not flush prompt");

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Could not read input");

    match input.trim().parse::<u64>() {
        Ok(value) if value < MESSAGE_MODULUS => Some(value),
        _ => {
            eprintln!("Enter a whole number from 0 to 7.");
            None
        }
    }
}

fn print_ciphertext(label: &str, ciphertext: &LweCiphertextOwned<u64>) {
    println!("\n{label}");
    println!("Mask coefficients:");

    for (i, coefficient) in ciphertext.get_mask().as_ref().iter().enumerate() {
        println!("  a[{i}] = {coefficient} (0x{coefficient:016X})");
    }

    let body = *ciphertext.get_body().data;
    println!("Body b = {body} (0x{body:016X})");
}

fn main() {
    println!("==============================================");
    println!(" TFHE-RS 1.8.1 — LWE HOMOMORPHIC ADDITION");
    println!("==============================================");
    println!("Educational toy parameters only.\n");

    let first = match read_integer("Enter first integer (0 to 7): ") {
        Some(value) => value,
        None => return,
    };

    let second = match read_integer("Enter second integer (0 to 7): ") {
        Some(value) => value,
        None => return,
    };

    let expected_sum = (first + second) % MESSAGE_MODULUS;

    // LWE parameters
    let dimension = LweDimension(16);
    let modulus = CiphertextModulus::new_native();

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();

    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            seeder.seed(),
            seeder,
        );

    let mut secret_generator =
        SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    println!("\n[1] Generate LWE secret key");
    let started = Instant::now();

    let secret_key =
        allocate_and_generate_new_binary_lwe_secret_key(
            dimension,
            &mut secret_generator,
        );

    println!("Key generation time: {:?}", started.elapsed());
    println!("LWE dimension: {}", dimension.0);
    println!("Secret key generated (not printed).");

    // Plaintext encoding: message * 2^59
    let plaintext_a = Plaintext(first * DELTA);
    let plaintext_b = Plaintext(second * DELTA);

    println!("\n[2] Encode messages");
    println!("First message: {first}");
    println!("Encoded first message: 0x{:016X}", plaintext_a.0);
    println!("Second message: {second}");
    println!("Encoded second message: 0x{:016X}", plaintext_b.0);
    println!("Encoding formula: message × 2^59");

    let noise_distribution =
        Gaussian::from_dispersion_parameter(
            StandardDev(NOISE_STD_DEV),
            0.0,
        );

    let mut ciphertext_a = LweCiphertext::new(
        0u64,
        dimension.to_lwe_size(),
        modulus,
    );

    let mut ciphertext_b = LweCiphertext::new(
        0u64,
        dimension.to_lwe_size(),
        modulus,
    );

    println!("\n[3] Encrypt both messages");

    let started = Instant::now();
    encrypt_lwe_ciphertext(
        &secret_key,
        &mut ciphertext_a,
        plaintext_a,
        noise_distribution,
        &mut encryption_generator,
    );
    println!("Encryption A time: {:?}", started.elapsed());

    let started = Instant::now();
    encrypt_lwe_ciphertext(
        &secret_key,
        &mut ciphertext_b,
        plaintext_b,
        noise_distribution,
        &mut encryption_generator,
    );
    println!("Encryption B time: {:?}", started.elapsed());

    print_ciphertext("Ciphertext A (actual values)", &ciphertext_a);
    print_ciphertext("Ciphertext B (actual values)", &ciphertext_b);

    println!("\n[4] Add ciphertexts without decrypting");
    println!("Operation: ciphertext_a += ciphertext_b");
    println!("The masks and bodies are added modulo 2^64.");

    let started = Instant::now();
    lwe_ciphertext_add_assign(&mut ciphertext_a, &ciphertext_b);
    println!("Ciphertext addition time: {:?}", started.elapsed());

    print_ciphertext("Result ciphertext (actual values)", &ciphertext_a);

    println!("\n[5] Decrypt the result");
    let started = Instant::now();
    let decrypted = decrypt_lwe_ciphertext(&secret_key, &ciphertext_a);
    println!("Decryption time: {:?}", started.elapsed());
    println!("Decrypted torus value: 0x{:016X}", decrypted.0);

    let rounded_torus = decrypted.0.wrapping_add(DELTA / 2);
    let recovered_sum = (rounded_torus / DELTA) % MESSAGE_MODULUS;

    println!("Rounded torus value: 0x{:016X}", (recovered_sum * DELTA));
    println!("Recovered sum: {recovered_sum}");
    println!("Expected sum: {expected_sum}");

    if recovered_sum == expected_sum {
        println!("\nSUCCESS: Homomorphic addition verified.");
    } else {
        println!("\nWARNING: Result did not match the expected sum.");
    }

    println!("\nReminder: toy parameters are not suitable for real secrets.");
}
