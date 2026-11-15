use std::io::{self, Write};
use std::time::Instant;

use tfhe::core_crypto::prelude::*;

const DECIMAL_SCALE: u64 = 100_000; // Five decimal places
const MAX_INPUT: f64 = 7.0;

// 2^42 gives a message space of 2^22 values in the u64 torus.
const DELTA: u64 = 1u64 << 42;
const MESSAGE_MODULUS: u64 = 1u64 << 22;

// Experimental noise parameter. This is still sampled randomly by TFHE.
const NOISE_STD_DEV: f64 = 0.0000000001;

fn read_decimal(prompt: &str) -> Option<u64> {
    print!("{prompt}");
    io::stdout().flush().expect("Could not flush prompt");

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Could not read input");

    let value: f64 = match input.trim().parse::<f64>() {
        Ok(value) if value.is_finite() => value,
        _ => {
            eprintln!("Please enter a valid number.");
            return None;
        }
    };

    if !(0.0..=MAX_INPUT).contains(&value) {
        eprintln!("Enter a value between 0 and {MAX_INPUT}.");
        return None;
    }

    let scaled = (value * DECIMAL_SCALE as f64).round();

    if scaled > (MESSAGE_MODULUS - 1) as f64 {
        eprintln!("The scaled value is outside the supported message range.");
        return None;
    }

    Some(scaled as u64)
}

fn format_fixed(value: u64) -> String {
    let whole = value / DECIMAL_SCALE;
    let fraction = value % DECIMAL_SCALE;
    format!("{whole}.{fraction:05}")
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
    println!(" TFHE-RS 1.8.1 — LWE FLOATING-POINT ADDITION");
    println!("==============================================");
    println!("Five decimal places; experimental toy parameters.");
    println!("Enter values from 0.00000 to 7.00000.\n");

    let first = match read_decimal("Enter first number (0 to 7): ") {
        Some(value) => value,
        None => return,
    };

    let second = match read_decimal("Enter second number (0 to 7): ") {
        Some(value) => value,
        None => return,
    };

    let expected_sum = first + second;

    println!("\n[Input values]");
    println!("First input:  {}", format_fixed(first));
    println!("Second input: {}", format_fixed(second));
    println!("Expected sum: {}", format_fixed(expected_sum));

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
    println!("Secret key generated.");

    // Print secret-key coefficients for this educational demonstration.
    // Never print or expose secret keys in a real application.
    println!("Secret key coefficients:");
    for (i, coefficient) in secret_key.as_ref().iter().enumerate() {
        println!("  s[{i}] = {coefficient}");
    }

    // Fixed-point encoding: decimal value × 100,000 × DELTA.
    let plaintext_a = Plaintext(first * DELTA);
    let plaintext_b = Plaintext(second * DELTA);

    println!("\n[2] Encode floating-point messages");
    println!("Decimal scale: {DECIMAL_SCALE} (5 decimal places)");
    println!("Delta: 2^42 = {DELTA}");
    println!("Message modulus: 2^22 = {MESSAGE_MODULUS}");
    println!("First scaled integer: {first}");
    println!("Encoded first message: 0x{:016X}", plaintext_a.0);
    println!("Second scaled integer: {second}");
    println!("Encoded second message: 0x{:016X}", plaintext_b.0);
    println!("Encoding formula: round(value × 100,000) × DELTA");

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

    // Decode the nearest fixed-point message level.
    let rounded_torus = decrypted.0.wrapping_add(DELTA / 2);
    let recovered_scaled = (rounded_torus / DELTA) % MESSAGE_MODULUS;

    println!("Rounded torus quotient: {recovered_scaled}");
    println!("Recovered sum: {}", format_fixed(recovered_scaled));
    println!("Expected sum:  {}", format_fixed(expected_sum));

    if recovered_scaled == expected_sum {
        println!("\nSUCCESS: Homomorphic floating-point addition verified.");
    } else {
        println!("\nWARNING: Result did not match the expected sum.");
        println!("Check the noise parameter and encoding configuration.");
    }

    println!("\n==============================================");
    println!(" LWE FLOATING-POINT ADDITION COMPLETED");
    println!("==============================================");
    println!("The ciphertexts were added before decryption.");
    println!("Encryption noise was sampled randomly.");
    println!("These toy parameters are not production-secure.");
}
