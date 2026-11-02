use std::io::{self, Write};
use std::time::Instant;

use tfhe::core_crypto::prelude::*;

const NOISE_STD_DEV: f64 = 0.000007069849454709433;
const LWE_DIMENSION: usize = 16;
const VALUE_RANGE: f64 = 100.0;
const DECIMAL_SCALE: f64 = 100_000.0;
const TORUS_MODULUS: f64 = 18_446_744_073_709_551_616.0;

fn encode_real(value: f64) -> u64 {
    let normalized = (value + VALUE_RANGE) / (2.0 * VALUE_RANGE);
    (normalized * TORUS_MODULUS) as u64
}

fn decode_real(torus_value: u64) -> f64 {
    let normalized = torus_value as f64 / TORUS_MODULUS;
    normalized * (2.0 * VALUE_RANGE) - VALUE_RANGE
}

fn round_to_five_decimals(value: f64) -> f64 {
    (value * DECIMAL_SCALE).round() / DECIMAL_SCALE
}

fn main() {
    println!("==============================================");
    println!(" TFHE-RS 1.8.1 - NOISE-DEPENDENT LWE DEMO (NO ROUNDING)");
    println!("==============================================");
    println!("Educational demonstration only.");
    println!("This is a custom approximate real-value encoding.");
    println!("It is not TFHE's standard integer decoder.");
    println!("Supported input range: -100 to +100");
    println!("Decimal precision: 5 places");

    print!("\nEnter a real number: ");
    io::stdout().flush().expect("Flush failed");

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Input failed");

    let original_value: f64 = match input.trim().parse::<f64>() {
        Ok(value) if value.is_finite() => value,
        _ => {
            println!("Invalid decimal input.");
            return;
        }
    };

    if !(-VALUE_RANGE..=VALUE_RANGE).contains(&original_value) {
        println!("Input must be between -100 and +100.");
        return;
    }

    let original_value = round_to_five_decimals(original_value);

    println!("\nOriginal input: {:.5}", original_value);

    // [1] Random generator initialization
    println!("\n[1] Initializing random generators");

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();

    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            seeder.seed(),
            seeder,
        );

    let mut secret_generator =
        SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    // [2] Secret key generation
    println!("\n[2] Generating LWE secret key");

    let start = Instant::now();

    let secret_key =
        allocate_and_generate_new_binary_lwe_secret_key(
            LweDimension(LWE_DIMENSION),
            &mut secret_generator,
        );

    println!("Key generation time: {:?}", start.elapsed());
    println!("LWE dimension: {}", LWE_DIMENSION);
    println!("Secret key coefficients (educational only):");

    for (i, coefficient) in secret_key.as_ref().iter().enumerate() {
        println!("s[{i}] = {coefficient}");
    }

    // [3] Real-value encoding
    println!("\n[3] Encoding real-valued input");

    let encoded_message = encode_real(original_value);

    println!("Original value: {:.5}", original_value);
    println!("Encoding range: -100 to +100");
    println!("Encoded torus value: 0x{:016X}", encoded_message);

    // [4] LWE encryption
    println!("\n[4] Encrypting using TFHE-RS LWE");

    let ciphertext_modulus = CiphertextModulus::new_native();

    let mut ciphertext = LweCiphertext::new(
        0u64,
        LweDimension(LWE_DIMENSION).to_lwe_size(),
        ciphertext_modulus,
    );

    let noise_distribution = Gaussian::from_dispersion_parameter(
        StandardDev(NOISE_STD_DEV),
        0.0,
    );

    let start = Instant::now();

    encrypt_lwe_ciphertext(
        &secret_key,
        &mut ciphertext,
        Plaintext(encoded_message),
        noise_distribution,
        &mut encryption_generator,
    );

    println!("Encryption time: {:?}", start.elapsed());

    // [5] Ciphertext inspection
    println!("\n[5] Actual ciphertext inspection");

    let mask = ciphertext.get_mask();

    println!("\nMask vector:");
    for (i, coefficient) in mask.as_ref().iter().enumerate() {
        println!("a[{i}] = 0x{:016X}", coefficient);
    }

    let body = *ciphertext.get_body().data;

    println!("\nCiphertext body:");
    println!("b = 0x{:016X}", body);

    // [6] LWE vector and residual calculation
    println!("\n[6] LWE vector and noise calculation");

    let dot_product = mask
        .as_ref()
        .iter()
        .zip(secret_key.as_ref().iter())
        .fold(0u64, |acc, (&a, &s)| {
            acc.wrapping_add(a.wrapping_mul(s))
        });

    let residual = body
        .wrapping_sub(dot_product)
        .wrapping_sub(encoded_message);

    println!("\nLWE equation:");
    println!("b = <a,s> + m + e (mod 2^64)");
    println!("\nDot product:");
    println!("<a,s> = 0x{:016X}", dot_product);
    println!("\nMeasured residual:");
    println!("e (hex) = 0x{:016X}", residual);
    println!("e (signed) = {}", residual as i64);

    // [7] Decryption
    println!("\n[7] Decrypting ciphertext");

    let start = Instant::now();
    let decrypted_plaintext = decrypt_lwe_ciphertext(&secret_key, &ciphertext);

    println!("Decryption time: {:?}", start.elapsed());
    println!(
        "Decrypted torus value: 0x{:016X}",
        decrypted_plaintext.0
    );

    // [8] Experimental approximate decoding
    println!("\n[8] Noise-dependent approximate decoding");

    let raw_approximate_value = decode_real(decrypted_plaintext.0);
    let approximate_output = round_to_five_decimals(raw_approximate_value);

    println!(
        "\nRaw decoded real value: {:.12}",
        raw_approximate_value
    );
    println!(
        "Rounded approximate output: {:.5}",
        approximate_output
    );

    // [9] Noise comparison
    println!("\n[9] Noise effect comparison");

    let measured_noise = residual as i64 as f64;
    let expected_noise_effect =
        (measured_noise / TORUS_MODULUS) * (2.0 * VALUE_RANGE);

    println!("Original input: {:.5}", original_value);
    println!(
        "Measured noise effect in real-value units: {:.12}",
        expected_noise_effect
    );
    println!(
        "Approximate decrypted output: {:.5}",
        approximate_output
    );
    println!(
        "Observed numerical difference: {:.12}",
        approximate_output - original_value
    );
}
