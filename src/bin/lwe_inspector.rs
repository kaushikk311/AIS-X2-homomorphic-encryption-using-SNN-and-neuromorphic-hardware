use std::io::{self, Write};
use std::time::Instant;

use tfhe::core_crypto::prelude::*;

const LWE_DIMENSION: usize = 16;

// Five decimal places: 1.23456 -> 123456.
const DECIMAL_SCALE: i64 = 100_000;

// Offset maps the signed input range [-100, 100] to non-negative message levels.
const INPUT_OFFSET: i64 = 10_000_000;
const MIN_CODE: i64 = 0;
const MAX_CODE: i64 = 20_000_000;

// 25-bit message space in a 64-bit torus: delta = 2^(64 - 25) = 2^39.
const DELTA: u64 = 1u64 << 39;

// Small Gaussian dispersion so the genuine random LWE error stays well below
// half a message interval. This is an experimental demonstration parameter.
const NOISE_STD_DEV: f64 = 0.000000000001;

fn parse_decimal(prompt: &str) -> Option<f64> {
    print!("{prompt}");
    io::stdout().flush().expect("Could not flush prompt");

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Could not read input");

    match input.trim().parse::<f64>() {
        Ok(value) if value.is_finite() && (-100.0..=100.0).contains(&value) => {
            Some(value)
        }
        _ => {
            eprintln!("Enter a valid number between -100 and 100.");
            None
        }
    }
}

fn encode_real(value: f64) -> (i64, u64) {
    let scaled = (value * DECIMAL_SCALE as f64).round() as i64;
    let message_code = scaled + INPUT_OFFSET;
    let torus_plaintext = (message_code as u64).wrapping_mul(DELTA);
    (message_code, torus_plaintext)
}

fn format_scaled(value: i64) -> String {
    let sign = if value < 0 { "-" } else { "" };
    let absolute = value.unsigned_abs();
    format!(
        "{sign}{}.{:05}",
        absolute / DECIMAL_SCALE as u64,
        absolute % DECIMAL_SCALE as u64
    )
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
    println!("==================================================");
    println!(" TFHE-RS 1.8.1 — LWE REAL INPUT WITH IDEAL ROUNDING");
    println!("==================================================");
    println!("Five decimal places; educational toy parameters.");
    println!("Supported input range: -100.00000 to +100.00000");

    let original_value = match parse_decimal("\nEnter a real number: ") {
        Some(value) => value,
        None => return,
    };

    let (message_code, encoded_message) = encode_real(original_value);
    let original_scaled = message_code - INPUT_OFFSET;

    println!("\nOriginal input: {}", format_scaled(original_scaled));

    // [1] Initialize random generators
    println!("\n[1] Initialize random generators");

    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();

    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            seeder.seed(),
            seeder,
        );

    let mut secret_generator =
        SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    // [2] Generate LWE secret key
    println!("\n[2] Generate LWE secret key");

    let started = Instant::now();

    let secret_key =
        allocate_and_generate_new_binary_lwe_secret_key(
            LweDimension(LWE_DIMENSION),
            &mut secret_generator,
        );

    println!("Key generation time: {:?}", started.elapsed());
    println!("LWE dimension: {LWE_DIMENSION}");
    println!("Secret key coefficients (educational only):");

    for (i, coefficient) in secret_key.as_ref().iter().enumerate() {
        println!("  s[{i}] = {coefficient}");
    }

    // [3] Encode the decimal as a fixed-point message level
    println!("\n[3] Encode real-valued input");
    println!("Decimal scale: {DECIMAL_SCALE}");
    println!("Message offset: {INPUT_OFFSET}");
    println!("Message code: {message_code}");
    println!("Delta: 2^39 = {DELTA}");
    println!("Encoded torus plaintext: 0x{encoded_message:016X}");

    // [4] Create and encrypt the LWE ciphertext
    println!("\n[4] Encrypt using TFHE-RS LWE");

    let modulus = CiphertextModulus::new_native();

    let mut ciphertext = LweCiphertext::new(
        0u64,
        LweDimension(LWE_DIMENSION).to_lwe_size(),
        modulus,
    );

    let noise_distribution = Gaussian::from_dispersion_parameter(
        StandardDev(NOISE_STD_DEV),
        0.0,
    );

    let started = Instant::now();

    encrypt_lwe_ciphertext(
        &secret_key,
        &mut ciphertext,
        Plaintext(encoded_message),
        noise_distribution,
        &mut encryption_generator,
    );

    println!("Encryption time: {:?}", started.elapsed());

    // [5] Inspect the actual ciphertext
    println!("\n[5] Inspect ciphertext");
    print_ciphertext("LWE ciphertext", &ciphertext);

    // [6] Calculate the LWE dot product and actual residual
    println!("\n[6] Calculate LWE dot product and residual");

    let mask = ciphertext.get_mask();
    let body = *ciphertext.get_body().data;

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

    println!("LWE equation:");
    println!("b = <a,s> + m + e (mod 2^64)");
    println!("Dot product <a,s> = 0x{dot_product:016X}");
    println!("Measured residual e = 0x{residual:016X}");
    println!("Residual interpreted as signed i64 = {}", residual as i64);

    // [7] Decrypt
    println!("\n[7] Decrypt ciphertext");

    let started = Instant::now();
    let decrypted = decrypt_lwe_ciphertext(&secret_key, &ciphertext);
    println!("Decryption time: {:?}", started.elapsed());
    println!("Decrypted torus value: 0x{:016X}", decrypted.0);

    // [8] Ideal nearest-message-level rounding
    //
    // The plaintext levels are multiples of DELTA. Adding DELTA/2 before
    // division selects the nearest encoded message level.
    println!("\n[8] Ideal rounding / nearest-level decoding");

    let rounded_code = (
        (decrypted.0 as u128 + (DELTA as u128 / 2)) / DELTA as u128
    ) as i64;

    let recovered_scaled = rounded_code - INPUT_OFFSET;

    println!("Rounded message code: {rounded_code}");
    println!(
        "Ideal rounded output: {}",
        format_scaled(recovered_scaled)
    );

    // [9] Raw approximate reading (diagnostic only)
    //
    // This keeps the fractional residual instead of rounding to a message
    // level. It is useful for observing the tiny encryption error.
    println!("\n[9] Raw approximate reading (diagnostic)");

    let raw_code = decrypted.0 as f64 / DELTA as f64;
    let raw_real = (raw_code - INPUT_OFFSET as f64) / DECIMAL_SCALE as f64;

    let measured_noise_effect =
        (residual as i64 as f64) / DELTA as f64 / DECIMAL_SCALE as f64;

    println!("Raw decoded value: {raw_real:.12}");
    println!("Measured noise effect: {measured_noise_effect:.12}");
    println!(
        "Raw value rounded to five decimals: {}",
        format_scaled((raw_real * DECIMAL_SCALE as f64).round() as i64)
    );

    // [10] Verification
    println!("\n[10] Verify result");

    println!("Expected input:  {}", format_scaled(original_scaled));
    println!("Ideal decoded:   {}", format_scaled(recovered_scaled));

    if recovered_scaled == original_scaled {
        println!("\nSUCCESS: Ideal nearest-level decoding recovered the input.");
    } else {
        println!("\nWARNING: Decoded value differs from the encoded input.");
        println!("Review the noise and encoding parameters.");
    }

    println!("\n==================================================");
    println!(" LWE REAL INPUT EXPERIMENT COMPLETED");
    println!("==================================================");
    println!("Ideal rounding removes the small residual for message recovery.");
    println!("The raw diagnostic displays the residual without message-level rounding.");
    println!("Secret-key printing and these toy parameters are for education only.");
}
