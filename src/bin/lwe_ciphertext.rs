use std::io::{self, Write};
use std::time::Instant;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::v1_8::V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;

fn print_ciphertext(label: &str, ct: &LweCiphertextOwned<u64>) {
    println!("\n========== {label} ==========");
    println!("LWE size: {}", ct.lwe_size().0);
    println!("LWE dimension: {}", ct.lwe_size().to_lwe_dimension().0);

    println!("\nMask coefficients:");
    for (i, coefficient) in ct.get_mask().as_ref().iter().enumerate() {
        println!("a[{i}] = {coefficient}  (0x{coefficient:016X})");
    }

    let body = *ct.get_body().data;
    println!("\nBody:");
    println!("b = {body}  (0x{body:016X})");
}

fn main() -> io::Result<()> {
    println!("==============================================");
    println!(" TFHE-RS 1.8.1 | LWE CIPHERTEXT GENERATION");
    println!("==============================================");

    let params = V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    let lwe_dimension = params.lwe_dimension;
    let noise_distribution = params.lwe_noise_distribution;
    let ciphertext_modulus = params.ciphertext_modulus;
    let plaintext_modulus = params.message_modulus.0 * params.carry_modulus.0;
    let max = plaintext_modulus - 1;
    print!("Enter an integer from 0 to {max}: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = match input.trim().parse::<u64>() {
        Ok(value) if value <= max => value,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Expected an integer from 0 to {max}"),
            ))
        }
    };

    println!("\n[1] Initialize runtime random generators");

    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();

    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    println!("Runtime seeder initialized.");
    println!("Secret-key generator initialized.");
    println!("Encryption generator initialized.");

    println!("\n[2] Generate LWE secret key");

    let start = Instant::now();

    let secret_key = LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);

    println!("Secret-key generation time: {:?}", start.elapsed());
    println!("LWE dimension: {}", secret_key.lwe_dimension().0);
    println!("Secret-key coefficients: {}", secret_key.as_ref().len());
    println!("Secret-key values are not printed.");

    println!("\n[3] Encode input message");

    let delta = (1_u64 << (u64::BITS - 1)) / plaintext_modulus;
    let encoded_message = input * delta;

    println!("Input message: {input}");
    println!("Plaintext modulus: {plaintext_modulus}");
    println!("Delta: {delta}");
    println!("Encoded plaintext: {encoded_message}");
    println!("Encoded plaintext hex: 0x{encoded_message:016X}");

    let plaintext = Plaintext(encoded_message);

    println!("\n[4] Encrypt message into an LWE ciphertext");

    let start = Instant::now();

    let ciphertext: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &secret_key,
        plaintext,
        noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    println!("Encryption time: {:?}", start.elapsed());

    print_ciphertext("ACTUAL ENCRYPTED CIPHERTEXT", &ciphertext);

    println!("\n[5] Decrypt only to verify encryption");

    let start = Instant::now();

    let decrypted = decrypt_lwe_ciphertext(&secret_key, &ciphertext);

    println!("Decryption time: {:?}", start.elapsed());
    println!("Decrypted torus value: 0x{:016X}", decrypted.0);

    let decomposer = SignedDecomposer::new(
        DecompositionBaseLog((plaintext_modulus.ilog2() + 1) as usize),
        DecompositionLevelCount(1),
    );

    let rounded = decomposer.closest_representable(decrypted.0);

    let recovered_message = rounded / delta;

    println!("Recovered message: {recovered_message}");
    println!("Expected message: {input}");

    assert_eq!(
        recovered_message, input,
        "LWE encryption/decryption verification failed"
    );

    println!("\nSUCCESS: Actual TFHE-RS LWE encryption verified.");
    println!("The ciphertext was encrypted before it was decrypted.");
    Ok(())
}
