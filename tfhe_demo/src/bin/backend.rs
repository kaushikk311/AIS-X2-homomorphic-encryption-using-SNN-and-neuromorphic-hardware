use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt128};

const SCALE: i128 = 1_000_000_000;
const PORT: &str = "127.0.0.1:7878";

fn send(stream: &mut TcpStream, message: &str) {
    println!("[BACKEND] {message}");

    writeln!(stream, "{message}")
        .expect("Could not send message to frontend");

    stream.flush()
        .expect("Could not flush TCP stream");
}

// Convert decimal input into a scaled i128 integer.
// Supports up to 9 decimal places.
fn parse_decimal(input: &str) -> Result<i128, String> {
    let input = input.trim();

    let (negative, unsigned) = if let Some(rest) = input.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = input.strip_prefix('+') {
        (false, rest)
    } else {
        (false, input)
    };

    if unsigned.is_empty() {
        return Err("Input cannot be empty".into());
    }

    let mut parts = unsigned.split('.');

    let whole_text = parts.next().unwrap_or("");
    let fraction_text = parts.next().unwrap_or("");

    if parts.next().is_some()
        || (whole_text.is_empty() && fraction_text.is_empty())
        || !whole_text.chars().all(|c| c.is_ascii_digit())
        || !fraction_text.chars().all(|c| c.is_ascii_digit())
        || fraction_text.len() > 9
    {
        return Err(
            "Enter a decimal with at most 9 decimal places".into()
        );
    }

    let whole: i128 = if whole_text.is_empty() {
        0
    } else {
        whole_text
            .parse()
            .map_err(|_| "Integer part is too large")?
    };

    let mut fraction = fraction_text.to_string();

    while fraction.len() < 9 {
        fraction.push('0');
    }

    let fractional: i128 = fraction
        .parse()
        .map_err(|_| "Invalid fractional part")?;

    let value = whole
        .checked_mul(SCALE)
        .and_then(|v| v.checked_add(fractional))
        .ok_or_else(|| "Number exceeds supported range".to_string())?;

    if negative {
        value
            .checked_neg()
            .ok_or_else(|| "Number exceeds supported range".to_string())
    } else {
        Ok(value)
    }
}

// Convert the scaled integer back into a decimal string.
fn format_decimal(value: i128) -> String {
    let magnitude = value.unsigned_abs();
    let scale = SCALE as u128;

    let whole = magnitude / scale;
    let fraction = magnitude % scale;

    let fraction_text = format!("{:09}", fraction);
    let fraction_text = fraction_text.trim_end_matches('0');

    let sign = if value < 0 { "-" } else { "" };

    if fraction_text.is_empty() {
        format!("{sign}{whole}")
    } else {
        format!("{sign}{whole}.{fraction_text}")
    }
}

fn main() {
    println!("==========================================");
    println!("         TFHE BACKEND SERVER");
    println!("==========================================");

    let listener = TcpListener::bind(PORT)
        .expect("Could not bind to backend port");

    println!("[BACKEND] Listening on {PORT}");
    println!("[BACKEND] Waiting for frontend connection...");

    let (mut stream, address) = listener
        .accept()
        .expect("Could not accept frontend connection");

    println!("[BACKEND] Frontend connected: {address}");

    send(&mut stream, "STATUS|Frontend connected to backend");

    // ==========================================
    // TFHE CONFIGURATION AND KEY GENERATION
    // ==========================================

    println!("\n========== KEY GENERATION ==========");

    send(&mut stream, "STATUS|Preparing TFHE configuration");

    let config = ConfigBuilder::default().build();

    send(&mut stream, "STATUS|Calling TFHE-RS key generation");

    send(
        &mut stream,
        "STATUS|Generating client key and server evaluation key",
    );

    println!("[BACKEND] Calling generate_keys(config) now...");

    let key_start = Instant::now();

    // Actual TFHE-RS cryptographic key generation.
    let (client_key, server_key) = generate_keys(config);

    let key_duration = key_start.elapsed();

    println!("[BACKEND] Key generation call completed.");
    println!("[BACKEND] Key generation duration: {key_duration:?}");

    send(&mut stream, "STATUS|Client key generated");
    send(&mut stream, "STATUS|Server evaluation key generated");

    set_server_key(server_key);

    send(&mut stream, "STATUS|Server evaluation key installed");
    send(&mut stream, "STATUS|Backend ready for encrypted operations");
    send(&mut stream, "READY");

    println!("\n[BACKEND] Waiting for calculation requests...");

    let mut reader = BufReader::new(
        stream.try_clone()
            .expect("Could not clone TCP connection"),
    );

    // ==========================================
    // MAIN REQUEST PROCESSING LOOP
    // ==========================================

    loop {
        let mut request = String::new();

        if reader.read_line(&mut request).unwrap_or(0) == 0 {
            println!("[BACKEND] Frontend disconnected.");
            break;
        }

        let request = request.trim();

        if request == "EXIT" {
            send(&mut stream, "RESULT|Backend session closed");
            break;
        }

        let fields: Vec<&str> = request.splitn(3, '|').collect();

        if fields.len() != 3 {
            send(&mut stream, "ERROR|Invalid request format");
            continue;
        }

        // Protocol: operation is "1", "2", "3", "4", or "5".
        let operation = fields[0];

        let a = match parse_decimal(fields[1]) {
            Ok(value) => value,
            Err(error) => {
                send(&mut stream, &format!("ERROR|First input: {error}"));
                continue;
            }
        };

        let b = match parse_decimal(fields[2]) {
            Ok(value) => value,
            Err(error) => {
                send(&mut stream, &format!("ERROR|Second input: {error}"));
                continue;
            }
        };

        if !["1", "2", "3", "4", "5"].contains(&operation) {
            send(&mut stream, "ERROR|Unknown operation");
            continue;
        }

        if operation == "4" && b == 0 {
            send(
                &mut stream,
                "ERROR|Division by zero is not allowed",
            );
            continue;
        }

        // Validate arithmetic ranges before encryption.
        let valid = match operation {
            "1" => a.checked_add(b).is_some(),

            "2" => a.checked_sub(b).is_some(),

            "3" => a.checked_mul(b).is_some(),

            "4" => a.checked_mul(SCALE)
                .and_then(|n| n.checked_div(b))
                .is_some(),

            "5" => true,

            _ => false,
        };

        if !valid {
            send(
                &mut stream,
                "ERROR|Operation exceeds the supported arithmetic range",
            );
            continue;
        }

        send(&mut stream, "STATUS|Received input from frontend");

        // ==========================================
        // ENCRYPTION OF INPUT 1
        // ==========================================

        println!("\n========== ENCRYPTION: INPUT 1 ==========");

        send(
            &mut stream,
            "STATUS|Starting actual TFHE encryption of input 1",
        );

        let start_a = Instant::now();

        // Actual encryption using TFHE-RS.
        let encrypted_a = FheInt128::encrypt(a, &client_key);

        let elapsed_a = start_a.elapsed();

        println!("[BACKEND] TFHE encryption call for input 1 returned.");
        println!("[BACKEND] Ciphertext type: FheInt128");
        println!("[BACKEND] Encryption duration: {elapsed_a:?}");

        println!(
            "[BACKEND] Ciphertext object is retained for encrypted computation."
        );

        send(&mut stream, "STATUS|Input 1 encryption completed");

        // ==========================================
        // ENCRYPTION OF INPUT 2
        // ==========================================

        println!("\n========== ENCRYPTION: INPUT 2 ==========");

        send(
            &mut stream,
            "STATUS|Starting actual TFHE encryption of input 2",
        );

        let start_b = Instant::now();

        // Actual encryption using TFHE-RS.
        let encrypted_b = FheInt128::encrypt(b, &client_key);

        let elapsed_b = start_b.elapsed();

        println!("[BACKEND] TFHE encryption call for input 2 returned.");
        println!("[BACKEND] Ciphertext type: FheInt128");
        println!("[BACKEND] Encryption duration: {elapsed_b:?}");

        println!(
            "[BACKEND] Ciphertext object is retained for encrypted computation."
        );

        send(&mut stream, "STATUS|Both inputs encrypted");

        // ==========================================
        // ENCRYPTED COMPUTATION
        // ==========================================

        println!("\n========== ENCRYPTED COMPUTATION ==========");

        send(
            &mut stream,
            "STATUS|Evaluating operation on ciphertexts",
        );

        let compute_start = Instant::now();

        // Operations are performed on encrypted values.
        let encrypted_result = match operation {

            // ADDITION
            "1" => {
                &encrypted_a + &encrypted_b
            }

            // SUBTRACTION
            "2" => {
                &encrypted_a - &encrypted_b
            }

            // MULTIPLICATION
            "3" => {
                let product = &encrypted_a * &encrypted_b;
                &product / SCALE
            }

            // DIVISION
            "4" => {
                let numerator = &encrypted_a * SCALE;
                &numerator / &encrypted_b
            }

            // COMPARISON
            "5" => {
                let gt = encrypted_a.gt(&encrypted_b);
                let lt = encrypted_a.lt(&encrypted_b);
                let eq = encrypted_a.eq(&encrypted_b);

                let compute_time = compute_start.elapsed();

                send(
                    &mut stream,
                    "STATUS|Encrypted computation completed",
                );

                println!(
                    "[BACKEND] Encrypted comparisons completed in {compute_time:?}"
                );

                send(
                    &mut stream,
                    "STATUS|Decrypting result with client key",
                );

                let gt: bool = gt.decrypt(&client_key);
                let lt: bool = lt.decrypt(&client_key);
                let eq: bool = eq.decrypt(&client_key);

                let result = format!(
                    "Greater={gt}, Less={lt}, Equal={eq}"
                );

                send(&mut stream, "RESULT|Operation completed");
                send(&mut stream, &format!("VALUE|{result}"));

                continue;
            }

            _ => unreachable!(),
        };

        let compute_time = compute_start.elapsed();

        println!(
            "[BACKEND] Encrypted computation duration: {compute_time:?}"
        );

        send(&mut stream, "STATUS|Encrypted computation completed");

        // ==========================================
        // DECRYPTION
        // ==========================================

        println!("\n========== DECRYPTION ==========");

        send(
            &mut stream,
            "STATUS|Decrypting result with client key",
        );

        let decrypt_start = Instant::now();

        // Actual TFHE-RS decryption.
        let result: i128 = encrypted_result.decrypt(&client_key);

        let decrypt_time = decrypt_start.elapsed();

        println!("[BACKEND] Decryption completed.");
        println!("[BACKEND] Decryption duration: {decrypt_time:?}");

        let formatted_result = format_decimal(result);

        send(&mut stream, "RESULT|Operation completed");
        send(&mut stream, &format!("VALUE|{formatted_result}"));

        // ==========================================
        // OPERATION SUMMARY
        // ==========================================

        println!("\n========== OPERATION SUMMARY ==========");

        println!("Input 1 encryption time: {elapsed_a:?}");
        println!("Input 2 encryption time: {elapsed_b:?}");
        println!("Encrypted computation time: {compute_time:?}");
        println!("Decryption time: {decrypt_time:?}");
        println!("Decrypted result: {formatted_result}");

        println!("=======================================");
    }
}