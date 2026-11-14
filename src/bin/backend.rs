use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::v1_8::V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;

use tfhe_demo::expression::{format_fixed, parse, Expr, SCALE};
use tfhe_demo::ADDRESS;

#[path = "backend/radix.rs"]
mod radix;
use radix::{Digit, EncryptedValue, Radix};

fn send(stream: &mut TcpStream, line: &str) -> io::Result<()> {
    println!("{line}");
    writeln!(stream, "{line}")?;
    stream.flush()
}

fn validate(expr: &Expr) -> Result<(), String> {
    match expr {
        Expr::Number(_) => Ok(()),
        Expr::Variable(name) => Err(format!(
            "Variable '{name}' requires an encrypted assignment"
        )),
        Expr::Unary { op: '+' | '-', rhs } => validate(rhs),
        Expr::Binary {
            op: '+' | '-' | '*' | '/',
            lhs,
            rhs,
        }
        | Expr::Compare { lhs, rhs, .. } => {
            validate(lhs)?;
            validate(rhs)
        }
        Expr::Unary { op, .. } | Expr::Binary { op, .. } => {
            Err(format!("Unsupported encrypted operator: {op}"))
        }
    }
}

fn evaluate(
    expr: &Expr,
    radix: &Radix,
    key: &LweSecretKeyOwned<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> (EncryptedValue, Option<Digit>) {
    match expr {
        Expr::Number(value) => (radix.encrypt(*value, key, generator), None),
        Expr::Unary { op, rhs } => {
            let (value, error) = evaluate(rhs, radix, key, generator);
            let value = if *op == '-' {
                radix.negate(&value)
            } else {
                value
            };
            (value, error)
        }
        Expr::Binary { op, lhs, rhs } => {
            let (left, lhs_error) = evaluate(lhs, radix, key, generator);
            let (right, rhs_error) = evaluate(rhs, radix, key, generator);
            let start = Instant::now();
            let (value, operation_error) = match op {
                '+' => (radix.add(&left, &right, false), None),
                '-' => (radix.add(&left, &right, true), None),
                '*' => (radix.multiply(&left, &right), None),
                '/' => {
                    let (value, zero) = radix.divide(&left, &right);
                    (value, Some(zero))
                }
                _ => unreachable!("operator validated before evaluation"),
            };
            println!("[EVAL/PBS/KS] {op} in {:?}", start.elapsed());
            (
                value,
                merge_errors(
                    radix,
                    merge_errors(radix, lhs_error, rhs_error),
                    operation_error,
                ),
            )
        }
        Expr::Compare { op, lhs, rhs } => {
            let (left, lhs_error) = evaluate(lhs, radix, key, generator);
            let (right, rhs_error) = evaluate(rhs, radix, key, generator);
            let start = Instant::now();
            let value = radix.compare(&left, &right, *op);
            println!("[COMPARE/PBS/KS] {op:?} in {:?}", start.elapsed());
            (value, merge_errors(radix, lhs_error, rhs_error))
        }
        Expr::Variable(_) => unreachable!("variables rejected before evaluation"),
    }
}

fn merge_errors(radix: &Radix, left: Option<Digit>, right: Option<Digit>) -> Option<Digit> {
    match (left, right) {
        (Some(left), Some(right)) => Some(radix.either_error(left, &right)),
        (left, right) => left.or(right),
    }
}

fn inspect_radix(value: &EncryptedValue) {
    println!("[RESULT] {} encrypted radix blocks", value.blocks.len());
    for (index, ciphertext) in value.blocks.iter().enumerate() {
        let mask = ciphertext.get_mask();
        let coefficients = mask.as_ref();
        println!(
            "[BLOCK {index}] LWE dimension={}, first mask coefficients={:?}, body={}",
            coefficients.len(),
            &coefficients[..coefficients.len().min(8)],
            ciphertext.get_body().data,
        );
    }
}

fn main() -> io::Result<()> {
    let listener = TcpListener::bind(ADDRESS)?;
    println!("[BACKEND] Listening on {ADDRESS}");
    let (mut stream, peer) = listener.accept()?;
    println!("[BACKEND] Connected: {peer}");

    let params = V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    let mut boxed_seeder = new_seeder();
    let seeder = boxed_seeder.as_mut();
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    send(&mut stream, "STATUS|Generating runtime LWE and GLWE keys")?;
    let start = Instant::now();
    let small_key = LweSecretKey::generate_new_binary(params.lwe_dimension, &mut secret_generator);
    let glwe_key = GlweSecretKey::generate_new_binary(
        params.glwe_dimension,
        params.polynomial_size,
        &mut secret_generator,
    );
    let large_key = glwe_key.clone().into_lwe_secret_key();
    println!("[KEYGEN] LWE and GLWE keys: {:?}", start.elapsed());

    send(
        &mut stream,
        "STATUS|Generating standard and Fourier bootstrapping keys",
    )?;
    let start = Instant::now();
    let standard_bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &small_key,
        &glwe_key,
        params.pbs_base_log,
        params.pbs_level,
        params.glwe_noise_distribution,
        params.ciphertext_modulus,
        &mut encryption_generator,
    );
    println!("[KEYGEN] Standard BSK: {:?}", start.elapsed());
    let start = Instant::now();
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        standard_bsk.input_lwe_dimension(),
        standard_bsk.glwe_size(),
        standard_bsk.polynomial_size(),
        standard_bsk.decomposition_base_log(),
        standard_bsk.decomposition_level_count(),
    );
    convert_standard_lwe_bootstrap_key_to_fourier(&standard_bsk, &mut fourier_bsk);
    println!("[KEYGEN] Fourier conversion: {:?}", start.elapsed());
    drop(standard_bsk);

    send(
        &mut stream,
        "STATUS|Generating key-switching key and PBS lookup tables",
    )?;
    let start = Instant::now();
    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &large_key,
        &small_key,
        params.ks_base_log,
        params.ks_level,
        params.lwe_noise_distribution,
        params.ciphertext_modulus,
        &mut encryption_generator,
    );
    println!("[KEYGEN] Key switching key: {:?}", start.elapsed());
    drop(large_key);
    drop(glwe_key);
    let radix = Radix::new(
        params,
        fourier_bsk,
        ksk,
        &small_key,
        &mut encryption_generator,
    );
    println!(
        "[PARAMETERS] scale={SCALE}, radix={}, LWE dimension={}, polynomial size={}, LWE noise={:?}, GLWE noise={:?}, modulus switch={:?}",
        radix.base, params.lwe_dimension.0, params.polynomial_size.0,
        params.lwe_noise_distribution, params.glwe_noise_distribution,
        params.modulus_switch_noise_reduction_params,
    );
    send(&mut stream, "READY")?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 || line.trim_end() == "EXIT" {
            return Ok(());
        }
        let Some(source) = line.trim_end().strip_prefix("EXPR|") else {
            send(&mut stream, "ERROR|Invalid expression request")?;
            continue;
        };
        let expr = match parse(source).and_then(|expr| {
            validate(&expr)?;
            Ok(expr)
        }) {
            Ok(expr) => expr,
            Err(error) => {
                send(&mut stream, &format!("ERROR|{error}"))?;
                continue;
            }
        };

        send(&mut stream, "STATUS|Evaluating encrypted expression")?;
        let (result, error) = evaluate(&expr, &radix, &small_key, &mut encryption_generator);
        if let Some(flag) = error {
            match radix.decrypt_error(&flag, &small_key) {
                Ok(false) => {}
                Ok(true) => {
                    send(&mut stream, "ERROR|Division by zero")?;
                    continue;
                }
                Err(error) => {
                    send(&mut stream, &format!("ERROR|{error}"))?;
                    continue;
                }
            }
        }
        inspect_radix(&result);
        let start = Instant::now();
        match radix.decrypt(&result, &small_key) {
            Ok(value) => {
                println!("[DECRYPT] Final radix result: {:?}", start.elapsed());
                send(&mut stream, &format!("VALUE|{}", format_fixed(value)))?;
            }
            Err(error) => send(&mut stream, &format!("ERROR|{error}"))?,
        }
    }
}
