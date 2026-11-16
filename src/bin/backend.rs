use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::v1_8::V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;

use tfhe_demo::expression::{format_fixed, parse, Comparison, Expr, SCALE};
use tfhe_demo::ADDRESS;

#[path = "backend/radix.rs"]
mod radix;
use radix::{inspect_ciphertexts, EncryptedValue, Radix};

fn section(title: &str) {
    println!("\n========== {title} ==========");
}

fn comparison_symbol(op: Comparison) -> &'static str {
    match op {
        Comparison::Less => "<",
        Comparison::LessEqual => "<=",
        Comparison::Equal => "==",
        Comparison::NotEqual => "!=",
        Comparison::GreaterEqual => ">=",
        Comparison::Greater => ">",
    }
}

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
            op: '+' | '*',
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

fn print_ast(expr: &Expr, depth: usize) {
    let indent = "  ".repeat(depth);
    match expr {
        Expr::Number(value) => println!("{indent}Number {}", format_fixed(*value)),
        Expr::Variable(name) => println!("{indent}Variable {name}"),
        Expr::Unary { op, rhs } => {
            println!("{indent}Unary {op}");
            print_ast(rhs, depth + 1);
        }
        Expr::Binary { lhs, rhs, .. } | Expr::Compare { lhs, rhs, .. } => {
            match expr {
                Expr::Binary { op, .. } => println!("{indent}Binary {op}"),
                Expr::Compare { op, .. } => println!("{indent}Compare {}", comparison_symbol(*op)),
                _ => unreachable!(),
            }
            print_ast(lhs, depth + 1);
            print_ast(rhs, depth + 1);
        }
    }
}

enum EncryptedExpr {
    Number(EncryptedValue),
    Unary(char, Box<EncryptedExpr>),
    Binary(char, Box<EncryptedExpr>, Box<EncryptedExpr>),
    Compare(Comparison, Box<EncryptedExpr>, Box<EncryptedExpr>),
}

fn encrypt_expression(
    expr: &Expr,
    radix: &Radix,
    key: &LweSecretKeyOwned<u64>,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
) -> EncryptedExpr {
    let mut child = |expr: &Expr| Box::new(encrypt_expression(expr, radix, key, generator));
    match expr {
        Expr::Number(value) => EncryptedExpr::Number(radix.encrypt(*value, key, generator)),
        Expr::Unary { op, rhs } => EncryptedExpr::Unary(*op, child(rhs)),
        Expr::Binary { op, lhs, rhs } => EncryptedExpr::Binary(*op, child(lhs), child(rhs)),
        Expr::Compare { op, lhs, rhs } => EncryptedExpr::Compare(*op, child(lhs), child(rhs)),
        Expr::Variable(_) => unreachable!("variables rejected before encryption"),
    }
}

fn evaluate(expr: EncryptedExpr, radix: &Radix) -> EncryptedValue {
    match expr {
        EncryptedExpr::Number(value) => value,
        EncryptedExpr::Unary(op, rhs) => {
            let value = evaluate(*rhs, radix);
            if op == '-' {
                println!("[ARITHMETIC] Unary minus: complement the radix digits and propagate the carry.");
                radix.trace_pbs("Unary minus", || radix.negate(&value))
            } else {
                value
            }
        }
        EncryptedExpr::Binary(op, lhs, rhs) => {
            let left = evaluate(*lhs, radix);
            let right = evaluate(*rhs, radix);
            match op {
                '+' => {
                    println!("[ARITHMETIC] +: Add LWE digits with lwe_ciphertext_add_assign and propagate carries with PBS lookup tables.");
                    radix.trace_pbs("Operator +", || radix.add(&left, &right))
                }
                '*' => {
                    println!("[ARITHMETIC] *: Generate encrypted partial products with PBS lookup tables, combine the rows, and rescale.");
                    radix.trace_pbs("Operator *", || radix.multiply(&left, &right))
                }
                _ => unreachable!("operator validated before encryption"),
            }
        }
        EncryptedExpr::Compare(op, lhs, rhs) => {
            let left = evaluate(*lhs, radix);
            let right = evaluate(*rhs, radix);
            let symbol = comparison_symbol(op);
            println!("[ARITHMETIC] Compare {symbol}: evaluate signed digit ordering with PBS LUTs and encode it as encrypted 0 or 1.");
            radix.trace_pbs(&format!("Comparison {symbol}"), || {
                radix.compare(&left, &right, op)
            })
        }
    }
}

fn send_outcome(stream: &mut TcpStream, line: &str) -> io::Result<()> {
    section("06 Send outcome to frontend");
    send(stream, line)
}

fn main() -> io::Result<()> {
    let listener = TcpListener::bind(ADDRESS)?;
    println!("[BACKEND] Listening on {ADDRESS}");
    let (mut stream, peer) = listener.accept()?;
    println!("[BACKEND] Connected: {peer}");

    section("Session setup | Generate TFHE keys");
    println!("[KEYGEN] Creating runtime random generators and session keys before sending READY.");
    println!("[KEYGEN] Parameter set: V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128");
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
    println!(
        "[KEYGEN] Small LWE dimension={}, GLWE dimension={}, polynomial size={}, large LWE dimension={}",
        small_key.lwe_dimension().0, params.glwe_dimension.0, params.polynomial_size.0,
        large_key.lwe_dimension().0,
    );
    println!("[KEYGEN] LWE and GLWE keys: {:?}", start.elapsed());

    send(
        &mut stream,
        "STATUS|Generating standard and Fourier bootstrapping keys",
    )?;
    let start = Instant::now();
    println!("[CORE CRYPTO] par_allocate_and_generate_new_lwe_bootstrap_key");
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
    println!("[CORE CRYPTO] convert_standard_lwe_bootstrap_key_to_fourier");
    println!("[KEYGEN] Fourier conversion: {:?}", start.elapsed());
    drop(standard_bsk);

    send(
        &mut stream,
        "STATUS|Generating key-switching key and PBS lookup tables",
    )?;
    let start = Instant::now();
    println!("[CORE CRYPTO] allocate_and_generate_new_lwe_keyswitch_key");
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
    println!("[CORE CRYPTO] generate_programmable_bootstrap_glwe_lut builds the lookup tables.");
    radix.describe_pbs();
    send(&mut stream, "READY")?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 || line.trim_end() == "EXIT" {
            return Ok(());
        }
        section("01 Receive expression from frontend");
        let Some(source) = line.trim_end().strip_prefix("EXPR|") else {
            send_outcome(&mut stream, "ERROR|Invalid expression request")?;
            continue;
        };
        println!("[TCP] Input: {source}");
        section("02 Parse expression and build AST");
        let expr = match parse(source).and_then(|expr| {
            validate(&expr)?;
            Ok(expr)
        }) {
            Ok(expr) => expr,
            Err(error) => {
                send_outcome(&mut stream, &format!("ERROR|{error}"))?;
                continue;
            }
        };
        print_ast(&expr, 0);

        let request_start = Instant::now();
        let pbs_before = radix.pbs_count();
        section("03 Encrypt input values and inspect ciphertexts");
        println!("[KEYGEN] Using the TFHE keys generated at session setup.");
        send(&mut stream, "STATUS|Evaluating encrypted expression")?;
        let encrypted = encrypt_expression(&expr, &radix, &small_key, &mut encryption_generator);

        section("04 Encrypted arithmetic with PBS and key switching");
        let result = evaluate(encrypted, &radix);
        let pbs_calls = radix.pbs_count() - pbs_before;
        println!("[PBS/KS] Request total: {pbs_calls} bootstraps and {pbs_calls} key switches, including input refresh.");
        inspect_ciphertexts("Encrypted expression result", &result.blocks);

        section("05 Decrypt final outcome");
        let start = Instant::now();
        println!("[CORE CRYPTO] decrypt_lwe_ciphertext uses the small LWE secret key to recover the encoded phase.");
        println!(
            "[DECRYPT] Round each decoded phase and reconstruct the signed fixed-point integer."
        );
        match radix.decrypt(&result, &small_key) {
            Ok(value) => {
                let formatted = format_fixed(value);
                println!(
                    "[DECRYPT] Scaled integer {value}, decimal result {formatted} (scale {SCALE}) in {:?}",
                    start.elapsed()
                );
                send_outcome(&mut stream, &format!("VALUE|{formatted}"))?;
                println!(
                    "[TIMING] Encryption through response: {:?}",
                    request_start.elapsed()
                );
            }
            Err(error) => send_outcome(&mut stream, &format!("ERROR|{error}"))?,
        }
    }
}
