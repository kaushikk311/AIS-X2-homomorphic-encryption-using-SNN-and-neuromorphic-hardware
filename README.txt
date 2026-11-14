TFHE-RS fixed-point expression calculator

Run these commands from this folder in separate terminals. Start the backend first.

    cargo run --locked --release --bin backend
    cargo run --locked --release --bin frontend

Enter an expression such as 1.25 + 2 * 3 and expect 7.25. The frontend sends the
expression to the Rust backend at 127.0.0.1:7878. Type exit to close the session.
Release builds are important for PBS performance. Full-size multiplications can
take substantial time on a CPU.

The evaluator supports addition, subtraction, multiplication, unary signs, and
parentheses. Literals use up to five decimal places and the existing parser range
of plus or minus one billion. Multiplication keeps a widened encrypted magnitude
through rescaling, then truncates toward zero at five decimal places. Results
outside the signed 128-bit fixed-point range wrap modulo 2^128.

The backend uses TFHE Core Crypto for LWE encryption, bootstrapping, key switching,
arithmetic, and decryption. The TFHE 1.8.1 parameter set provides the radix base,
noise distributions, and centered modulus switching. The backend encrypts each
literal into 64 two-bit blocks and decrypts only the final 64-block result before
sending VALUE to the frontend. The backend prints ciphertext coefficients and
stage timings. The standalone LWE demo is a separate binary.

Run cargo test --locked --release for the parser and formatting tests.
