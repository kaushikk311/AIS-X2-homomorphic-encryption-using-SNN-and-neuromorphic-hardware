TFHE-RS fixed-point expression calculator

Run these commands from this folder in separate terminals. Start the backend first.

    cargo run --locked --release --bin backend
    cargo run --locked --release --bin frontend

Enter an expression such as 1.25 + 2 * 3 and expect 7.25. The frontend sends the
expression to the Rust backend at 127.0.0.1:7878. Type exit to close the session.
Release builds are important for PBS performance. Full-size multiplications can
take substantial time on a CPU.

The evaluator supports addition, subtraction, multiplication, division, unary signs,
parentheses, and comparisons (<, <=, ==, !=, >=, >). Comparisons have lower
precedence than arithmetic and return 1 for true or 0 for false. Use parentheses
to combine comparisons. Literals use up to five decimal places and the existing parser range
of plus or minus one billion. Multiplication keeps a widened encrypted magnitude
through rescaling. Division scales the encrypted numerator before dividing by
the encrypted denominator. Both operations truncate toward zero at five decimal
places. The backend reports division by zero at the end of evaluation. Results
outside the signed 128-bit fixed-point range wrap modulo 2^128.

The backend uses TFHE Core Crypto for LWE encryption, bootstrapping, key switching,
arithmetic, and decryption. The TFHE 1.8.1 parameter set provides the radix base,
noise distributions, and centered modulus switching. The backend encrypts each
literal into 64 two-bit blocks. The backend decrypts the final 64-block result and
the final error flag for expressions containing division. The backend sends a VALUE
or ERROR response and prints ciphertext coefficients and
stage timings. The standalone LWE demo is a separate binary.

Run cargo test --locked --release for the parser and formatting tests.
