# AIS-X2: Homomorphic Encryption Using SNN and Neuromorphic Hardware

Repository:
[AIS-X2-homomorphic-encryption-using-SNN-and-neuromorphic-hardware](https://github.com/kaushikk311/AIS-X2-homomorphic-encryption-using-SNN-and-neuromorphic-hardware)

## Overview

This repository contains a Rust implementation component for exploring
homomorphic encryption with **TFHE-RS 1.8.1**. The checked-in source
files provide a high-level encrypted arithmetic client/server
application and a separate low-level Learning With Errors (LWE)
inspection program.

The repository name describes the broader project direction involving
spiking neural networks (SNNs) and neuromorphic hardware. However, the
files currently visible in this repository snapshot are the Rust TFHE
demonstration files listed below; this README does not claim that an SNN
pipeline or neuromorphic hardware mapping is already implemented in
these files.

## Current repository contents

  -----------------------------------------------------------------------
  File                                Purpose
  ----------------------------------- -----------------------------------
  `Cargo.toml`                        Rust package configuration and
                                      TFHE-RS dependency

  `main.rs`                           Frontend/client application that
                                      collects inputs and sends operation
                                      requests to the backend

  `backend.rs`                        TCP backend that generates TFHE
                                      keys, encrypts inputs, evaluates
                                      supported operations, and decrypts
                                      results

  `lwe_inspector.rs`                  Standalone low-level LWE
                                      demonstration that displays
                                      ciphertext components and performs
                                      a noise-related residual
                                      calculation
  -----------------------------------------------------------------------

The GitHub repository currently lists these four files at its root.

## Technology stack

-   **Rust** --- implementation language.
-   **TFHE-RS 1.8.1** --- fully homomorphic encryption library.
-   **Integer API (`FheInt128`)** --- encrypted signed 128-bit integer
    operations in the backend.
-   **Core Crypto LWE API** --- low-level LWE key generation,
    encryption, ciphertext inspection, and decryption in the inspector.
-   **TCP sockets** --- communication between the frontend and backend
    over `127.0.0.1:7878`.

The dependency declared in `Cargo.toml` is:

``` toml
[package]
name = "tfhe_demo"
version = "0.1.0"
edition = "2021"

[dependencies]
tfhe = { version = "=1.8.1", features = ["integer"] }
```

## High-level encrypted arithmetic

The frontend accepts two numeric inputs and an operation selection. It
sends a request to the backend through a local TCP connection.

The backend performs the following sequence:

1.  Binds a TCP listener to `127.0.0.1:7878` and accepts a frontend
    connection.
2.  Builds the TFHE configuration.
3.  Generates a client key and a server evaluation key at runtime.
4.  Installs the server key for homomorphic evaluation.
5.  Parses the received decimal inputs into a scaled integer
    representation.
6.  Encrypts both inputs as `FheInt128` ciphertexts using the client
    key.
7.  Performs the selected operation on the encrypted values.
8.  Decrypts the result with the client key and sends the result to the
    frontend.

### Supported operations

  ------------------------------------------------------------------------
               Frontend choice Operation             Backend operation
  ---------------------------- --------------------- ---------------------
                           `1` Addition              Encrypted addition

                           `2` Subtraction           Encrypted subtraction

                           `3` Multiplication        Encrypted
                                                     multiplication with
                                                     fixed-point rescaling

                           `4` Division              Encrypted scaled
                                                     division

                           `5` Comparison            Encrypted
                                                     greater-than,
                                                     less-than, and
                                                     equality comparisons
  ------------------------------------------------------------------------

The backend uses a scale factor of `1,000,000,000` for decimal
representation, corresponding to a maximum of nine fractional decimal
digits in its input parser.

Division by zero is rejected by the backend. Arithmetic range checks are
also performed before the encrypted operation.

## Low-level LWE inspector

`lwe_inspector.rs` is a separate educational program. It demonstrates
the lower-level LWE encryption process independently of the `FheInt128`
arithmetic backend.

The inspector:

1.  Reads an integer in the range `0` to `15`.
2.  Creates an LWE secret key using the configured LWE dimension.
3.  Encodes the message into a 64-bit torus plaintext.
4.  Encrypts the plaintext using the TFHE-RS LWE encryption primitive
    and a Gaussian noise distribution.
5.  Displays the actual ciphertext mask coefficients in decimal and
    hexadecimal.
6.  Displays the ciphertext body in decimal and hexadecimal.
7.  Calculates the mask-secret-key dot product and the residual\
    `body - <a,s> - encoded_message` modulo `2^64`.
8.  Decrypts the LWE ciphertext, applies the configured decomposer, and
    checks whether the original message is recovered.

### Important distinction

The LWE inspector and the high-level arithmetic backend are separate
demonstrations:

-   `lwe_inspector.rs` exposes the mask and body of the LWE ciphertext
    it creates.
-   `backend.rs` performs arithmetic using `FheInt128` ciphertexts.
-   The LWE ciphertext displayed by the inspector is **not** the
    internal ciphertext used by the backend's `FheInt128` calculation.

The inspector's parameters are explicitly described in the source as
educational and **not secure**. They should not be used as production
cryptographic parameters.

## Architecture

``` text
                 FRONTEND
                  main.rs
                    |
                    | TCP request
                    | 127.0.0.1:7878
                    v
                 BACKEND
                backend.rs
                    |
          +---------+----------+
          |                    |
          v                    v
    TFHE configuration    Runtime key generation
                               |
                     +---------+---------+
                     |                   |
                     v                   v
                 Client key        Server key
                     |                   |
                     v                   v
              Encrypt inputs      Homomorphic evaluation
                     |                   |
                     +---------+---------+
                               |
                               v
                       Encrypted result
                               |
                               v
                    Client-key decryption
                               |
                               v
                        Final result


        SEPARATE LOW-LEVEL DEMONSTRATION

                 lwe_inspector.rs
                         |
                 LWE key generation
                         |
                  LWE encryption
                         |
             +-----------+-----------+
             |           |           |
           Mask        Body       Residual
             |           |           |
             +-----------+-----------+
                         |
                   LWE decryption
                         |
                 Message verification
```

## Requirements

-   Rust toolchain with Cargo.
-   Internet access on the first build so Cargo can download
    dependencies.
-   Windows, Linux, or macOS with a supported Rust toolchain.

The project pins TFHE-RS to version `1.8.1` in `Cargo.toml`.

## Build and run

Clone the repository:

``` bash
git clone https://github.com/kaushikk311/AIS-X2-homomorphic-encryption-using-SNN-and-neuromorphic-hardware.git
cd AIS-X2-homomorphic-encryption-using-SNN-and-neuromorphic-hardware
```

Build the project:

``` bash
cargo build --release
```

Run the backend in the first terminal:

``` bash
cargo run --bin backend --release
```

Run the frontend in a second terminal:

``` bash
cargo run --bin tfhe_demo --release
```

Run the low-level LWE inspector separately:

``` bash
cargo run --bin lwe_inspector --release
```

The frontend and backend must run in separate terminals. Start the
backend first so it is listening before the frontend attempts to
connect.

## Example usage

For an addition test:

1.  Start the backend.
2.  Start the frontend.
3.  Select operation `1` (Addition).
4.  Enter `2` as the first number.
5.  Enter `3` as the second number.
6.  The backend encrypts both inputs, performs the operation on the
    encrypted values, decrypts the result, and returns it.

Expected mathematical result:

``` text
2 + 3 = 5
```

For the LWE inspector, run it separately and enter an integer from `0`
to `15` when prompted.

## Security and implementation notes

-   The backend uses runtime-generated TFHE client and server keys.
-   The high-level arithmetic path uses `FheInt128`; it does not print
    the raw mask and body coefficients of that high-level ciphertext.
-   The LWE inspector prints the coefficients of its own low-level
    diagnostic ciphertext.
-   The LWE inspector's small educational parameters are not suitable
    for real-world security.
-   Do not expose the local backend port publicly without adding
    appropriate network security and access controls.
-   This README describes the source files visible in the repository
    snapshot. It does not assert that the broader SNN inference or
    neuromorphic hardware components are implemented in this Rust
    subproject.

## Future work

The broader project title points toward combining homomorphic
encryption, SNN-based processing, and neuromorphic hardware. Potential
next steps for the repository include:

-   Documenting the SNN model, input representation, and inference
    pipeline when those components are added.
-   Integrating encrypted inference with the intended SNN workflow.
-   Documenting the neuromorphic hardware target and mapping or
    acceleration strategy.
-   Adding reproducible benchmarks for encryption, evaluation,
    decryption, and inference.
-   Adding tests for decimal parsing, arithmetic boundaries, comparison,
    and protocol error handling.

These are suggested future additions, not claims about features already
present in the current repository snapshot.

## Repository

[View the source code on
GitHub](https://github.com/kaushikk311/AIS-X2-homomorphic-encryption-using-SNN-and-neuromorphic-hardware)
