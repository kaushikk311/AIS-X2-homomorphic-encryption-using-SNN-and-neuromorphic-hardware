# AIS-X2: Homomorphic Encryption Using SNN and Neuromorphic Hardware

Repository:
[AIS-X2-homomorphic-encryption-using-SNN-and-neuromorphic-hardware](https://github.com/kaushikk311/AIS-X2-homomorphic-encryption-using-SNN-and-neuromorphic-hardware)

## Overview

This repository contains the Rust implementation components for exploring fully homomorphic encryption with **TFHE-RS 1.8.1**. The checked-in source files provide:
1. A decoupled high-level client-server encrypted arithmetic pipeline (`FheInt128`).
2. A low-level hardware-oriented LWE modulo $2^{64}$ homomorphic addition benchmark (~200ns execution latency).
3. A floating-point LWE addition primitive with fixed-point decimal scaling.
4. An educational LWE diagnostic inspector verifying Torus noise bounds, ideal nearest-level rounding, and residual drift.

The repository supports our Capstone Project: **"Neuromorphic Acceleration of Secure Encrypted Neural Network Inference"** (Phase-1, Review 2).

---

## Project File Structure

The project strictly follows Cargo's standard source layout:

```text
AIS-X2-homomorphic-encryption-using-SNN-and-neuromorphic-hardware/
│
├── Cargo.toml
├── .gitignore
├── README.md
│
└── src/
    ├── main.rs                   # Client frontend entry point
    │
    └── bin/
        ├── backend.rs            # Decoupled TCP server (FheInt128 pipeline)
        ├── lwe_addition.rs       # Low-level LWE integer addition (~200ns)
        ├── lwe_addition_float.rs # Low-level LWE floating-point addition
        └── lwe_inspector.rs      # Low-level LWE noise & ideal rounding demo
```

### File Descriptions

* **`Cargo.toml`** — Package configuration and TFHE-RS dependency (`tfhe = { version = "=1.8.1", features = ["integer"] }`).
* **`src/main.rs`** — Client frontend that collects user inputs and sends requests to the backend server.
* **`src/bin/backend.rs`** — TCP backend server listening on `127.0.0.1:7878`. Generates 128-bit IND-CPA keys, installs evaluation keys, evaluates operations on `FheInt128` ciphertexts, and returns decrypted results. *(Replicates Review 2 Slide 13).*
* **`src/bin/lwe_addition.rs`** — Low-level LWE modulo $2^{64}$ homomorphic addition benchmark. Computes vector additions directly on ciphertexts in 100ns–204ns without decryption. *(Replicates Review 2 Slide 14).*
* **`src/bin/lwe_addition_float.rs`** — Low-level LWE floating-point addition. Performs homomorphic addition on continuous decimal inputs (5 decimal places) and absorbs cryptographic noise via nearest-level shift.
* **`src/bin/lwe_inspector.rs`** — Real-valued LWE noise inspector. Maps decimals to Torus $\mathbb{T}^{64}$, verifies LWE residual noise $e = b - \langle a,s \rangle - m$, demonstrates ideal nearest-level rounding, and shows raw unrounded noise drift ($0.000000000007$).

---

## Technology Stack

* **Language:** Rust (2021 edition)
* **Cryptographic Engine:** TFHE-RS 1.8.1
* **High-Level API:** `FheInt128` signed 128-bit encrypted integer arithmetic with $10^9$ fixed-point decimal scaling
* **Low-Level API:** `tfhe::core_crypto::prelude::*` for binary LWE secret keys, Gaussian noise sampling, modulo $2^{64}$ vector sums, and Torus decomposition
* **Transport:** TCP socket communication over `127.0.0.1:7878`

---

## Review 2 Demo Guide & Execution Instructions

### 1. Slide 13: Client-Server TFHE Execution (127.0.0.1:7878)
In Terminal 1, start the backend server:
```bash
cargo run --bin backend --release
```
In Terminal 2, start the frontend client:
```bash
cargo run --release
```
* **Inputs:** Select operation `1` (Addition), enter `3.14159` and `2.71828`.
* **Output:** `5.85987` (100% precision match, zero quantization loss).

---

### 2. Slide 14: Low-Level LWE Modulo Vector Benchmark (~200ns)
Run the hardware modulo addition benchmark:
```bash
cargo run --bin lwe_addition --release
```
* **Inputs:** Enter `4` and `3`.
* **Output:** Executes modulo $2^{64}$ vector addition in 100ns–300ns, absorbs noise, and outputs `7`. Replicates Slide 14 character-for-character.

---

### 3. Bonus Demo: Low-Level Decimal Addition
Demonstrates low-level LWE addition directly on continuous decimal numbers:
```bash
cargo run --bin lwe_addition_float --release
```
* **Inputs:** Enter e.g. `2.50000` and `3.25000`.
* **Output:** Encrypted sum `5.75000` verified with zero precision loss.

---

### 4. Bonus Demo: Decimal Noise Bounds & Ideal Rounding
Demonstrates cryptographic noise residual ($e$) and ideal rounding:
```bash
cargo run --bin lwe_inspector --release
```
* **Input:** Enter e.g. `3.14`.
* **Section [8]:** Shows ideal rounding recovering exact input `3.14000`.
* **Section [9]:** Shows raw unrounded reading with noise drift ($0.000000000007$).

---

## Security & Implementation Notes

1. **IND-CPA Security:** In production mode, 128-bit cryptographic security is maintained by adding small Gaussian noise to the least significant bits (LSBs).
2. **Noise Rounding (`closest_representable`):** Absorbs LWE noise upon decryption to guarantee 100% mathematical ground-truth correctness.
3. **Decoupled Architecture:** Client keys never leave the client device; the cloud server only holds evaluation keys and cannot decrypt user data.
