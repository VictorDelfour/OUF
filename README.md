# Oblivious Universal Function (OUF)

**OUF** is a proof-of-concept implementation of an **Oblivious Universal Function Evaluator**, designed for secure client-server computations.

In this model:

- The **client** provides both the function and the input.
- The **server** provides computational resources but learns **nothing** about the function or the data, except for some upper bounds.

This proof of concept is implemented using the [`tfhe-rs`](https://github.com/zama-ai/tfhe-rs) homomorphic encryption library in Rust.

---

## 🚀 Features

- Secure two-party computation
- Oblivious evaluation using homomorphic encryption
- Modular and customizable
- Built with Rust and `tfhe-rs`

---

## 🛠️ Prerequisites

Make sure you have **Rust** and **Cargo** installed.

### 1. Install the Nightly Toolchain

```bash
rustup toolchain install nightly


