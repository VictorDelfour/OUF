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
'''bash
rustup toolchain install nightly

### 2. Use the Nightly Toolchain

Choose one of the following:

**Option A:** Prefix commands with `+nightly`  
Example: 
'''bash
cargo +nightly build  
cargo +nightly run
'''
**Option B:** Set nightly as the default for this project  
Run:  
'''bash
rustup override set nightly
'''
Then you can simply run:  
'''bash
cargo build
'''
---

## ▶️ Usage

1. Clone the repository and navigate to the project directory:  
'''bash
git clone https://github.com/yourusername/ouf.git  
cd ouf
'''
2. Edit `src/main.rs` to define your function and input.

3. Run the project:  
'''bash
cargo run --release
'''
> ⚠️ Ensure your function is compatible with the operations supported by `tfhe-rs`.

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for more information.
