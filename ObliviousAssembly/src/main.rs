use std::fs::OpenOptions;
use std::time::{Duration, Instant};
use std::{env, vec};

use revolut::*;
use std::io::Write;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::*;

const DEBUG: bool = false; // true if willing to decrypt the intermediate tape
                           // const COMPARE: bool = true; // true if willing to compare OTM to OMov

pub fn main() {
    for i in 0..1 {
        pouf();
    }
}

fn pouf() {
    let param = PARAM_MESSAGE_4_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = key(ctx.parameters());
    let public_key = private_key.get_public_key();

    let mut tape_vec = vec![0; ctx.message_modulus().0];
    let mut tape = LUT::from_vec(&tape_vec, &private_key, &mut ctx);

    let selector = generate_function_selector(&private_key, &mut ctx);
    let data_access = generate_access(&private_key, &mut ctx);
    let functions_storage = generate_random_functions_2D(&mut ctx);

    let start_time_total = Instant::now();

    for step in 0..selector.len() {
        println!("step {}", step);
        let (addr1, addr2, addr3) = (
            &data_access[3 * step],
            &data_access[3 * step + 1],
            &data_access[3 * step + 2],
        );

        let input1 = move_and_read(&mut tape, addr1, public_key, &mut ctx);
        let input2 = move_and_read(&mut tape, addr2, public_key, &mut ctx);
        let cell_content = move_and_read(&mut tape, addr3, public_key, &mut ctx);

        let start_time_eval = Instant::now();
        let mut result = evaluate_pouf(
            public_key,
            &ctx,
            &input1,
            &input2,
            &selector[step],
            &functions_storage,
        );
        println!("temps PIR : {} ms", start_time_eval.elapsed().as_millis());

        write_new_cell_content_LUT(&mut tape, &cell_content, public_key, &ctx, &mut result);
    }

    println!("temps Step : {} ms", start_time_total.elapsed().as_millis());
    tape.print(&private_key, &ctx);
}

fn move_and_read(tape: &mut LUT, addr: &LWE, public_key: &PublicKey, ctx: &mut Context) -> LWE {
    change_head_position_LUT(tape, addr, public_key);
    let mut content = read_cell_content(tape, public_key, ctx);
    content
}

/// Lift a 2-digit value to its OHE as a vector of LWE
pub fn blind_tensor_lift_LWE(x: &LWE, y: &LWE, ctx: &Context, public_key: &PublicKey) -> Vec<LWE> {
    let p = ctx.full_message_modulus() as usize;
    let mut result = Vec::with_capacity(p * p);

    // Step 1: Trivially encrypt LUT [1, 0, 0, ..., 0]
    let mut base_lut = LUT::from_vec_trivially(&vec![1], ctx);

    // Step 2: Apply blind rotation on x (negated once)
    let neg_x = public_key.neg_lwe(x, ctx);
    public_key.blind_rotation_assign(&neg_x, &mut base_lut, ctx);

    // Step 3: Extract along first dimension and apply blind rotation for y
    let neg_y = public_key.neg_lwe(y, ctx);
    for d in 0..p {
        let intermediate = public_key.lut_extract(&base_lut, d, ctx);
        let mut y_lut = LUT::from_lwe(&intermediate, public_key, ctx);
        public_key.blind_rotation_assign(&neg_y, &mut y_lut, ctx);

        for e in 0..p {
            let final_value = public_key.lut_extract(&y_lut, e, ctx);
            result.push(final_value);
        }
    }

    result
}
/// PIR-like construction to access a matrix element blindly.
/// Homomorphically returns Enc(matrix[x][y]) by summing OHE[i] * data[i].
/// Cost: 2 Blind Rotations (for generating OHE) + ~p multiplications.
pub fn blind_matrix_access_clear_1d(
    public_key: &PublicKey,
    data: &[u64],
    ctx: &Context,
    ohe: &[LWE],
) -> LWE {
    assert_eq!(data.len(), ohe.len(), "Data and OHE size mismatch.");

    let mut result = public_key.allocate_and_trivially_encrypt_lwe(0, ctx);

    for (val, lwe) in data.iter().zip(ohe.iter()) {
        let mut temp = lwe.clone();
        lwe_ciphertext_cleartext_mul_assign(&mut temp, Cleartext(*val));
        lwe_ciphertext_add_assign(&mut result, &temp);
    }

    result
}

/// PIR-like matrix access using homomorphic operations:
/// Computes Enc(matrix[x][y]) by weighted summation over one-hot encoded encrypted indices.
/// Periodic bootstrapping is applied to control noise growth.
pub fn blind_matrix_access_clear_1d_with_noise_management(
    public_key: &PublicKey,
    data: &[u64],
    ctx: &Context,
    ohe: &[LWE],
) -> LWE {
    assert_eq!(data.len(), ohe.len(), "Data and OHE size mismatch.");

    let mut result = public_key.allocate_and_trivially_encrypt_lwe(0, ctx);
    let mut count_since_bootstrap = 0;
    let bootstrap_interval = 32; // Tune as needed based on your parameters

    for (val, lwe) in data.iter().zip(ohe.iter()) {
        let mut temp = lwe.clone();
        lwe_ciphertext_cleartext_mul_assign(&mut temp, Cleartext(*val));
        lwe_ciphertext_add_assign(&mut result, &temp);
        count_since_bootstrap += 1;

        // Periodically reset noise to prevent overflow
        if count_since_bootstrap >= bootstrap_interval {
            public_key.bootstrap_lwe(&mut result, ctx);
            count_since_bootstrap = 0;
        }
    }

    // Final safety bootstrap if needed
    if count_since_bootstrap > 0 {
        public_key.bootstrap_lwe(&mut result, ctx);
    }

    result
}

pub fn write_new_cell_content_LUT(
    tape: &mut LUT,
    cell_content: &LweCiphertext<Vec<u64>>,
    public_key: &PublicKey,
    ctx: &Context,
    storage: &mut LweCiphertext<Vec<u64>>,
) {
    lwe_ciphertext_sub_assign(&mut storage.to_owned(), cell_content);
    let lut_new_cell_content = LUT::from_lwe(&storage, &public_key, &ctx);
    public_key.glwe_sum_assign(&mut tape.0, &lut_new_cell_content.0);
}

pub fn change_head_position_LUT(
    tape: &mut LUT,
    data_access: &LweCiphertext<Vec<u64>>,
    public_key: &PublicKey,
) {
    blind_rotate_assign(&data_access, &mut tape.0, &public_key.fourier_bsk);
}

pub fn read_cell_content(
    tape: &LUT,
    public_key: &PublicKey,
    ctx: &Context,
) -> LweCiphertext<Vec<u64>> {
    let mut ct_0 = LweCiphertext::new(
        0,
        ctx.big_lwe_dimension().to_lwe_size(),
        ctx.ciphertext_modulus(),
    );
    trivially_encrypt_lwe_ciphertext(&mut ct_0, Plaintext(ctx.full_message_modulus() as u64));
    let cell_content = public_key.blind_array_access(&ct_0, &tape, &ctx);

    return cell_content;
}

fn evaluate_ouf(
    public_key: &PublicKey,
    ctx: &Context,
    input1: &LweCiphertext<Vec<u64>>,
    input2: &LweCiphertext<Vec<u64>>,
    selector: &LweCiphertext<Vec<u64>>,
    function_storage: &Vec<Vec<Vec<u64>>>,
) -> LweCiphertext<Vec<u64>> {
    let mut storage = Vec::new();

    for i in function_storage {
        // let start_time_bma = Instant::now();

        storage.push(public_key.blind_matrix_access_clear(i, &input1, &input2, &ctx));
        // let elapsed_time_bma = start_time_bma.elapsed();
        // println!("temps clear BMA :{} ms",elapsed_time_bma.as_millis());
    }

    // let start_time_packing = Instant::now();

    let result_acc = LUT::from_vec_of_lwe(&storage, &public_key, &ctx);
    // let elapsed_time_step = start_time_packing.elapsed();
    // println!("temps packing :{}",elapsed_time_step.as_millis());
    let result = public_key.blind_array_access(&selector, &result_acc, &ctx);
    result
}

fn evaluate_pouf(
    public_key: &PublicKey,
    ctx: &Context,
    input1: &LweCiphertext<Vec<u64>>,
    input2: &LweCiphertext<Vec<u64>>,
    selector: &LweCiphertext<Vec<u64>>,
    function_storage: &Vec<Vec<u64>>,
) -> LweCiphertext<Vec<u64>> {
    // Step 1: Compute 2D one-hot encoding of (input1, input2)
    let ohe = blind_tensor_lift_LWE(input1, input2, ctx, public_key);

    // Step 2: PIR-like access for each function row
    let mut row_results = Vec::with_capacity(function_storage.len());
    for row in function_storage.iter() {
        let accessed = blind_matrix_access_clear_1d(public_key, row, ctx, &ohe);
        row_results.push(accessed);
    }

    // Step 3: Pack the resulting LWE values into a LUT (indexed by selector)
    let packed_result = LUT::from_vec_of_lwe(&row_results, public_key, ctx);

    // Step 4: Blindly access the correct row result based on selector
    public_key.blind_array_access(selector, &packed_result, ctx)
}

fn generate_random_functions(ctx: &mut Context) -> Vec<Vec<Vec<u64>>> {
    let mut result = Vec::new();
    for i in 0..ctx.full_message_modulus() as u64 {
        let mut matrix = Vec::new();
        for j in 0..ctx.full_message_modulus() as u64 {
            let mut line = Vec::new();
            for k in 0..ctx.full_message_modulus() as u64 {
                line.push(k);
            }
            matrix.push(line);
        }
        result.push(matrix);
    }
    result
}

fn generate_random_functions_2D(ctx: &mut Context) -> Vec<Vec<u64>> {
    let mut result = Vec::new();
    for i in 0..ctx.full_message_modulus() as u64 {
        let mut line = Vec::new();
        for j in 0..(ctx.full_message_modulus() as u64) * (ctx.full_message_modulus() as u64) {
            line.push(1);
        }
        result.push(line);
    }
    result
}

fn generate_access(
    private_key: &PrivateKey,
    mut ctx: &mut Context,
) -> Vec<LweCiphertext<Vec<u64>>> {
    let mut result = Vec::new();
    for i in 0..1 {
        let mut j = i + 1;
        while j > 0 {
            result.push(0);
            result.push(0);
            result.push(0);
            j -= 1;
        }
    }
    let mut relative_result = Vec::new() as Vec<i32>;
    relative_result.push(result[0].clone() as i32);
    for i in 1..result.len() {
        relative_result
            .push((result[i].clone() as i32 - result[i.clone() - 1].clone() as i32) as i32);
    }

    let mut relative_result_positive = Vec::new() as Vec<u64>;

    for i in relative_result {
        if i <= 0 {
            relative_result_positive.push(i as u64 + 2 * ctx.message_modulus().0 as u64);
        } else {
            relative_result_positive.push(i as u64);
        }
    }

    let mut result_encrypted = Vec::new();
    for i in relative_result_positive {
        result_encrypted.push(private_key.allocate_and_encrypt_lwe(i, &mut ctx));
    }
    result_encrypted
}

fn generate_function_selector(
    private_key: &PrivateKey,
    mut ctx: &mut Context,
) -> Vec<LweCiphertext<Vec<u64>>> {
    let mut result = Vec::new();
    result.push(0);
    let mut result_encrypted = Vec::new();
    for i in result.clone() {
        result_encrypted.push(private_key.allocate_and_encrypt_lwe(i, &mut ctx));
    }
    // print!("selector : {:?}", result.clone());

    result_encrypted
}
