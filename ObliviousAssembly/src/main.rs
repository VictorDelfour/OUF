use std::fs::OpenOptions;
use std::time::{Duration, Instant};
use std::{env, vec};

use revolut::*;
use std::io::Write;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::*;
use rand::Rng;

const DEBUG: bool = false; // true if willing to decrypt the intermediate tape
                           // const COMPARE: bool = true; // true if willing to compare OTM to OMov

pub fn main() {
    for i in 0..1 {
        // pouf();
        pouf_glwe();
        // let param = PARAM_MESSAGE_4_CARRY_0;
        // let mut ctx = Context::from(param);
        // let private_key = key(ctx.parameters());
        // let public_key = private_key.get_public_key();
        //
        // let mut glwe = GlweCiphertext::new(
        //     0u64,
        //     ctx.glwe_dimension().to_glwe_size(),
        //     ctx.polynomial_size(),
        //     ctx.ciphertext_modulus(),
        // );
        // let mut glwe2 = GlweCiphertext::new(
        //     0u64,
        //     ctx.glwe_dimension().to_glwe_size(),
        //     ctx.polynomial_size(),
        //     ctx.ciphertext_modulus(),
        // );
        // let start_time_total = Instant::now();
        // glwe_ciphertext_monomial_mul_assign(&mut glwe2, MonomialDegree(2));
        // public_key.glwe_sum_assign(&mut glwe,&glwe2);
        // println!("temps GLWE rotate and sum: {} ms", start_time_total.elapsed().as_millis());


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
    let functions_storage = generate_random_matrix(&mut ctx);

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
    // tape.print(&private_key, &ctx);
}

fn move_and_read(tape: &mut LUT, addr: &LWE, public_key: &PublicKey, ctx: &mut Context) -> LWE {
    change_head_position_LUT(tape, addr, public_key);
    let mut content = read_cell_content(tape, public_key, ctx);
    content
}

pub fn write_new_cell_content_LUT(
    tape: &mut LUT,
    cell_content: &LWE,
    public_key: &PublicKey,
    ctx: &Context,
    storage: &mut LWE,
) {
    lwe_ciphertext_sub_assign(&mut storage.to_owned(), cell_content);
    let lut_new_cell_content = LUT::from_lwe(&storage, &public_key, &ctx);
    public_key.glwe_sum_assign(&mut tape.0, &lut_new_cell_content.0);
}

pub fn change_head_position_LUT(
    tape: &mut LUT,
    data_access: &LWE,
    public_key: &PublicKey,
) {
    blind_rotate_assign(&data_access, &mut tape.0, &public_key.fourier_bsk);
}

pub fn read_cell_content(
    tape: &LUT,
    public_key: &PublicKey,
    ctx: &Context,
) -> LWE {
    let mut ct_0 = LweCiphertext::new(
        0,
        ctx.big_lwe_dimension().to_lwe_size(),
        ctx.ciphertext_modulus(),
    );
    trivially_encrypt_lwe_ciphertext(&mut ct_0, Plaintext(ctx.full_message_modulus() as u64));
    let cell_content = public_key.blind_array_access(&ct_0, &tape, &ctx);

    return cell_content;
}


fn evaluate_pouf(
    public_key: &PublicKey,
    ctx: &Context,
    input1: &LWE,
    input2: &LWE,
    selector: &Vec<LWE>,
    function_storage: &Vec<Vec<u64>>,
) -> LWE {

    let modulus = ctx.message_modulus().0;
    // Step 1: Compute 2D one-hot encoding of selector

    let start_time_ohe = Instant::now();

    let mut ohe = blind_tensor_lift_LWE_k(selector, ctx, public_key);

    println!("temps ohe : {} ms", start_time_ohe.elapsed().as_millis());

    ohe.truncate(ctx.polynomial_size().0);

    // Concatenate all inner Vec<u64> into one big Vec<u64>.

    let mut flat = Vec::with_capacity(ohe.len() * ctx.big_lwe_dimension().to_lwe_size().0);
    for ct in ohe {
        let raw: Vec<u64> = ct.into_container();     // take ownership of the inner buffer
        flat.extend(raw);                          // append (copies)
    }

    let ohe_list = LweCiphertextList::from_container(flat, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());

    // Step 2: Pack the ohe in a glwe.
    let mut ohe_glwe = GlweCiphertext::new(
        0u64,
        ctx.glwe_dimension().to_glwe_size(),
        ctx.polynomial_size(),
        ctx.ciphertext_modulus(),
    );

    keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(&public_key.packing_ksk, &ohe_list, &mut ohe_glwe);

    println!("temps ohe as glwe: {} ms", start_time_ohe.elapsed().as_millis());

    // Step 3: Get the matrix row (encoding the selected function)
    let mut function =  mat_vec_mul(function_storage, &ohe_glwe, ctx, public_key);
    function.truncate((modulus*modulus) as usize);

    // Step 4: Pack the resulting vec of LWE to do a BMA
    let mut function_BMA = Vec::new() as Vec<LUT>;
    for i in 0..modulus{
        let lut = function[((&i*modulus)as usize)..(((&i+1)*modulus)as usize)].to_vec();
        function_BMA.push(LUT::from_vec_of_lwe(&lut, public_key, ctx));
    }
    // Step 5: Compute the BMA and obtain the final result.
    public_key.blind_matrix_access(&function_BMA, &input1, &input2,&ctx)
}

fn generate_random_matrix(ctx: &mut Context) -> Vec<Vec<u64>>{
    let p = ctx.full_message_modulus();

    // Define a random matrix of size t*n with elements modulo 16
    let mut rng = rand::thread_rng();
    let mut matrix = vec![vec![0; ctx.polynomial_size().0]; ctx.polynomial_size().0];
    for i in 0..ctx.polynomial_size().0 {
        for j in 0..ctx.polynomial_size().0 {
            matrix[i][j] = rng.gen_range(0..p) as u64;
        }
    }
    matrix
}

fn generate_access(
    private_key: &PrivateKey,
    mut ctx: &mut Context,
) -> Vec<LWE> {
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
) -> Vec<Vec<LWE>> {
    let mut result = Vec::new();
    ///The function selector cannot exceed the poly size.
    result.push(vec![0,0,0]);
    let mut result_encrypted = Vec::new();
    for i in result.clone() {
        let mut result_i_encrypted = Vec::new();
        for j in i{
            result_i_encrypted.push(private_key.allocate_and_encrypt_lwe(j, &mut ctx));
        }
        result_encrypted.push(result_i_encrypted)

    }
    // print!("selector : {:?}", result.clone());

    result_encrypted
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

/// Recursively lift a k-digit value (values[0..k)) to its OHE as a vector of LWE.
/// `values`: slice of LWE, one per digit (k digits)
/// Output length: p^k, where p = ctx.full_message_modulus()
pub fn blind_tensor_lift_LWE_k(
    values: &[LWE],
    ctx: &Context,
    public_key: &PublicKey,
) -> Vec<LWE> {
    assert!(
        !values.is_empty(),
        "blind_tensor_lift_LWE_k: need at least one digit"
    );

    let p = ctx.full_message_modulus() as usize;
    let k = values.len();

    // Precompute negations once.
    let neg_values: Vec<LWE> = values
        .iter()
        .map(|v| public_key.neg_lwe(v, ctx))
        .collect();

    // Capacity hint: p^k
    let cap = p.pow(k as u32);
    let mut result = Vec::with_capacity(cap);

    // Base LUT: trivially encrypted [1, 0, 0, ...]
    let mut base_lut = LUT::from_vec_trivially(&vec![1], ctx);

    // First rotation by values[0]
    public_key.blind_rotation_assign(&neg_values[0], &mut base_lut, ctx);

    // Recurse from the next digit (level = 1)
    fn recurse(
        level: usize,
        current_lut: &LUT,
        neg_values: &[LWE],
        p: usize,
        result: &mut Vec<LWE>,
        public_key: &PublicKey,
        ctx: &Context,
    ) {
        // If we've already rotated by all digits, do the final extraction over the last axis.
        if level == neg_values.len() {
            for idx in 0..p {
                let ct = public_key.lut_extract(current_lut, idx, ctx);
                result.push(ct);
            }
            return;
        }

        // Otherwise: extract along this axis, lift to a LUT, rotate by the current digit, and go deeper.
        let neg = &neg_values[level];
        for idx in 0..p {

            let extracted_ct = public_key.lut_extract(current_lut, idx, ctx);
            let mut next_lut = LUT::from_lwe(&extracted_ct, public_key, ctx); // error here
            public_key.blind_rotation_assign(neg, &mut next_lut, ctx);
            recurse(level + 1, &next_lut, neg_values, p, result, public_key, ctx);
        }
    }

    recurse(1, &base_lut, &neg_values, p, &mut result, public_key, ctx);
    result
}

pub fn mat_vec_mul(
    matrix: &Vec<Vec<u64>>,
    ct_vec: &GLWE,
    ctx: &Context,
    public_key: &PublicKey,
) -> Vec<LWE> {
    let mut result = vec![];
    // Encode the rows of the matrix as polynomials
    let encoded_matrix = encode_matrix(matrix, ctx);

    // absorption rows x glwe
    for row in encoded_matrix {
        let r = public_key.glwe_absorption_polynomial_with_fft(ct_vec, &row);

        result.push(public_key.glwe_extract(&r, 0, ctx));
    }
    result

}

/// Encode a row
pub fn encode_row(row: &Vec<u64>, ctx: &Context) -> Poly {
    let n = ctx.polynomial_size().0;
    let p = ctx.full_message_modulus() as u64;

    // resize row to n with 0s if needed
    let mut new_row = row.clone();
    if row.len() < n {
        new_row.extend(vec![0; n - row.len()]);
    }
    // encode row
    let first = new_row[0];
    new_row[1..].reverse();
    for x in &mut new_row[1..] {
        *x = x.wrapping_neg() % p;
    }
    new_row[0] = first;
    Poly::from_container(new_row)
}

/// Encode a small matrix where each row is a polynomial
#[allow(dead_code)]
pub fn encode_matrix(matrix: &Vec<Vec<u64>>, ctx: &Context) -> Vec<Poly> {
    let mut result: Vec<Poly> = vec![];

    for row in matrix {
        result.push(encode_row(row, ctx));
    }
    result
}


///pouf if the client send one hot encoding to access functions :
fn pouf_glwe() {
    let param = PARAM_MESSAGE_4_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = key(ctx.parameters());
    let public_key = private_key.get_public_key();

    let mut tape_vec = vec![0; ctx.message_modulus().0];
    let mut tape = LUT::from_vec(&tape_vec, &private_key, &mut ctx);

    let selector = generate_function_selector_glwe(&private_key, &mut ctx);
    let data_access = generate_access(&private_key, &mut ctx);
    let functions_storage = generate_random_matrix(&mut ctx);

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
        let mut result = evaluate_pouf_glwe(
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

fn evaluate_pouf_glwe(
    public_key: &PublicKey,
    ctx: &Context,
    input1: &LWE,
    input2: &LWE,
    selector: &GLWE,
    function_storage: &Vec<Vec<u64>>,
) -> LWE {

    let modulus = ctx.message_modulus().0;

    // let start_time_ohe = Instant::now();
    //println!("temps ohe as glwe: {} ms", start_time_ohe.elapsed().as_millis());

    // Step 1: Get the matrix row (encoding the selected function)
    let start_time_test = Instant::now();
    let mut function =  mat_vec_mul(function_storage, &selector, ctx, public_key);
    function.truncate((modulus*modulus) as usize);
    println!("temps mat_vec_mul: {} ms", start_time_test.elapsed().as_millis());

    // Step 2: Pack the resulting vec of LWE to do a BMA
    let start_time_test = Instant::now();
    let mut function_BMA = Vec::new() as Vec<LUT>;
    for i in 0..modulus{
        let lut = function[((&i*modulus)as usize)..(((&i+1)*modulus)as usize)].to_vec();
        function_BMA.push(LUT::from_vec_of_lwe(&lut, public_key, ctx));
    }
    println!("temps creation matrice pour BMA: {} ms", start_time_test.elapsed().as_millis());

    // Step 3: Compute the BMA and obtain the final result.
    let start_time_test = Instant::now();
    let result = public_key.blind_matrix_access(&function_BMA, &input1, &input2,&ctx);
    println!("temps BMA: {} ms", start_time_test.elapsed().as_millis());
    result
}

fn generate_function_selector_glwe(
    private_key: &PrivateKey,
    mut ctx: &mut Context,
) -> Vec<GLWE> {
    let mut result = Vec::new();
    let mut rng = rand::thread_rng();

    ///The function selector cannot exceed the poly size.
    result.push(rng.gen_range(0..ctx.polynomial_size().0) as u64);
    let mut result_encrypted = Vec::new();

    for i in result.clone() {
        let mut v = vec![0 as u64; ctx.polynomial_size().0];
        v[i as usize] = 1;
        result_encrypted.push(private_key.allocate_and_encrypt_glwe_from_vec(&v,&mut ctx));

    }
    // print!("selector : {:?}", result.clone());

    result_encrypted
}













