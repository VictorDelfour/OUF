use std::{env, vec};
use std::fs::OpenOptions;
use std::time::{Duration, Instant};

use revolut::*;
use tfhe::shortint::parameters::*;
use tfhe::core_crypto::prelude::*;
use std::io::Write;


const DEBUG: bool = false; // true if willing to decrypt the intermediate tape
// const COMPARE: bool = true; // true if willing to compare OTM to OMov

pub fn main()
{
    for i in 0..1{
        oa1();
    }
}

fn oa1(){
    // Generate the crypto context
    let param = PARAM_MESSAGE_4_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = key(ctx.parameters());
    let public_key = private_key.get_public_key();



    let mut output_file_oa = OpenOptions::new()
        .create(true)
        .append(true)
        .open("resultats_oa.txt")
        .expect("Impossible d'ouvrir le fichier");

    // En tête
    writeln!(output_file_oa, "execution,params,time").expect("Impossible d'écrire dans le fichier");

    // for i in 0..25 {

    //creation of tape
    let mut tape = vec![0, 0, 0, 0,0];
    while tape.len() < ctx.message_modulus().0 {
        tape.push(0_u64);
    }
    let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);

    let selector = generate_function_selector(&private_key, &mut ctx,);
    let data_access = generate_access(&private_key,&mut ctx,);
    let functions_storage = generate_random_functions_2D(&mut ctx);



    // let instruction_add = encode_instruction_add(&ctx);
    // let ct_instruction_add = private_key.encrypt_matrix(&mut ctx,&instruction_add);
    // let mut function_storage = Vec::new();
    // for i in 0..1{
    //     function_storage.push(&ct_instruction_add);
    //
    // }

    let mut nb_of_move = public_key.allocate_and_trivially_encrypt_lwe(0, &ctx);

    let start_time_total = Instant::now();
    let mut step = 0;
    while step < selector.len() {
        println!("step {}",&step);



        // println!("étape 0 \n");

        change_head_position_oa(&mut tape,&data_access[3*step.clone()] , public_key, &private_key, &mut nb_of_move, &mut ctx);
        // private_key.debug_lwe("move1", &data_access[3*step.clone()], &ctx);
        //
        // let mut output = tape.clone();
        // public_key.wrapping_neg_lwe(&mut nb_of_move);
        // blind_rotate_assign(&nb_of_move, &mut output.0, &public_key.fourier_bsk);
        // private_key.debug_lwe("nb_of_move",&nb_of_move,&ctx);


        // println!("étape 1 \n");

        let mut input1 = read_cell_content(&tape, &public_key, &ctx);
        change_head_position_oa(&mut tape, &data_access[3*step.clone()+1], public_key, &private_key, &mut nb_of_move, &mut ctx);
        // private_key.debug_lwe("nb_of_move",&nb_of_move,&ctx);


        // private_key.debug_lwe("move2", &data_access[1+3*step.clone()], &ctx);

        // let mut output = tape.clone();
        // public_key.wrapping_neg_lwe(&mut nb_of_move);
        // blind_rotate_assign(&nb_of_move, &mut output.0, &public_key.fourier_bsk);
        // output.print(&private_key,&ctx);

        // println!("étape 2 \n");

        let mut input2 = read_cell_content(&tape, &public_key, &ctx);
        change_head_position_oa(&mut tape, &data_access[3*step.clone()+2], public_key, &private_key, &mut nb_of_move, &mut ctx);
        // private_key.debug_lwe("nb_of_move",&nb_of_move,&ctx);





        println!("étape 3 \n");
        let mut cell_content = read_cell_content(&tape, &public_key, &ctx);
        let start_time_oa1 = Instant::now();

        let mut result = evaluate_oa2(public_key, &ctx, &input1, &input2, &selector[step.clone()], &functions_storage);
        let elapsed_time_oa1 = start_time_oa1.elapsed();
        println!("temps PIR : {} ms",elapsed_time_oa1.as_millis());
        write_new_cell_content_oa(&mut tape, &cell_content, &public_key, &ctx, &mut result);
        // write_new_cell_content_oa(&mut tape, &cell_content, &public_key, &ctx, &mut cell_content.clone());

        // private_key.debug_lwe("move3", &data_access[2+3*step.clone()], &ctx);
        // private_key.debug_lwe("input1", &input1, &ctx);
        // private_key.debug_lwe("input2", &input2, &ctx);
        // private_key.debug_lwe("result", &result, &ctx);
        // private_key.debug_lwe("selector", &selector[step.clone()], &ctx);
        //
        //
        // let mut output = tape.clone();
        // public_key.wrapping_neg_lwe(&mut nb_of_move);
        // blind_rotate_assign(&nb_of_move, &mut output.0, &public_key.fourier_bsk);
        // output.print(&private_key,&ctx);

        step += 1;

    }


    let elapsed_time_step = start_time_total.elapsed();
    println!("temps Step : {} ms",elapsed_time_step.as_millis());

    //println!("Oblivious oa End... \nReordering the tape..");
    // public_key.wrapping_neg_lwe(&mut nb_of_move);
    // blind_rotate_assign(&nb_of_move, &mut tape.0, &public_key.fourier_bsk);
    tape.print(&private_key,&ctx);
    // }

}

/// Lift a 2-digit value to its OHE as a vector of LWE
pub fn blind_tensor_lift_LWE(
    x: &LWE,
    y: &LWE,
    ctx: &Context,
    public_key: &PublicKey,
) -> Vec<LWE> {
    let p = ctx.full_message_modulus() as u64;
    let mut lut = LUT::from_vec_trivially(&vec![1], ctx);
    public_key.blind_rotation_assign(&public_key.neg_lwe(&x, &ctx), &mut lut, ctx);
    let mut result = Vec::new();
    for d in 0..p {
        let value = public_key.lut_extract(&lut, d as usize, &ctx);
        // let start_time_packing = Instant::now();
        let mut lut_temp = LUT::from_lwe(&value,&public_key,&ctx);
        public_key.blind_rotation_assign(&public_key.neg_lwe(&y, &ctx), &mut lut_temp, ctx);
        // let elapsed_time_step = start_time_packing.elapsed();
        // println!("packing 1 elt + BR :{}",elapsed_time_step.as_millis());
        for e in 0..p {
            let value = public_key.lut_extract(&lut_temp, e as usize, &ctx);
            result.push(value);
        }
    }
    result
}
/// PIR-like construction to access a matrix element blindly, returns Enc(matrix[x][y])
/// time: 2BR + pKS
pub fn blind_matrix_access_clear_1D(
    public_key: &PublicKey,
    data: &Vec<u64>,
    x: &LWE,
    y: &LWE,
    ctx: &Context,
    OHE: &Vec<LWE>,
) -> LWE {
    let zero = public_key.allocate_and_trivially_encrypt_lwe(0, ctx);
    let l = data
        .iter()
        .enumerate()
        .map(|(i, val)| {
            let mut xi = OHE[i].clone();
            lwe_ciphertext_cleartext_mul_assign(&mut xi, Cleartext(*val));
            xi
        });

    // Sum all the resulting LWE ciphertexts into one
    l.fold(zero, |mut acc, elt| {
        lwe_ciphertext_add_assign(&mut acc, &elt);
        acc
    })
}





pub fn store_read_cell_LUT_oa(
    public_key: &PublicKey,
    ctx: &Context,
    storage1: &LweCiphertext<Vec<u64>>,
    storage3: &LweCiphertext<Vec<u64>>,
    state:&LweCiphertext<Vec<u64>>,
    ct_instruction_add: &Vec<LUT>,
    ct_instruction_mul_unit: &Vec<LUT>,
    ct_instruction_mul_ten: &Vec<LUT>,

) -> (LweCiphertext<Vec<u64>>,LweCiphertext<Vec<u64>>){

    let mut res_add1_ct = public_key.allocate_and_trivially_encrypt_lwe(0,&ctx);
    lwe_ciphertext_add(&mut res_add1_ct,&storage1,&storage3);
    let res_add2_ct = public_key.blind_matrix_access(&ct_instruction_add, &storage1, &storage3, &ctx);
    let res_mul1_ct = public_key.blind_matrix_access(&ct_instruction_mul_unit, &storage1, &storage3, &ctx);
    let res_mul2_ct = public_key.blind_matrix_access(&ct_instruction_mul_ten, &storage1, &storage3, &ctx);

    let acc = vec![res_add1_ct,res_mul1_ct,res_add2_ct,res_mul2_ct];
    let ct_acc =LUT::from_vec_of_lwe(&*acc, &public_key, &ctx);

    let res_pir_1 = public_key.blind_array_access(&state,&ct_acc,&ctx);

    let mut stateplustwo = public_key.allocate_and_trivially_encrypt_lwe(2,&ctx);
    lwe_ciphertext_add_assign(&mut stateplustwo,&state);
    let res_pir_2 = public_key.blind_array_access(&stateplustwo,&ct_acc,&ctx);

    (res_pir_2,res_pir_1)
}

fn encode_instruction_position_oa(
    instruction_position: &Vec<i64>,
    ctx: &Context
) -> Vec<u64>
{
    let mut vector= Vec::new();
    for i in instruction_position.to_owned() {
        if i>=0{vector.push(i as u64)
        }
        else { vector.push((2*ctx.message_modulus().0 + i as usize) as u64,) }
    }
    vector
}

pub fn write_new_cell_content_oa(
    tape: &mut LUT,
    cell_content: &LweCiphertext<Vec<u64>>,
    public_key: &PublicKey,
    ctx: &Context,
    storage:&mut LweCiphertext<Vec<u64>>,
)
{
    lwe_ciphertext_sub_assign(&mut storage.to_owned(),cell_content);
    let lut_new_cell_content = LUT::from_lwe(&storage,&public_key,&ctx);
    public_key.glwe_sum_assign(&mut tape.0, &lut_new_cell_content.0);
}

pub fn change_head_position_oa(
    tape: &mut LUT,
    data_access: &LweCiphertext<Vec<u64>>,
    public_key: &PublicKey,
    private_key: &PrivateKey,
    nb_of_move : &mut LweCiphertext<Vec<u64>>,
    mut ctx: &mut Context,
)
{
    lwe_ciphertext_add_assign(nb_of_move, &data_access);
    blind_rotate_assign(&data_access, &mut tape.0, &public_key.fourier_bsk);

}

pub fn read_cell_content(
    tape: &LUT,
    public_key: &PublicKey,
    ctx: &Context,
) -> LweCiphertext<Vec<u64>>
{

    let mut ct_0 = LweCiphertext::new(0, ctx.big_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    trivially_encrypt_lwe_ciphertext(&mut ct_0, Plaintext(ctx.full_message_modulus() as u64));
    let cell_content = public_key.blind_array_access(&ct_0, &tape, &ctx);

    return cell_content;
}

fn evaluate_oa1(
    public_key: &PublicKey,
    ctx: &Context,
    input1 :&LweCiphertext<Vec<u64>>,
    input2 :&LweCiphertext<Vec<u64>>,
    selector:&LweCiphertext<Vec<u64>>,
    function_storage: &Vec<Vec<Vec<u64>>>,

) ->LweCiphertext<Vec<u64>>{
    let mut storage = Vec::new();

    for i in function_storage{
        // let start_time_bma = Instant::now();

        storage.push(public_key.blind_matrix_access_clear(i, &input1, &input2, &ctx));
        // let elapsed_time_bma = start_time_bma.elapsed();
        // println!("temps clear BMA :{} ms",elapsed_time_bma.as_millis());
    }



    // let start_time_packing = Instant::now();

    let result_acc =LUT::from_vec_of_lwe(&storage, &public_key, &ctx);
    // let elapsed_time_step = start_time_packing.elapsed();
    // println!("temps packing :{}",elapsed_time_step.as_millis());
    let result = public_key.blind_array_access(&selector,&result_acc,&ctx);
    result
}

fn evaluate_oa2(
    public_key: &PublicKey,
    ctx: &Context,
    input1 :&LweCiphertext<Vec<u64>>,
    input2 :&LweCiphertext<Vec<u64>>,
    selector:&LweCiphertext<Vec<u64>>,
    function_storage: &Vec<Vec<u64>>,

) ->LweCiphertext<Vec<u64>>{
    let OHE = blind_tensor_lift_LWE(input1, input2, &ctx, &public_key);
    let mut storage = Vec::new();
    for i in function_storage{
        // let start_time_bma = Instant::now();

        storage.push(blind_matrix_access_clear_1D(public_key,i, &input1, &input2, &ctx,&OHE));
        // let elapsed_time_bma = start_time_bma.elapsed();
        // println!("temps clear BMA :{} ms",elapsed_time_bma.as_millis());
    }



     // let start_time_packing = Instant::now();

    let result_acc =LUT::from_vec_of_lwe(&storage, &public_key, &ctx);
    // let elapsed_time_step = start_time_packing.elapsed();
    // println!("temps packing :{}",elapsed_time_step.as_millis());
    let result = public_key.blind_array_access(&selector,&result_acc,&ctx);
    result
}

fn generate_random_functions(ctx: &mut Context)->Vec<Vec<Vec<u64>>>{
    let mut result = Vec::new();
    for i in 0..ctx.full_message_modulus() as u64{
        let mut matrix = Vec::new();
        for j in 0..ctx.full_message_modulus() as u64{
            let mut line = Vec::new();
            for k in 0..ctx.full_message_modulus() as u64{
                line.push(k);
            }
            matrix.push(line);
        }
        result.push(matrix);
    }
    result
}

fn generate_random_functions_2D(ctx: &mut Context)->Vec<Vec<u64>>{
    let mut result = Vec::new();
    for i in 0..ctx.full_message_modulus() as u64{
        let mut line = Vec::new();
        for j in 0..(ctx.full_message_modulus() as u64)*(ctx.full_message_modulus() as u64){
            line.push(1);
        }
        result.push(line);
    }
    result
}



fn generate_access(
    private_key: &PrivateKey,
    mut ctx: &mut Context)->Vec<LweCiphertext<Vec<u64>>>{
    let mut result = Vec::new();
    for i in 0..1{
        let mut j =i+1;
        while j>0 {
            result.push(0);
            result.push(0);
            result.push(0);
            j-=1;
        }
    }
    let mut relative_result = Vec::new() as Vec<i32>;
    relative_result.push(result[0].clone() as i32);
    for i in 1..result.len(){
        relative_result.push((result[i].clone() as i32 - result[i.clone() - 1].clone() as i32) as i32);
    }

    let mut relative_result_positive = Vec::new() as Vec<u64>;

    for i in relative_result{
        if i<=0{
            relative_result_positive.push(i as u64+2*ctx.message_modulus().0 as u64);
        }
        else {
            relative_result_positive.push(i as u64);
        }
    }


    let mut result_encrypted = Vec::new();
    for i in relative_result_positive{
        result_encrypted.push(private_key.allocate_and_encrypt_lwe(i,&mut ctx));
    }
    result_encrypted
}

fn generate_function_selector(
    private_key: &PrivateKey,
    mut ctx: &mut Context,
)->Vec<LweCiphertext<Vec<u64>>>{
    let mut result = Vec::new();
    result.push(0);
    let mut result_encrypted = Vec::new();
    for i in result.clone(){
        result_encrypted.push(private_key.allocate_and_encrypt_lwe(i,&mut ctx));
    }
    // print!("selector : {:?}", result.clone());

    result_encrypted
}




