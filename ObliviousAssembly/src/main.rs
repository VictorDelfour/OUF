use std::{env, vec};
use std::time::{Duration, Instant};

use tfhe::shortint::parameters::*;
use tfhe::core_crypto::prelude::*;

///The main library we are using besides tfhe.rs
use revolut::*;


///This implementation is a proof of concept that does not simulate client/server interaction
pub fn main()
{
    ofe();
}

///Our main function oblivious function evaluation.
fn ofe(){
    /// Generating the keys
    let param = PARAM_MESSAGE_4_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = key(ctx.parameters());
    let public_key = private_key.get_public_key();

    ///Choosing and encrypting the tape, it will be padded with 0
    let mut tape = vec![0, 0, 0, 0, 0];
    while tape.len() < ctx.message_modulus().0 {
        tape.push(0_u64);
    }
    let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);

    ///Generating functions, function selector and head movements inputs
    let selector = generate_function_selector(&private_key, &mut ctx,);
    let data_access = generate_access(&private_key,&mut ctx,);
    let functions_storage = generate_functions(&private_key,&mut ctx);


    let start_time_total = Instant::now();
    let mut step = 0;

    ///The computation procedure : doing steps until all instructions are done
    while step < selector.len() {
        println!("step {}",&step);
        let start_time_step = Instant::now();

        ///moving the head to input 1 and reading it
        change_head_position_ofe(&mut tape,&data_access[3*step.clone()] , public_key,   &mut ctx);
        let mut input1 = read_cell_content(&tape, &public_key, &ctx);

        ///moving the head to input 2 and reading it
        change_head_position_ofe(&mut tape, &data_access[3*step.clone()+1], public_key,   &mut ctx);
        let mut input2 = read_cell_content(&tape, &public_key, &ctx);

        ///moving the head to output location and reading it
        change_head_position_ofe(&mut tape, &data_access[3*step.clone()+2], public_key,   &mut ctx);
        let mut cell_content = read_cell_content(&tape, &public_key, &ctx);

        ///computing f_selector(input1, input2) and writing it at output location
        let mut result = oblivious_function_evaluation(public_key, &ctx, &input1, &input2, &selector[step.clone()], &functions_storage);
        write_new_cell_content_ofe(&mut tape, &cell_content, &public_key, &ctx, &mut result);

        step += 1;
        let elapsed_time_step = start_time_step.elapsed();
        println!("step time: {} ms",elapsed_time_step.as_millis());

    }


    let elapsed_time_total = start_time_total.elapsed();
    println!("total time: {} ms",elapsed_time_total.as_millis());

    ///decrypting the tape
    tape.print(&private_key,&ctx);
}

///Function to move the head
pub fn change_head_position_ofe(
    tape: &mut LUT,
    data_access: &LweCiphertext<Vec<u64>>,
    public_key: &PublicKey,
    mut ctx: &mut Context,
)
{
    blind_rotate_assign(&data_access, &mut tape.0, &public_key.fourier_bsk);

}
///Function to read under the head
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


///Function to overwrite a cell
pub fn write_new_cell_content_ofe(
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



///Function to evaluate f_selector(input1, input2).
/// It first compute all f_i(input1,input2) and then select the right one with a PBS.
fn oblivious_function_evaluation(
    public_key: &PublicKey,
    ctx: &Context,
    input1 :&LweCiphertext<Vec<u64>>,
    input2 :&LweCiphertext<Vec<u64>>,
    selector:&LweCiphertext<Vec<u64>>,
    function_storage: &Vec<Vec<LUT>>,

) ->LweCiphertext<Vec<u64>>{
    let mut storage = Vec::new();

    for i in function_storage{
        storage.push(public_key.blind_matrix_access(i, &input1, &input2, &ctx));
    }

    let result_acc =LUT::from_vec_of_lwe(&storage, &public_key, &ctx);
    let result = public_key.blind_array_access(&selector,&result_acc,&ctx);
    result
}


///Just a function to generate functions. The current functions are trivial.
///This function requires as output a Vec<Vec<LUT>>
/// You can give your functions as a vector of matrices (Vec<Vec<Vec<u64>>>)
/// And encrypt them using the encrypt_matrix function.
fn generate_functions(
    private_key: &PrivateKey,
    mut ctx: &mut Context)->Vec<Vec<LUT>>{
    let mut result_clear = Vec::new();
    for i in 0..ctx.full_message_modulus() as u64{
        let mut matrix = Vec::new();
        for j in 0..ctx.full_message_modulus() as u64{
            let mut line = Vec::new();
            for k in 0..ctx.full_message_modulus() as u64{
                line.push(1);
            }
            matrix.push(line);
        }
        result_clear.push(matrix);
    }
    let mut result = Vec::new();
    for i in result_clear {
        let f = private_key.encrypt_matrix(&mut ctx, &i);
        result.push(f)}
    result
}
///Generate head movements relatively to where the head currently is.
/// You cqn replace the first for with a vector of u64 and the function will generate the head movements
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

///Generate a vector of function selectors and encrypt it
///You can give a vector of u64 and it will be encrypted.
fn generate_function_selector(
    private_key: &PrivateKey,
    mut ctx: &mut Context,
)->Vec<LweCiphertext<Vec<u64>>>{
    let mut result = Vec::new();
    result.push(1);
    let mut result_encrypted = Vec::new();
    for i in result.clone(){
        result_encrypted.push(private_key.allocate_and_encrypt_lwe(i,&mut ctx));
    }

    result_encrypted
}
