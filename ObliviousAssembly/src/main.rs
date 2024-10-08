use std::env;
use std::fs::OpenOptions;
use std::time::{Duration, Instant};

use revolut::*;
use tfhe::shortint::parameters::*;
use tfhe::core_crypto::prelude::*;
use std::io::Write;


const DEBUG: bool = false; // true if willing to decrypt the intermediate tape
const COMPARE: bool = true; // true if willing to compare OTM to OMov

pub fn main()
{
    OA();
}


fn OA(){
    // Generate the crypto context
    let param = PARAM_MESSAGE_3_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();


    println!("Key generated");

    let mut output_file_OA = OpenOptions::new()
        .create(true)
        .append(true)
        .open("resultats_OA.txt")
        .expect("Impossible d'ouvrir le fichier");

    // En tête
    writeln!(output_file_OA, "execution,params,time").expect("Impossible d'écrire dans le fichier");

    // for i in 0..25 {

    //creation of tape
    let mut tape = vec![1, 2, 0, 3];
    while tape.len() < ctx.message_modulus().0 {
        tape.push(0_u64);
    }
    println!("Tape : {:?}", tape);
    let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);
    println!("Tape Encrypted");


    // add
    // let mut instruction_position =  vec![1,2,2,-3,-2,4,0,0];
    // let mut state = public_key.allocate_and_trivially_encrypt_lwe(0, &ctx);

    //mul
    // let mut instruction_position = vec![1, 2, 2, -2, -3, 1, 1, 2];
    // let mut state = public_key.allocate_and_trivially_encrypt_lwe(1, &ctx);

    let state = private_key.allocate_and_encrypt_lwe(1,&mut ctx);

    let instruction_position = vec![0, 1, 1, 1, 2, -1];
    let instruction_position = encode_instruction_position_OA(&instruction_position, &ctx);
    let ct_instruction_position = LUT::from_vec(&instruction_position, &private_key, &mut ctx);

    if DEBUG {
        print!("instruction position : {:?}", instruction_position);
    }

    let instruction_add = encode_instruction_add(&ctx);
    let (instruction_mul_unit,instruction_mul_ten) = encode_instruction_mul(&ctx);
    let ct_instruction_add = private_key.encrypt_matrix(&mut ctx,&instruction_add);
    let ct_instruction_mul_unit = private_key.encrypt_matrix(&mut ctx,&instruction_mul_unit);
    let ct_instruction_mul_ten = private_key.encrypt_matrix(&mut ctx,&instruction_mul_ten);


    println!("Instructions Encrypted");
    let mut nb_of_move = public_key.allocate_and_trivially_encrypt_lwe(0, &ctx);
    let two = public_key.allocate_and_trivially_encrypt_lwe(2, &ctx);

    let start_time_total = Instant::now();

    println!("étape 0 \n");
    let start_time_step = Instant::now();

    change_head_position_OA(&mut tape, 0, &ct_instruction_position, public_key, &private_key, &mut nb_of_move, &mut ctx);

    if DEBUG {
        print!("New Tape : ");
        tape.print(&private_key, &ctx);
    }
    let elapsed_time_step = start_time_step.elapsed();
    println!("temps etape0 :{}",elapsed_time_step.as_millis());

    println!("étape 1 \n");
    let start_time_step = Instant::now();

    let mut storage0 = read_cell_content(&tape, &public_key, &ctx);
    change_head_position_OA(&mut tape, 1, &ct_instruction_position, public_key, &private_key, &mut nb_of_move, &mut ctx);

    let elapsed_time_step = start_time_step.elapsed();
    println!("temps etape1 :{}",elapsed_time_step.as_millis());
    if DEBUG {
        print!("New Tape : ");
        tape.print(&private_key, &ctx);
        private_key.debug_lwe("storage0", &storage0, &ctx);
    }

    println!("étape 2 \n");
    let start_time_step = Instant::now();

    let mut storage1 = read_cell_content(&tape, &public_key, &ctx);
    change_head_position_OA(&mut tape, 2, &ct_instruction_position, public_key, &private_key, &mut nb_of_move, &mut ctx);
    let elapsed_time_step = start_time_step.elapsed();
    println!("temps etape2 :{}",elapsed_time_step.as_millis());

    if DEBUG {
        print!("New Tape : ");
        tape.print(&private_key, &ctx);
    }

    println!("étape 3 \n");
    let start_time_step = Instant::now();

    let mut storage2 = read_cell_content(&tape, &public_key, &ctx);
    change_head_position_OA(&mut tape, 3, &ct_instruction_position, public_key, &private_key, &mut nb_of_move, &mut ctx);

    let elapsed_time_step = start_time_step.elapsed();
    println!("temps etape3 :{}",elapsed_time_step.as_millis());

    if DEBUG {
        print!("New Tape : ");
        tape.print(&private_key, &ctx);
    }



    println!("étape 4 \n");
    let start_time_step = Instant::now();

    let mut storage3 = read_cell_content(&tape, &public_key, &ctx);
    let (mut storage4, mut storage5) = store_read_cell_LUT_OA(
        &public_key,
        &ctx,
        &storage1,
        &storage3,
        &state,
        &ct_instruction_add,
        &ct_instruction_mul_unit,
        &ct_instruction_mul_ten);

    change_head_position_OA(&mut tape, 4, &ct_instruction_position, public_key, &private_key, &mut nb_of_move, &mut ctx);

    let elapsed_time_step = start_time_step.elapsed();
    println!("temps etape4 :{}",elapsed_time_step.as_millis());

    if DEBUG {
        print!("New Tape : ");
        tape.print(&private_key, &ctx);
        private_key.debug_lwe("storage0", &storage0, &ctx);
        private_key.debug_lwe("storage4", &storage4, &ctx);
        private_key.debug_lwe("storage5", &storage5, &ctx);
    }

    println!("étape 5 \n");
    let start_time_step = Instant::now();

    let cell_content = read_cell_content(&tape, &public_key, &ctx);
    write_new_cell_content_OA(&mut tape, &cell_content, &public_key, &ctx, &mut storage5);
    change_head_position_OA(&mut tape, 5, &ct_instruction_position, public_key, &private_key, &mut nb_of_move, &mut ctx);

    let elapsed_time_step = start_time_step.elapsed();
    println!("temps etape5 :{}",elapsed_time_step.as_millis());

    if DEBUG {
        print!("New Tape : ");
        tape.print(&private_key, &ctx);
    }

    println!("étape 6 \n");
    let start_time_step = Instant::now();

    let cell_content = read_cell_content(&tape, &public_key, &ctx);
    let mut storage4 = select_write(
        &public_key,
        &ctx,
        &mut storage0,
        &mut storage1,
        &mut storage2,
        &mut storage3,
        &mut storage4,
        &state,
        &ct_instruction_mul_unit,);

    write_new_cell_content_OA(&mut tape, &cell_content, &public_key, &ctx, &mut storage4);

    let elapsed_time_step = start_time_step.elapsed();
    println!("temps etape6 :{}",elapsed_time_step.as_millis());

    let elapsed_time_step = start_time_total.elapsed();
    println!("temps oblivious operation :{}",elapsed_time_step.as_millis());

    println!("Oblivious OA End... \nReordering the tape..");
    public_key.wrapping_neg_lwe(&mut nb_of_move);
    blind_rotate_assign(&nb_of_move, &mut tape.0, &public_key.fourier_bsk);
    tape.print(&private_key,&ctx);

    if DEBUG {
        print!("New Tape : ");
        tape.print(&private_key, &ctx);
    }
    // }

}

pub fn select_write(
    public_key: &PublicKey,
    ctx: &Context,
    storage0: &mut LweCiphertext<Vec<u64>>,
    storage1: &mut LweCiphertext<Vec<u64>>,
    storage2: &mut LweCiphertext<Vec<u64>>,
    storage3: &mut LweCiphertext<Vec<u64>>,
    storage4: &mut LweCiphertext<Vec<u64>>,
    state:&LweCiphertext<Vec<u64>>,
    ct_instruction_mul_unit: &Vec<LUT>,


)->LweCiphertext<Vec<u64>> {
    //add
    let mut storage4_add = public_key.allocate_and_trivially_encrypt_lwe(0,&ctx);
    lwe_ciphertext_add(&mut storage4_add,&storage4, &storage0);
    lwe_ciphertext_add_assign(&mut storage4_add, &storage2);


    //mul
    let mut storage4_mul = public_key.blind_matrix_access(&ct_instruction_mul_unit,&storage0,&storage3,&ctx);
    lwe_ciphertext_add_assign(&mut storage4_mul,&storage4);
    let storage4 = public_key.blind_matrix_access(&ct_instruction_mul_unit,&storage1,&storage2,&ctx);
    lwe_ciphertext_add_assign(&mut storage4_mul,&storage4);


    //obliviousness
    let acc = vec![storage4_add,storage4_mul];
    let ct_acc =LUT::from_vec_of_lwe(acc,&public_key,&ctx);
    let res_pir = public_key.blind_array_access(&state,&ct_acc,&ctx);
    res_pir
}

pub fn store_read_cell_LUT_OA(
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
    let ct_acc =LUT::from_vec_of_lwe(acc,&public_key,&ctx);

    let res_pir_1 = public_key.blind_array_access(&state,&ct_acc,&ctx);

    let mut stateplustwo = public_key.allocate_and_trivially_encrypt_lwe(2,&ctx);
    lwe_ciphertext_add_assign(&mut stateplustwo,&state);
    let res_pir_2 = public_key.blind_array_access(&stateplustwo,&ct_acc,&ctx);

    (res_pir_2,res_pir_1)
}

fn encode_instruction_add(
    ctx: &Context
) -> (Vec<Vec<u64>>)
{
    let mut result_ten = Vec::new();

    for i in 0..ctx.message_modulus().0 {
        let mut line_ten = Vec::new();

        for j in 0..ctx.message_modulus().0{
            let iplusj = i.clone()+j ;
            line_ten.push((iplusj.to_owned() as u64)/ctx.message_modulus().0 as u64);

        }
        result_ten.push(line_ten);
    }

    (result_ten)
}
fn encode_instruction_mul(
    ctx: &Context
) -> (Vec<Vec<u64>>,Vec<Vec<u64>>)
{
    let mut result_unit = Vec::new();
    let mut result_ten = Vec::new();

    for i in 0..ctx.message_modulus().0 {
        let mut line_unit = Vec::new();
        let mut line_ten = Vec::new();

        for j in 0..ctx.message_modulus().0{
            let itimej = i.clone()*j ;
            line_unit.push((itimej as u64)%ctx.message_modulus().0 as u64) ;
            line_ten.push((itimej.to_owned() as u64)/ctx.message_modulus().0 as u64);

        }
        result_unit.push(line_unit);
        result_ten.push(line_ten);
    }

    (result_unit,result_ten)
}

fn encode_instruction_position_OA(
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

pub fn write_new_cell_content_OA(
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

pub fn change_head_position_OA(
    tape: &mut LUT,
    instruction_change: u64,
    ct_instruction_position: &LUT,
    public_key: &PublicKey,
    private_key: &PrivateKey,
    nb_of_move : &mut LweCiphertext<Vec<u64>>,
    mut ctx: &mut Context,
)
{
    let ct_0=private_key.allocate_and_encrypt_lwe(instruction_change,&mut ctx);
    let position_change = public_key.blind_array_access(&ct_0, ct_instruction_position, &ctx);
    if DEBUG {
        private_key.debug_lwe("position_change", &position_change, &ctx); //column
    }
    lwe_ciphertext_add_assign(nb_of_move, &position_change);
    blind_rotate_assign(&position_change, &mut tape.0, &public_key.fourier_bsk);

}

pub fn read_cell_content(
    tape: &LUT,
    public_key: &PublicKey,
    ctx: &Context,
) -> LweCiphertext<Vec<u64>>
{
    let mut ct_0 = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    trivially_encrypt_lwe_ciphertext(&mut ct_0, Plaintext(ctx.full_message_modulus() as u64));
    let cell_content = public_key.blind_array_access(&ct_0, &tape, &ctx);

    return cell_content;
}




