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
fn generate_bubble_sort_functions(
    private_key: &PrivateKey,
    mut ctx: &mut Context,) -> Vec<Vec<LUT>> {
    let mut functions = Vec::new();

    let mut comp_sup = Vec::new();
    let mut comp_inf_eq = Vec::new();
    let mut mult = Vec::new();
    let mut add = Vec::new();
    let mut sub = Vec::new();
    let mut copy = Vec::new();


    for i in 0..ctx.message_modulus().0 {
        let mut line_comp_sup = Vec::new();
        let mut line_mult = Vec::new();
        let mut line_add = Vec::new();
        let mut line_sub = Vec::new();
        let mut line_copy = Vec::new();
        let mut line_comp_inf_eq = Vec::new();




        for j in 0..ctx.message_modulus().0{
            line_mult.push((((i.clone()*j.clone())as u64)%ctx.message_modulus().0 as u64) as u64);
            line_add.push((((i.clone()+j.clone()) as u64)%ctx.message_modulus().0 as u64) as u64);
            line_sub.push((((i.clone()-j.clone()) as u64)%ctx.message_modulus().0 as u64) as u64);
            line_comp_sup.push((i.clone()>j) as u64);
            line_copy.push((i.clone()) as u64);
            line_comp_inf_eq.push((i.clone()<=j) as u64);



        }
        comp_sup.push(line_comp_sup);
        mult.push(line_mult);
        add.push(line_add);
        sub.push(line_sub);
        copy.push(line_copy);
        comp_inf_eq.push(line_comp_inf_eq);

    }

    functions.push(private_key.encrypt_matrix(&mut ctx,&comp_sup));
    functions.push(private_key.encrypt_matrix(&mut ctx,&comp_inf_eq));
    functions.push(private_key.encrypt_matrix(&mut ctx,&mult));
    functions.push(private_key.encrypt_matrix(&mut ctx,&add));
    functions.push(private_key.encrypt_matrix(&mut ctx,&sub));
    functions.push(private_key.encrypt_matrix(&mut ctx,&copy));
    functions
}

fn generate_access_pattern_bubble_sort(
    private_key: &PrivateKey,
    mut ctx: &mut Context,
    nb_cells:u64)->Vec<LweCiphertext<Vec<u64>>>{
    let mut result = Vec::new();
    for i in 0..nb_cells-1{
        let mut j =i+1;
        while j>0 {
            result.push(3 + j.clone() - 1);
            result.push(3 + j.clone());
            result.push(0);

            result.push(3 + j.clone() - 1);
            result.push(3 + j.clone());
            result.push(1);

            result.push(3 + j.clone() - 1);
            result.push(0);
            result.push(0);

            result.push(3 + j.clone());
            result.push(1);
            result.push(1);

            result.push(0);
            result.push(1);
            result.push(2);

            result.push(3 + j.clone() - 1);
            result.push(0);
            result.push(0);

            result.push(3 + j.clone());
            result.push(1);
            result.push(1);

            result.push(0);
            result.push(1);
            result.push(0);

            result.push(2);
            result.push(2);
            result.push(3 + j.clone() - 1);

            result.push(0);
            result.push(0);
            result.push(3 + j.clone());

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

fn generate_function_selector_bubble_sort(
    private_key: &PrivateKey,
    mut ctx: &mut Context,
    nb_cells:u64)->Vec<LweCiphertext<Vec<u64>>>{
    let mut result = Vec::new();
    for i in 0..(((nb_cells-1)*nb_cells.clone())/2){
        result.push(0);
        result.push(1);
        result.push(2);
        result.push(2);
        result.push(3);
        result.push(4);
        result.push(4);
        result.push(3);
        result.push(5);
        result.push(5);
    }
    let mut result_encrypted = Vec::new();
    for i in result.clone(){
        result_encrypted.push(private_key.allocate_and_encrypt_lwe(i,&mut ctx));
    }
    // print!("selector : {:?}", result.clone());

    result_encrypted
}


fn evaluate_oa1(
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
    let result_acc =LUT::from_vec_of_lwe(storage,&public_key,&ctx);
    let result = public_key.blind_array_access(&selector,&result_acc,&ctx);
    result
}

fn oa1(){
    // Generate the crypto context
    let param = PARAM_MESSAGE_5_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = PrivateKey::new(&mut ctx);
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
    let mut tape = vec![0, 0, 0, 1,2];
    while tape.len() < ctx.message_modulus().0 {
        tape.push(0_u64);
    }
    let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);

    let nb_cells = 2;
    let selector = generate_function_selector_bubble_sort(&private_key, &mut ctx, nb_cells.clone());
    let data_access = generate_access_pattern_bubble_sort(&private_key,&mut ctx,nb_cells);
    let functions_storage = generate_bubble_sort_functions(&private_key,&mut ctx);



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



        //println!("étape 0 \n");

        change_head_position_oa(&mut tape,&data_access[3*step.clone()] , public_key, &private_key, &mut nb_of_move, &mut ctx);
        // private_key.debug_lwe("move1", &data_access[3*step.clone()], &ctx);
        //
        // let mut output = tape.clone();
        // public_key.wrapping_neg_lwe(&mut nb_of_move);
        // blind_rotate_assign(&nb_of_move, &mut output.0, &public_key.fourier_bsk);
        // output.print(&private_key,&ctx);


        //println!("étape 1 \n");

        let mut input1 = read_cell_content(&tape, &public_key, &ctx);
        change_head_position_oa(&mut tape, &data_access[3*step.clone()+1], public_key, &private_key, &mut nb_of_move, &mut ctx);

        // private_key.debug_lwe("move2", &data_access[1+3*step.clone()], &ctx);

        // let mut output = tape.clone();
        // public_key.wrapping_neg_lwe(&mut nb_of_move);
        // blind_rotate_assign(&nb_of_move, &mut output.0, &public_key.fourier_bsk);
        // output.print(&private_key,&ctx);

        //println!("étape 2 \n");

        let mut input2 = read_cell_content(&tape, &public_key, &ctx);
        change_head_position_oa(&mut tape, &data_access[3*step.clone()+2], public_key, &private_key, &mut nb_of_move, &mut ctx);




        //println!("étape 3 \n");
        let cell_content = read_cell_content(&tape, &public_key, &ctx);
        let mut result = evaluate_oa1(public_key, &ctx, &input1, &input2, &selector[step.clone()], &functions_storage);
        write_new_cell_content_oa(&mut tape, &cell_content, &public_key, &ctx, &mut result);

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
    println!("temps oblivious operation :{}",elapsed_time_step.as_millis());

    //println!("Oblivious oa End... \nReordering the tape..");
    public_key.wrapping_neg_lwe(&mut nb_of_move);
    blind_rotate_assign(&nb_of_move, &mut tape.0, &public_key.fourier_bsk);
    tape.print(&private_key,&ctx);
    // }

}



// fn oa(){
//     // Generate the crypto context
//     let param = PARAM_MESSAGE_4_CARRY_0;
//     let mut ctx = Context::from(param);
//     let private_key = PrivateKey::new(&mut ctx);
//     let public_key = private_key.get_public_key();
//
//
//     println!("Key generated");
//
//     let mut output_file_oa = OpenOptions::new()
//         .create(true)
//         .append(true)
//         .open("resultats_oa.txt")
//         .expect("Impossible d'ouvrir le fichier");
//
//     // En tête
//     writeln!(output_file_oa, "execution,params,time").expect("Impossible d'écrire dans le fichier");
//
//     // for i in 0..25 {
//
//     //creation of tape
//     let mut tape = vec![1, 2, 0, 3];
//     while tape.len() < ctx.message_modulus().0 {
//         tape.push(0_u64);
//     }
//     println!("Tape : {:?}", tape);
//     let mut tape = LUT::from_vec(&tape, &private_key, &mut ctx);
//     println!("Tape Encrypted");
//
//
//     // add
//     // let mut instruction_position =  vec![1,2,2,-3,-2,4,0,0];
//     // let mut state = public_key.allocate_and_trivially_encrypt_lwe(0, &ctx);
//
//     //mul
//     // let mut instruction_position = vec![1, 2, 2, -2, -3, 1, 1, 2];
//     // let mut state = public_key.allocate_and_trivially_encrypt_lwe(1, &ctx);
//
//     let state = private_key.allocate_and_encrypt_lwe(1,&mut ctx);
//
//     let instruction_position = vec![0, 1, 1, 1, 2, -1];
//     let instruction_position = encode_instruction_position_oa(&instruction_position, &ctx);
//     let ct_instruction_position = LUT::from_vec(&instruction_position, &private_key, &mut ctx);
//
//     if DEBUG {
//         print!("instruction position : {:?}", instruction_position);
//     }
//
//     let instruction_add = encode_instruction_add(&ctx);
//     let (instruction_mul_unit,instruction_mul_ten) = encode_instruction_mul(&ctx);
//     let ct_instruction_add = private_key.encrypt_matrix(&mut ctx,&instruction_add);
//     let ct_instruction_mul_unit = private_key.encrypt_matrix(&mut ctx,&instruction_mul_unit);
//     let ct_instruction_mul_ten = private_key.encrypt_matrix(&mut ctx,&instruction_mul_ten);
//
//
//     println!("Instructions Encrypted");
//     let mut nb_of_move = public_key.allocate_and_trivially_encrypt_lwe(0, &ctx);
//
//     let start_time_total = Instant::now();
//
//     println!("étape 0 \n");
//     let start_time_step = Instant::now();
//
//     change_head_position_oa(&mut tape, 0, &ct_instruction_position, public_key, &private_key, &mut nb_of_move, &mut ctx);
//
//     if DEBUG {
//         print!("New Tape : ");
//         tape.print(&private_key, &ctx);
//     }
//     let elapsed_time_step = start_time_step.elapsed();
//     println!("temps etape0 :{}",elapsed_time_step.as_millis());
//
//     println!("étape 1 \n");
//     let start_time_step = Instant::now();
//
//     let mut storage0 = read_cell_content(&tape, &public_key, &ctx);
//     change_head_position_oa(&mut tape, 1, &ct_instruction_position, public_key, &private_key, &mut nb_of_move, &mut ctx);
//
//     let elapsed_time_step = start_time_step.elapsed();
//     println!("temps etape1 :{}",elapsed_time_step.as_millis());
//     if DEBUG {
//         print!("New Tape : ");
//         tape.print(&private_key, &ctx);
//         private_key.debug_lwe("storage0", &storage0, &ctx);
//     }
//
//     println!("étape 2 \n");
//     let start_time_step = Instant::now();
//
//     let mut storage1 = read_cell_content(&tape, &public_key, &ctx);
//     change_head_position_oa(&mut tape, 2, &ct_instruction_position, public_key, &private_key, &mut nb_of_move, &mut ctx);
//     let elapsed_time_step = start_time_step.elapsed();
//     println!("temps etape2 :{}",elapsed_time_step.as_millis());
//
//     if DEBUG {
//         print!("New Tape : ");
//         tape.print(&private_key, &ctx);
//     }
//
//     println!("étape 3 \n");
//     let start_time_step = Instant::now();
//
//     let mut storage2 = read_cell_content(&tape, &public_key, &ctx);
//     change_head_position_oa(&mut tape, 3, &ct_instruction_position, public_key, &private_key, &mut nb_of_move, &mut ctx);
//
//     let elapsed_time_step = start_time_step.elapsed();
//     println!("temps etape3 :{}",elapsed_time_step.as_millis());
//
//     if DEBUG {
//         print!("New Tape : ");
//         tape.print(&private_key, &ctx);
//     }
//
//
//
//     println!("étape 4 \n");
//     let start_time_step = Instant::now();
//
//     let mut storage3 = read_cell_content(&tape, &public_key, &ctx);
//     let (mut storage4, mut storage5) = store_read_cell_LUT_oa(
//         &public_key,
//         &ctx,
//         &storage1,
//         &storage3,
//         &state,
//         &ct_instruction_add,
//         &ct_instruction_mul_unit,
//         &ct_instruction_mul_ten);
//
//     change_head_position_oa(&mut tape, 4, &ct_instruction_position, public_key, &private_key, &mut nb_of_move, &mut ctx);
//
//     let elapsed_time_step = start_time_step.elapsed();
//     println!("temps etape4 :{}",elapsed_time_step.as_millis());
//
//     if DEBUG {
//         print!("New Tape : ");
//         tape.print(&private_key, &ctx);
//         private_key.debug_lwe("storage0", &storage0, &ctx);
//         private_key.debug_lwe("storage4", &storage4, &ctx);
//         private_key.debug_lwe("storage5", &storage5, &ctx);
//     }
//
//     println!("étape 5 \n");
//     let start_time_step = Instant::now();
//
//     let cell_content = read_cell_content(&tape, &public_key, &ctx);
//     write_new_cell_content_oa(&mut tape, &cell_content, &public_key, &ctx, &mut storage5);
//     change_head_position_oa(&mut tape, 5, &ct_instruction_position, public_key, &private_key, &mut nb_of_move, &mut ctx);
//
//     let elapsed_time_step = start_time_step.elapsed();
//     println!("temps etape5 :{}",elapsed_time_step.as_millis());
//
//     if DEBUG {
//         print!("New Tape : ");
//         tape.print(&private_key, &ctx);
//     }
//
//     println!("étape 6 \n");
//     let start_time_step = Instant::now();
//
//     let cell_content = read_cell_content(&tape, &public_key, &ctx);
//     let mut storage4 = select_write(
//         &public_key,
//         &ctx,
//         &mut storage0,
//         &mut storage1,
//         &mut storage2,
//         &mut storage3,
//         &mut storage4,
//         &state,
//         &ct_instruction_mul_unit,);
//
//     write_new_cell_content_oa(&mut tape, &cell_content, &public_key, &ctx, &mut storage4);
//
//     let elapsed_time_step = start_time_step.elapsed();
//     println!("temps etape6 :{}",elapsed_time_step.as_millis());
//
//     let elapsed_time_step = start_time_total.elapsed();
//     println!("temps oblivious operation :{}",elapsed_time_step.as_millis());
//
//     println!("Oblivious oa End... \nReordering the tape..");
//     public_key.wrapping_neg_lwe(&mut nb_of_move);
//     blind_rotate_assign(&nb_of_move, &mut tape.0, &public_key.fourier_bsk);
//     tape.print(&private_key,&ctx);
//
//     if DEBUG {
//         print!("New Tape : ");
//         tape.print(&private_key, &ctx);
//     }
//     // }
//
// }

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
    let ct_acc =LUT::from_vec_of_lwe(acc,&public_key,&ctx);

    let res_pir_1 = public_key.blind_array_access(&state,&ct_acc,&ctx);

    let mut stateplustwo = public_key.allocate_and_trivially_encrypt_lwe(2,&ctx);
    lwe_ciphertext_add_assign(&mut stateplustwo,&state);
    let res_pir_2 = public_key.blind_array_access(&stateplustwo,&ct_acc,&ctx);

    (res_pir_2,res_pir_1)
}

fn encode_instruction_add(
    ctx: &Context
) -> Vec<Vec<u64>>
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

    result_ten
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
    let mut ct_0 = LweCiphertext::new(0, ctx.small_lwe_dimension().to_lwe_size(), ctx.ciphertext_modulus());
    trivially_encrypt_lwe_ciphertext(&mut ct_0, Plaintext(ctx.full_message_modulus() as u64));
    let cell_content = public_key.blind_array_access(&ct_0, &tape, &ctx);

    return cell_content;
}




