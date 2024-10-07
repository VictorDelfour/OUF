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

    // Generate the crypto context
    let param = PARAM_MESSAGE_3_CARRY_0;
    let mut ctx = Context::from(param);
    let private_key = PrivateKey::new(&mut ctx);
    let public_key = private_key.get_public_key();
    a();
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

pub fn store_read_cell(
    public_key: &PublicKey,
    ctx: &Context,
    cell_content: &LweCiphertext<Vec<u64>>,
    storage:&LweCiphertext<Vec<u64>>,
    state:&LweCiphertext<Vec<u64>>,
    ct_instruction_storage: &Vec<LUT>,

) -> (LweCiphertext<Vec<u64>>,LweCiphertext<Vec<u64>>){
    let storage_index = public_key.blind_matrix_access(&ct_instruction_storage, &state, &cell_content, &ctx);
    let mut vector= Vec::new();
    vector =vec![storage.to_owned(),cell_content.to_owned(),cell_content.to_owned(),storage.to_owned()];
    let accumulator = LUT::from_vec_of_lwe(vector, public_key, ctx);
    let storage = public_key.blind_array_access(&storage_index, &accumulator,  &ctx);
    return (storage,storage_index)
}


pub fn change_head_position(
    tape: &mut LUT,
    cell_content: &LweCiphertext<Vec<u64>>,
    state: &LweCiphertext<Vec<u64>>,
    ct_instruction_position: &Vec<LUT>,
    public_key: &PublicKey,
    ctx: &Context,
    nb_of_move : &mut LweCiphertext<Vec<u64>>,
    private_key : &PrivateKey
)
{

    let position_change = public_key.blind_matrix_access(&ct_instruction_position,&state , &cell_content, &ctx);
    if DEBUG {
    private_key.debug_lwe("(P) next move = ", &position_change, ctx);
    }
    lwe_ciphertext_add_assign(nb_of_move, &position_change);
    blind_rotate_assign(&position_change, &mut tape.0, &public_key.fourier_bsk);

}



fn encode_instruction_add(
    ctx: &Context
) -> (Vec<Vec<u64>>,Vec<Vec<u64>>)
{
    let mut result_unit = Vec::new();
    let mut result_ten = Vec::new();

    for i in 0..ctx.message_modulus().0 {
        let mut line_unit = Vec::new();
        let mut line_ten = Vec::new();

        for j in 0..ctx.message_modulus().0{
            let iplusj = i.clone()+j ;
            line_unit.push((iplusj as u64)%ctx.message_modulus().0 as u64);
            line_ten.push((iplusj.to_owned() as u64)/ctx.message_modulus().0 as u64);

        }
        result_unit.push(line_unit);
        result_ten.push(line_ten);
    }

    (result_unit,result_ten)
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




