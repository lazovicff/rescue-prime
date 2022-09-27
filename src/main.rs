use franklin_crypto::bellman::bn256::{Bn256, Fr};
use franklin_crypto::bellman::Field;
pub mod common;
mod rescue_prime;
mod traits;

fn main() {
	let mut inputs = [Fr::zero(); 10];
	rescue_prime::rescue_prime_hash::<Bn256, 10, 9>(&mut inputs);
	print!("{:?}", inputs);
}