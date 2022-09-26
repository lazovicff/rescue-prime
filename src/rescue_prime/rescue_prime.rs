use crate::common::matrix::mmul_assign;
use crate::common::sbox::sbox;
use crate::traits::HashParams;
use franklin_crypto::bellman::pairing::ff::Field;
use franklin_crypto::bellman::pairing::Engine;
use super::params::RescuePrimeParams;

/// Receives inputs whose length `known` prior(fixed-length).
/// Also uses custom domain strategy which basically sets value of capacity element to
/// length of input and applies a padding rule which makes input size equals to multiple of
/// rate parameter.
/// Uses pre-defined state-width=3 and rate=2.
pub fn rescue_prime_hash<E: Engine, const L: usize>(input: &mut [E::Fr; 3]) -> [E::Fr; 3] {
    const WIDTH: usize = 3;
    const RATE: usize = 2;

    let params = RescuePrimeParams::<E, RATE, WIDTH>::default();
    rescue_prime_round_function(&params, input);
	*input
}


pub(crate) fn rescue_prime_round_function<
    E: Engine,
    P: HashParams<E, RATE, WIDTH>,
    const RATE: usize,
    const WIDTH: usize,
>(
    params: &P,
    state: &mut [E::Fr; WIDTH],
) {
	println!("Rescue Prime Full Rounds: {}", params.number_of_full_rounds() - 1);
    for round in 0..params.number_of_full_rounds() - 1 {
        // sbox alpha
        sbox::<E>(params.alpha(), state);
        // mds
        mmul_assign::<E, WIDTH>(&params.mds_matrix(), state);

        // round constants
        state
            .iter_mut()
            .zip(params.constants_of_round(round).iter())
            .for_each(|(s, c)| s.add_assign(c));
        // sbox alpha inv
        sbox::<E>(params.alpha_inv(), state);

        // mds
        mmul_assign::<E, WIDTH>(&params.mds_matrix(), state);

        // round constants
        state
            .iter_mut()
            .zip(params.constants_of_round(round + 1).iter())
            .for_each(|(s, c)| s.add_assign(c));
    }
}
