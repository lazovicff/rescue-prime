use byteorder::{BigEndian, ReadBytesExt};
use franklin_crypto::bellman::pairing::ff::Field;
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::constants;
use franklin_crypto::group_hash::{BlakeHasher, GroupHasher};
use rand::{chacha::ChaChaRng, Rng, SeedableRng};

use crate::common::utils::construct_mds_matrix;

#[derive(Debug, Clone)]
pub struct InnerHashParameters<E: Engine, const RATE: usize, const WIDTH: usize> {
    pub security_level: usize,
    pub full_rounds: usize,
    pub partial_rounds: usize,
    pub round_constants: Vec<[E::Fr; WIDTH]>,
    pub mds_matrix: [[E::Fr; WIDTH]; WIDTH],
}

type H = BlakeHasher;

impl<E: Engine, const RATE: usize, const WIDTH: usize> InnerHashParameters<E, RATE, WIDTH> {
    pub fn new(security_level: usize, full_rounds: usize, partial_rounds: usize) -> Self {
        assert_ne!(RATE, 0);
        assert_ne!(WIDTH, 0);
        assert_ne!(full_rounds, 0);

        Self {
            security_level,
            full_rounds,
            partial_rounds,
            round_constants: vec![[E::Fr::zero(); WIDTH]],
            mds_matrix: [[E::Fr::zero(); WIDTH]; WIDTH],
        }
    }

    pub fn constants_of_round(&self, round: usize) -> [E::Fr; WIDTH] {
        self.round_constants[round]
    }

    pub fn round_constants(&self) -> &[[E::Fr; WIDTH]] {
        &self.round_constants
    }

    pub fn mds_matrix(&self) -> &[[E::Fr; WIDTH]; WIDTH] {
        &self.mds_matrix
    }

    pub(crate) fn compute_mds_matrix_for_rescue(&mut self) {
        let rng = &mut init_rng_for_rescue();
        self.compute_mds_matrix(rng)
    }

    fn compute_mds_matrix<R: Rng>(&mut self, rng: &mut R) {
        self.mds_matrix = construct_mds_matrix::<E, _, WIDTH>(rng);
    }
}

fn init_rng_for_rescue() -> ChaChaRng {
    let tag = b"ResM0003";
    let mut h = H::new(&tag[..]);
    h.update(constants::GH_FIRST_BLOCK);
    let h = h.finalize();
    assert!(h.len() == 32);
    let mut seed = [0u32; 8];
    for i in 0..8 {
        seed[i] = (&h[..])
            .read_u32::<BigEndian>()
            .expect("digest is large enough for this to work");
    }

    ChaChaRng::from_seed(&seed)
}
