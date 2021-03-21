use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use franklin_crypto::bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr};
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::constants;
use franklin_crypto::group_hash::{BlakeHasher, GroupHasher};
use rand::{chacha::ChaChaRng, Rng, SeedableRng};

use crate::common::utils::construct_mds_matrix;


#[derive(Debug, Clone)]
pub struct HasherParams<E: Engine> {
    pub rate: usize,
    pub state_width: usize,
    pub capacity: usize,
    pub security_level: usize,
    pub full_rounds: usize,
    pub partial_rounds: usize,
    round_constants: Vec<Vec<E::Fr>>,
    mds_matrix: Vec<Vec<E::Fr>>,
}

type H = BlakeHasher;

impl<E: Engine> HasherParams<E> {
    pub fn constants_of_round(&self, round: usize) -> &[E::Fr] {
        &self.round_constants[round]
    }

    pub fn round_constants(&self) -> &[Vec<E::Fr>] {
        &self.round_constants
    }
    pub fn mds_matrix(&self) -> &[Vec<E::Fr>] {
        &self.mds_matrix
    }

    fn compute_round_constants(&mut self, number_of_rounds_constants: usize, tag: &[u8]) {
        let mut round_constants = Vec::with_capacity(number_of_rounds_constants);
        let mut nonce = 0u32;
        let mut nonce_bytes = [0u8; 4];

        loop {
            (&mut nonce_bytes[0..4])
                .write_u32::<BigEndian>(nonce)
                .unwrap();
            let mut h = H::new(&tag[..]);
            h.update(constants::GH_FIRST_BLOCK);
            h.update(&nonce_bytes[..]);
            let h = h.finalize();
            assert!(h.len() == 32);

            let mut constant_repr = <E::Fr as PrimeField>::Repr::default();
            constant_repr.read_le(&h[..]).unwrap();

            if let Ok(constant) = E::Fr::from_repr(constant_repr) {
                if !constant.is_zero() {
                    round_constants.push(constant);
                }
            }

            if round_constants.len() == number_of_rounds_constants {
                break;
            }

            nonce += 1;
        }

        self.round_constants = round_constants
            .chunks_exact(self.state_width)
            .map(|chunk| chunk.to_vec())
            .collect();
    }

    fn compute_mds_matrix_for_poseidon(&mut self) {
        let rng = &mut init_rng_for_poseidon();
        self.compute_mds_matrix(rng)
    }

    fn compute_mds_matrix_for_rescue(&mut self) {
        let rng = &mut init_rng_for_rescue();
        self.compute_mds_matrix(rng)
    }

    fn compute_mds_matrix<R: Rng>(&mut self, rng: &mut R) {
        self.mds_matrix = construct_mds_matrix::<E, _>(self.state_width, rng)
            .chunks_exact(self.state_width)
            .map(|chunk| chunk.to_vec())
            .collect();
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

fn init_rng_for_poseidon() -> ChaChaRng {
    let tag = b"ResM0003"; // TODO: change tag?
    let mut h = H::new(&tag[..]);
    h.update(constants::GH_FIRST_BLOCK);
    let h = h.finalize();
    assert!(h.len() == 32);
    let mut seed = [0u32; 8];

    for (i, chunk) in h.chunks_exact(4).enumerate() {
        seed[i] = (&chunk[..])
            .read_u32::<BigEndian>()
            .expect("digest is large enough for this to work");
    }

    ChaChaRng::from_seed(&seed)
}