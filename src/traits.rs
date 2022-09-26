use franklin_crypto::bellman::Engine;

#[derive(Clone, PartialEq, Eq)]
pub enum Sbox {
    Alpha(u64),
    AlphaInverse(Vec<u64>, u64),
}

impl std::fmt::Debug for Sbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alpha(alpha) => write!(f, "sbox x^{}", alpha),
            Self::AlphaInverse(vec, alpha) => write!(f, "inverse sbox [u64; {}] for x^{}", vec.len(), alpha),
        }
    }
}

pub trait HashParams<E: Engine, const RATE: usize, const WIDTH: usize>:
    Clone + Send + Sync
{
    #[inline]
    fn allows_specialization(&self) -> bool {
        false
    }
    fn constants_of_round(&self, round: usize) -> &[E::Fr; WIDTH];
    fn mds_matrix(&self) -> &[[E::Fr; WIDTH]; WIDTH];
    fn number_of_full_rounds(&self) -> usize;
    fn number_of_partial_rounds(&self) -> usize;
    fn alpha(&self) -> &Sbox;
    fn alpha_inv(&self) -> &Sbox;
}
