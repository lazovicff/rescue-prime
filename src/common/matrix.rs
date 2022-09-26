use franklin_crypto::bellman::{Engine, Field};

// Multiplies matrix with a vector  and assigns result into same vector.
pub(crate) fn mmul_assign<E: Engine, const DIM: usize>(
    matrix: &[[E::Fr; DIM]; DIM],
    vector: &mut [E::Fr; DIM],
) {
    // [M]xv
    let mut result = [E::Fr::zero(); DIM];
    for col in 0..DIM {
        result[col] = crate::common::utils::scalar_product::<E>(vector, &matrix[col]);
    }
    vector.copy_from_slice(&result[..]);
}
