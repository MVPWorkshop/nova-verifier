use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum CurveName {
    Pallas,
    Vesta,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Z0Values {
    ZERO = 0,
    ONE = 1,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Pubs {
    pub first_curve: CurveName,
    pub num_of_steps: usize,
    pub z0_primary: Z0Values,
    pub z0_secondary: Z0Values,
}
