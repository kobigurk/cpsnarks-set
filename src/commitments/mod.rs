//! Implements integer and Pedersen commitments.

use rug::Integer;

pub mod integer;
pub mod pedersen;

quick_error! {
    #[derive(Debug)]
    pub enum CommitmentError {
        WrongOpening {}
        IntegerTooBig {}
        ConversionError(err: std::io::Error) {
            from()
        }
    }
}

pub trait Commitment {
    type Instance;

    fn commit(
        &self,
        value: &Integer,
        randomness: &Integer,
    ) -> Result<Self::Instance, CommitmentError>;
    fn open(
        &self,
        commitment: &Self::Instance,
        value: &Integer,
        randomness: &Integer,
    ) -> Result<(), CommitmentError>;
}
