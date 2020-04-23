pub mod hash_to_prime;
pub mod membership;
pub mod modeq;
pub mod nonmembership;
pub mod root;

use std::cell::{BorrowError, BorrowMutError};

quick_error! {
    #[derive(Debug)]
    pub enum ChannelError {
        CouldNotSend {}
        CouldNotBorrow(e: BorrowError) {
            from()
        }
        CouldNotBorrowMut(e: BorrowMutError) {
            from()
        }
    }
}
