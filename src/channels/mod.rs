pub mod membership;
pub mod nonmembership;

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
