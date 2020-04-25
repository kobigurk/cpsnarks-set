//! Channels provide a way for protocol to act as interactive protocol.
//!
//! Each protocol defines the messages the prover and verifiers send, such that
//! the prover receives a verifier channel and the prover receives a verifier
//! channel.
use crate::utils::curve::CurveError;
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
        CurveError(e: CurveError) {
            from()
        }
    }
}
