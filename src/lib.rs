//! This library implements the protocols from [Zero-Knowledge Proofs for Set
//! Membership: Efficient, Succinct,
//! Modular](https://eprint.iacr.org/2019/1255).
//!
//! `CPMemRSA`, `CPMemRSAPrm`, `CPNonMemRSA`, `CPNonMemRSAPrm`, with RSA and
//! class groups available as groups of unknown order to be used for the root
//! protocol, RSA available for the coprime protocol and LegoGroth16 and
//! Bulletproofs available for the hash-to-prime and range proof protocols. The
//! hash-to-prime uses Blake2s.
//!
//! The library is designed in a modular fashion - each subprotocol (root,
//! coprime, modeq and hash_to_prime) implements generic prove and verify
//! functions, a channel for the interactive proof abstraction and a transcript
//! for the non-interactive proof instantiation. The hash-to-prime protocols
//! also define a setup function.
//!
//! The higher level protocols (membership, nonmembership) define setup, prove
//! and verify functions and compose the subprotocols into end-to-end protocols
//! ready to use.

#[macro_use]
extern crate quick_error;

pub mod channels;
pub mod commitments;
pub mod parameters;
pub mod protocols;
pub mod transcript;
pub mod utils;
