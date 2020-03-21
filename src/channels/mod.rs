pub mod root;
pub mod modeq;
pub mod range;

quick_error! {
    #[derive(Debug)]
    pub enum ChannelError {
        CouldNotSend {}
    }
}