pub struct Parameters {
    root_security_zk: u16,
    root_security_soundness: u16,
    hash_to_prime_bits: u16, // μ
    field_size_bits: u16, // ν
}

quick_error! {
    #[derive(Debug)]
    pub enum ParametersError {
        InvalidParameters {}
    }
}

impl Parameters {
    pub fn from_security_level(security_level: u16) -> Result<Parameters, ParametersError> {

        let parameters = Parameters {
            root_security_zk: security_level - 3,
            root_security_soundness: security_level - 2,
            field_size_bits: 2*security_level,
            hash_to_prime_bits: 2*security_level - 2,
        };

        Ok(parameters)
    }

    pub fn valid(&self) -> Result<(), ParametersError> {
        let d = 1 + (self.root_security_zk + self.root_security_soundness + 2)/self.hash_to_prime_bits;
        if d*self.hash_to_prime_bits + 2 <= self.field_size_bits {
            Ok(())
        } else {
            Err(ParametersError::InvalidParameters)
        }
    }
}
