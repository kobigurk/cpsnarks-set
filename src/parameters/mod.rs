use crate::utils::curve::Field;
use std::fmt;

#[derive(Clone, Debug)]
pub struct Parameters {
    pub security_level: u16,
    pub security_zk: u16,
    pub security_soundness: u16,
    pub hash_to_prime_bits: u16, // μ
    pub field_size_bits: u16,    // ν
}

impl fmt::Display for Parameters {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Parameters(𝜆={} (security level), 𝜆_s={} (soundness security), 𝜆_z={} (zero-knowledge security), μ={} (hash-to-prime/range bits), ν={} (field size bits)", 
            self.security_level,
            self.security_zk,
            self.security_soundness,
            self.hash_to_prime_bits,
            self.field_size_bits,
        )
    }
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
            security_level,
            security_zk: security_level - 3,
            security_soundness: security_level - 2,
            field_size_bits: 2 * security_level,
            hash_to_prime_bits: 2 * security_level - 2,
        };

        parameters.is_valid()?;
        Ok(parameters)
    }

    pub fn from_curve<P: Field>() -> Result<(Parameters, u16), ParametersError> {
        let field_size_bits = P::size_in_bits() as u16;
        let security_level = field_size_bits / 2;
        let parameters = Parameters {
            security_level,
            security_zk: security_level - 3,
            security_soundness: security_level - 2,
            field_size_bits,
            hash_to_prime_bits: 2 * security_level - 2,
        };

        parameters.is_valid()?;
        Ok((parameters, security_level))
    }

    // based on page 33 in https://eprint.iacr.org/2019/1255.pdf
    pub fn from_curve_and_small_prime_size<P: Field>(
        prime_bits_min: u16,
        prime_bits_max: u16,
    ) -> Result<(Parameters, u16), ParametersError> {
        let field_size_bits = P::size_in_bits() as u16;
        let security_level = field_size_bits / 2;
        let derived = (|| {
            for c in 0..security_level {
                let security_soundness_zk = ((2 * security_level - 2 - c) - 2) / 2;
                for i in prime_bits_min..=prime_bits_max {
                    if i <= 2 * security_level - 2 - c && (2 * security_level - 2 - c) % i >= i - c
                    {
                        return Some((i, security_soundness_zk));
                    }
                }
            }

            return None;
        })();
        let (prime_bits, security_soundness_zk) =
            derived.ok_or(ParametersError::InvalidParameters)?;

        let parameters = Parameters {
            security_level,
            security_zk: security_soundness_zk,
            security_soundness: security_soundness_zk,
            field_size_bits,
            hash_to_prime_bits: prime_bits,
        };

        parameters.is_valid()?;
        Ok((parameters, security_level))
    }

    pub fn is_valid(&self) -> Result<(), ParametersError> {
        // See page 32 in https://eprint.iacr.org/2019/1255.pdf
        let d = 1 + (self.security_zk + self.security_soundness + 2) / self.hash_to_prime_bits;
        if d * self.hash_to_prime_bits + 2 <= self.field_size_bits {
            Ok(())
        } else {
            Err(ParametersError::InvalidParameters)
        }
    }
}

#[cfg(test)]
mod test {
    use super::Parameters;

    #[test]
    fn test_valid_for_128() {
        let params = Parameters::from_security_level(128).unwrap();
        params.is_valid().unwrap();
    }

    #[cfg(all(test, feature = "zexe"))]
    #[test]
    fn test_valid_for_some_fields() {
        let params_with_security_level =
            Parameters::from_curve::<algebra::bls12_381::Fr>().unwrap();
        println!(
            "security level: {}, params: {:#?}",
            params_with_security_level.1, params_with_security_level.0
        );
        params_with_security_level.0.is_valid().unwrap();
    }
}
