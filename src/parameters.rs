//! Derives secure parameters given a desired security level or curve parameters.

use crate::utils::curve::Field;
use std::fmt;
#[derive(Clone, Debug)]
pub struct Parameters {
    /// Desired security level. It's an upper bound rather than the final
    /// security level.
    pub security_level: u16,
    /// Zero-knowledge security.
    pub security_zk: u16,
    /// Soundness security.
    pub security_soundness: u16,
    /// Size of the elements in the set, as a result of the hash-to-prime or
    /// just size in case of prime elements.
    pub hash_to_prime_bits: u16, // μ
    /// Size of the field the element are taken from.
    pub field_size_bits: u16, // ν
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
    /// Derive parameters for a desired security level.
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

    /// Derive parameters based on a curve.
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

    /// Derive parameters based on a curve and desired small prime bit size.
    /// Based on section 4.5 of the paper.
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

            None
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

    /// Check the parameters are valid according to section 4.5 of
    /// the paper.
    pub fn is_valid(&self) -> Result<(), ParametersError> {
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

    #[cfg(all(test, feature = "arkworks"))]
    #[test]
    fn test_valid_for_some_fields() {
        let params_with_security_level = Parameters::from_curve::<ark_bls12_381::Fr>().unwrap();
        println!(
            "security level: {}, params: {:#?}",
            params_with_security_level.1, params_with_security_level.0
        );
        params_with_security_level.0.is_valid().unwrap();
    }
}
