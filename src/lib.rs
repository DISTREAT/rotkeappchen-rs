use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct Rotkeappchen<'a> {
    /// Shared secret, protecting against calculability by a third party
    pub shared_secret: &'a [u8],
    /// Time frame in seconds, after which the digest will rotate
    pub persist_rotation_seconds: usize,
    /// Verify against last n rotations
    pub lookback_window_size: usize,
    /// Function used for generating the digest
    pub hashing_function: fn(&[u8]) -> Vec<u8>,
}

impl<'a> Rotkeappchen<'a> {
    fn default_hashing_function(data: &[u8]) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        hasher.finalize().as_bytes().to_vec()
    }

    pub fn default(shared_secret: &'a [u8], persist_rotation_seconds: usize) -> Self {
        Self {
            shared_secret,
            persist_rotation_seconds,
            lookback_window_size: 1,
            hashing_function: Self::default_hashing_function,
        }
    }

    /// Calculate the digest for the provided offset
    pub fn calculate_digest(&self, salt: &str, offset: isize) -> Vec<u8> {
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime is out of sync") // highly unlikely scenario (time < UNIX epoch)
            .as_secs();
        let current_rotation = unix_time / self.persist_rotation_seconds as u64;

        (self.hashing_function)(
            &[
                salt.as_bytes(),
                self.shared_secret,
                &(current_rotation as i64 + offset as i64).to_be_bytes(),
            ]
            .concat(),
        )
    }

    /// Return the current digest
    pub fn digest(&self, salt: &str) -> Vec<u8> {
        self.calculate_digest(salt, 0)
    }

    /// Return the validity of a digest
    pub fn is_valid(&self, salt: &str, custom_check: impl Fn(Vec<u8>) -> bool) -> bool {
        (0..self.lookback_window_size + 1)
            .map(|index| -(index as isize))
            .map(|offset| custom_check(self.calculate_digest(salt, offset)))
            .any(|result| result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn basic_verify_digest() {
        let rot = Rotkeappchen::default(b"secret", 10);
        let code = rot.digest("client");
        assert!(rot.is_valid("client", |digest| digest == code))
    }

    #[test]
    fn different_secrets() {
        let rot1 = Rotkeappchen::default(b"secret1", 10);
        let rot2 = Rotkeappchen::default(b"secret2", 10);
        let code1 = rot1.digest("client");
        let code2 = rot2.digest("client");
        assert!(code1 != code2)
    }

    #[test]
    fn different_salts() {
        let rot1 = Rotkeappchen::default(b"secret", 10);
        let rot2 = Rotkeappchen::default(b"secret", 10);
        let code1 = rot1.digest("client1");
        let code2 = rot2.digest("client2");
        assert!(code1 != code2)
    }

    #[test]
    fn realistic_timing() {
        let rot = Rotkeappchen::default(b"secret", 2);
        let code = rot.digest("client");
        sleep(Duration::from_secs(2));
        assert!(rot.is_valid("client", |digest| digest == code))
    }

    #[test]
    fn digest_expiration() {
        let rot = Rotkeappchen::default(b"secret", 1);
        let code = rot.digest("client");
        sleep(Duration::from_secs(2));
        assert!(!rot.is_valid("client", |digest| digest == code))
    }
}
