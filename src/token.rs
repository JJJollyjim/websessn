/// Wraps the jsonwebtoken library to enforce session timeouts.
///
/// We retain jsonwebtoken's default 60-second fudge factor to allow for clock skew.

use std::time::{Duration, UNIX_EPOCH, SystemTime};
use jsonwebtoken as jwt;
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use lazy_static::lazy_static;

#[derive(Serialize, Deserialize)]
struct Claims<T> {
    exp: u64,
    nbf: u64,
    inner: T,
}

// Internal function which allows specifying the current time (meaning we can test it)
fn encode_internal<T: Serialize>(inner: T, length: Duration, ek: &jwt::EncodingKey, current_time_since_epoch: Duration) -> String {
    let claims = Claims {
        nbf: current_time_since_epoch.as_secs(),
        exp: (current_time_since_epoch + length).as_secs(),
        inner: inner,
    };

    jwt::encode(&jwt::Header::default(), &claims, ek).expect("jwt encoding failed")
}

pub fn encode<T: Serialize>(inner: T, length: Duration, ek: &jwt::EncodingKey) -> String {
    encode_internal(inner, length, ek, SystemTime::now().duration_since(UNIX_EPOCH).expect("pretty sure rust hasn't been invented yet..."))
}

lazy_static! {
    static ref VALIDATION: jwt::Validation = {
        let mut validation = jwt::Validation::default();
        validation.set_required_spec_claims(&["nbf", "exp"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation
    };
}

pub fn decode<'de, T: DeserializeOwned>(token: &str, dk: &jwt::DecodingKey) -> Result<T, jwt::errors::Error> {
    jwt::decode::<Claims<T>>(token, dk, &VALIDATION).map(|x| x.claims.inner)
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_token_lib() {
        let secret = b"secret";
        let ek = jwt::EncodingKey::from_secret(secret);
        let dk = jwt::DecodingKey::from_secret(secret);

        let expiry = Duration::from_secs(300);

        let now: Duration = SystemTime::now().duration_since(UNIX_EPOCH).expect("pretty sure rust hasn't been invented yet...");

        assert_eq!(decode::<String>(&encode("superadmin".to_string(), expiry, &ek), &dk).expect("currently-valid token should be accepted"), "superadmin", "token data should roundtrip");
        // or, equivalently...
        assert_eq!(decode::<String>(&encode_internal("superadmin".to_string(), expiry, &ek, now), &dk).expect("currently-valid token should be accepted"), "superadmin", "token data should roundtrip");

        // created 10 minutes ago, so should have expired 5 minutes ago
        assert!(decode::<String>(&encode_internal("superadmin".to_string(), expiry, &ek, now - Duration::from_secs(10*60)), &dk).is_err(), "expired token should not be accepted");
        // created in 5 minutes, so shouldn't be valid until then
        assert!(decode::<String>(&encode_internal("superadmin".to_string(), expiry, &ek, now + Duration::from_secs(5*60)), &dk).is_err(), "future token should not be accepted");
    }
}
