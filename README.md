# Rotkeappchen-rs

Crate for generating stateless and rotating verification codes,
following the [Rotkeappchen proposal](https://github.com/DISTREAT/Rotkeappchen).

Rotkeappchen verifies email addresses, CAPTCHA challenges, and timed access tokens.

## Example

This crate generates time-based codes that are unique for each client:

```rs
use rotkeappchen::Rotkeappchen;

let rot = Rotkeappchen::default(b"secret", 60);  // 60 seconds
let code = rot.digest("client");

assert!(rot.is_valid("client", |digest| digest == code))
```
