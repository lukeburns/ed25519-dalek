# redschnorr

An experimental Rust implementation of Schnorr signatures based on the [Ristretto prime order group](https://doc.dalek.rs/curve25519_dalek/ristretto/), built on [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) and a fork of [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek), primarily for my own learning / interest.

It's insecure and not meant to be used. **Don't use this** unless you are just learning / experimenting. [DAVROS](https://github.com/isislovecruft/davros) is the repository to watch for a real use implementation of Schnorr signatures based on Ristretto.

Also, thanks to the [dalek-cryptography](https://github.com/dalek-cryptography) folks. Their code is super readable and well documented.

**Are you considering implementing something on this?** *Really, don't.* Follow the development of [DAVROS](https://github.com/isislovecruft/davros).

## Why not ed25519? [Why ristretto?](https://ristretto.group/why_ristretto.html)

ed25519 signatures are "malleable" because the scheme is constructed over a non-prime order group. This can [create vulnerabilities](https://ristretto.group/why_ristretto.html#pitfalls-of-a-cofactor) in some crypto protocols. Ristretto is a prime order group constructed over the Edwards 25519 curve.

Implementing Schnorr signature schemes in the Ristretto group also allows one to preserve mathematical properties that are [lost](https://ristretto.group/why_ristretto.html#why-cant-we-just-multiply-by-the-cofactor) in the ed25519 scheme. This allows one to implement more complex protocols on top, e.g. [hierarchical key derivation](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
