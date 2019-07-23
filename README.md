# Nettle

This is a package which wraps the
"[nettle](https://www.lysator.liu.se/~nisse/nettle/)"
(and "hogweed") cryptographic libraries, making them easy to use from
Swift.

Currently, it supports the hash functions, and some of the asymmetric
cryptography algorithms. Support for the symmetric algorithms would be
nice, but I have not needed it yet; if you want to add that, I would
welcome any contributions.

## Goals

A Swift-y interface which is reasonably easy to use correctly.

The API should avoid leaking underlying types, such as GMP integers or
Nettle structures, without a good reason. Memory and state management
should seem normal to a Swift programmer.

The interface should otherwise roughly follow Nettle's.

When there are commonly accepted good defaults for parameters, they should be
provided.

## Non-Goals

There is no attempt to make different kinds of algorithms (*e.g.*, RSA
and ECDH) look similar.

This is not attempting to be a drop-in replacement for any other API.

I'm not attempting to provide obsolete algorithms (3DES, MD5, arguably DSA)
unless there's a particular need for them.

# Supported Nettle Features

- [X] Hash functions
- Cipher functions
  - [ ] Block ciphers
  - [ ] Cipher modes
  - [ ] AEAD
- Keyed Hash Functions
  - [X] HMAC
  - [ ] UMAC
  - [ ] CMAC
  - [ ] Poly1305
- Key Derivation Functions
  - [ ] HKDF
  - [ ] PBKDF2
- Public-key Algorithms
  - [X] RSA
  - [ ] DSA
  - [X] ECDSA
  - [ ] Curve25519
  - [ ] EdDSA
- [X] Yarrow
