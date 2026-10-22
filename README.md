# CryptoKit

A modular cryptographic toolkit for Perl. Provides password hashing, secure random password generation, ECC key management, hybrid encryption, and secure memory handling — each as an independent, lazily loaded submodule.

Built on [CryptX](https://metacpan.org/pod/CryptX) and [Crypt::Argon2](https://metacpan.org/pod/Crypt::Argon2), with security-critical version pins.

## Features

| Module | Purpose |
|---|---|
| `CryptoKit::Hash` | Argon2id password hashing with random salts |
| `CryptoKit::Password` | Cryptographically strong random password generation |
| `CryptoKit::Key` | ECC key generation, ECDSA sign/verify |
| `CryptoKit::Encrypt` | Hybrid ECDH + HKDF + AES-256-GCM authenticated encryption |
| `CryptoKit::Secure` | Secure memory buffers and constant-time comparison |

## Installation

### From source (development)

```bash
git clone <your-repo-url> CryptoKit
cd CryptoKit

# Install dependencies into local/ via Carton
carton install

# Build and test
carton exec -- perl Build.PL
carton exec -- ./Build
carton exec -- ./Build test
```

### As a library

```bash
cpanm CryptX Crypt::Argon2 Crypt::SecretBuffer
```

Then add the project's `lib/` to your `@INC`, or install with `./Build install`.

## Requirements

- Perl 5.16 or later
- **CryptX >= 0.088** — earlier versions do not reseed the PRNG after `fork()`, which can cause child processes to generate identical keys
- **Crypt::SecretBuffer >= 0.019** — earlier versions have a timing side-channel in `memcmp`
- `Crypt::Argon2` (any version)
- For tests: `Test2::V0`

## Encryption vs. signing: which key does what

These two operations use the same key pair but in **opposite directions**. Confusing them is one of the most common cryptographic mistakes, so CryptoKit keeps them in separate modules.

| Operation | Encrypt / Sign with | Decrypt / Verify with | What it provides |
|---|---|---|---|
| **Encryption** (`CryptoKit::Encrypt`) | **Public** key | **Private** key | Confidentiality — only the key holder can read |
| **Signing** (`CryptoKit::Key`) | **Private** key | **Public** key | Authenticity — anyone can verify, only the holder can sign |

- To send someone a secret: encrypt with **their public key**. Only they can decrypt it with their private key.
- To prove a message came from you: sign with **your private key**. Anyone can verify with your public key.
- "Private key encrypts, public key decrypts" is **not** encryption — it is signing, and it provides no confidentiality, because the public key is public.

## Usage

### Quick start

```perl
use CryptoKit;

my $kit = CryptoKit->new;

# Password hashing
my $encoded = $kit->hash->create('my secret password');
my $ok      = $kit->hash->verify($encoded, 'my secret password');   # true
my $bad     = $kit->hash->verify($encoded, 'wrong');                # false

# Strong random password
my $pw = $kit->password->generate(24);

# ECC key pair
my $kp = $kit->key->generate;
# $kp->{private_pem}, $kp->{public_pem}

# Sign with PRIVATE key, verify with PUBLIC key
my $sig   = $kit->key->sign($kp->{private_pem}, 'message');
my $valid = $kit->key->verify($kp->{public_pem}, $sig, 'message');

# Encrypt with PUBLIC key, decrypt with PRIVATE key
my $blob = $kit->encrypt->encrypt($kp->{public_pem}, 'secret text');
my $text = $kit->encrypt->decrypt($kp->{private_pem}, $blob);

# Constant-time comparison
my $eq = $kit->secure->compare($user_token, $stored_token);
```

### Password hashing (`CryptoKit::Hash`)

Uses Argon2id with parameters: 3 iterations, 32 MiB memory, 1 lane, 32-byte tag, random 16-byte salt. The output is a standard Argon2id-encoded string suitable for database storage.

```perl
my $h = CryptoKit::Hash->new;

my $encoded = $h->create($password);       # store this
my $ok      = $h->verify($encoded, $password);
```

**Do not** store the raw password. Only store the encoded string. The salt is embedded in it.

### Password generation (`CryptoKit::Password`)

Uses `Crypt::PRNG` (ChaCha20, part of CryptX) — not Perl's built-in `rand`.

```perl
my $p = CryptoKit::Password->new;
my $pw = $p->generate(20);

# Custom charset and length
my $custom = CryptoKit::Password->new(charset => 'ab', length => 8);
my $short  = $custom->generate;
```

Default charset: `A-Z a-z 0-9 ! # $ % ^ & *`. Length defaults to 16. Rejects non-positive lengths and lengths above 4096.

### Key management and signing (`CryptoKit::Key`)

ECC with `secp256r1` (NIST P-256) and SHA-256 by default.

Signing uses the **private key** to sign and the **public key** to verify. This proves authenticity: anyone can verify, but only the key holder can sign. Signing does **not** provide confidentiality — for that, use `CryptoKit::Encrypt`.

```perl
my $k = CryptoKit::Key->new;

my $kp = $k->generate;                 # { private_pem, public_pem, object }
my $kp = $k->generate('secp384r1');    # alternative curve

# Sign with the PRIVATE key
my $sig = $k->sign($kp->{private_pem}, 'message');

# Verify with the PUBLIC key
my $ok = $k->verify($kp->{public_pem}, $sig, 'message');
```

The `object` field is a live `Crypt::PK::ECC` instance if you need lower-level access.

### Hybrid encryption (`CryptoKit::Encrypt`)

Encryption uses the **recipient's public key** to encrypt, and the **recipient's private key** to decrypt. This is the opposite direction from signing: only the holder of the private key can read the message.

Do not confuse this with `sign`/`verify`, where the private key signs and the public key verifies. Signing proves authenticity but provides no confidentiality — anyone with the public key can verify a signature.

`CryptoKit::Encrypt` implements the standard hybrid pattern, because ECC alone cannot encrypt arbitrary-length data (it is a key-agreement primitive, limited to a few dozen bytes):

1. Generate an ephemeral ECC key pair per message (forward secrecy)
2. ECDH: ephemeral private key + recipient public key → shared secret
3. HKDF-SHA256 derives a 32-byte AES key
4. AES-256-GCM encrypts and authenticates the payload
5. Serialize as `[4-byte BE DER length][DER][12-byte IV][16-byte tag][ciphertext]`

```perl
my $e = CryptoKit::Encrypt->new;

# Encrypt with the PUBLIC key (anyone can do this)
my $blob = $e->encrypt($kp->{public_pem}, 'secret message');

# Decrypt with the PRIVATE key (only the key holder can do this)
my $text = $e->decrypt($kp->{private_pem}, $blob);
```

`decrypt` returns `undef` and dies if the ciphertext was tampered with or the wrong private key was used. Authenticated encryption fails closed.

### Secure memory (`CryptoKit::Secure`)

Wraps `Crypt::SecretBuffer` — an opaque buffer that wipes its memory on destruction — and provides constant-time comparison.

```perl
my $s = CryptoKit::Secure->new;

my $buf = $s->wrap('sensitive data');
# $buf is a Crypt::SecretBuffer; wiped when it goes out of scope

my $eq = $s->compare($a, $b);   # constant-time, works with scalars or buffers
```

Never use Perl's `eq` to compare security-sensitive strings (HMACs, tokens) — it short-circuits on the first differing byte, which leaks timing information.

## Command-line interface

Install with `./Build install`, or run from the source tree:

```bash
carton exec -- ./bin/cryptokit genpw 24
carton exec -- ./bin/cryptokit hash 'my password'
carton exec -- ./bin/cryptokit keygen
```

| Command | Output |
|---|---|
| `genpw [length]` | A random password (default 20) |
| `hash <password>` | Argon2id-encoded hash |
| `keygen` | ECC private PEM followed by public PEM |

## Security Notes

- **Keep CryptX updated.** Version 0.088 fixed a critical `fork()` PRNG reseeding bug that could cause different worker processes to generate identical keys. Version 0.088_001 fixed a timing side-channel in AEAD tag verification.
- **Keep encrypt and sign directions straight.** Encrypt with the public key, decrypt with the private key. Sign with the private key, verify with the public key. Mixing them up either breaks confidentiality or breaks authenticity.
- **Only store hashed passwords.** `CryptoKit::Hash->create` returns the encoded string; store that, never the plaintext.
- **Authenticated encryption only.** `CryptoKit::Encrypt` always uses AES-GCM. Do not add unauthenticated modes (AES-CBC, CTR without a MAC) — they are trivially malleable.
- **Constant-time comparison.** Use `CryptoKit::Secure->compare` for tokens and HMACs, not `eq` or `==`.
- **Private keys are sensitive.** `CryptoKit::Key` returns PEM strings in plain scalars. For production, pass them through `CryptoKit::Secure->wrap` before further use, and protect key files with mode `0600`.

## Project layout

```
CryptoKit/
├── Build.PL
├── cpanfile
├── cpanfile.snapshot
├── Changes
├── README.md
├── bin/
│   └── cryptokit
├── lib/
│   ├── CryptoKit.pm
│   └── CryptoKit/
│       ├── Hash.pm
│       ├── Password.pm
│       ├── Key.pm
│       ├── Encrypt.pm
│       └── Secure.pm
└── t/
    ├── 00-load.t
    ├── hash.t
    ├── password.t
    ├── key.t
    ├── encrypt.t
    └── secure.t
```

## Extending

Adding a new feature is designed to be simple:

1. Create `lib/CryptoKit/YourFeature.pm` as an OO class with a `new` constructor.
2. Add one line to `%MODULES` in `lib/CryptoKit.pm`:

```perl
yourfeature => 'CryptoKit::YourFeature',
```

3. Add a convenience accessor:

```perl
sub yourfeature { $_[0]->module('yourfeature')->new(@_[1..$#_]) }
```

4. Write `t/yourfeature.t` and run `carton exec -- ./Build test`.

The main module never needs to know your implementation details; each submodule is independently testable and replaceable.

### Planned additions

- `CryptoKit::HMAC` — HMAC signing for API tokens and webhook verification
- `CryptoKit::TOTP` — time-based one-time passwords (Google Authenticator compatible)
- File encryption — streaming AES-GCM for large files
- `SecretBuffer` integration inside `Hash` and `Key` so passwords and private keys never linger in plain scalars

## Testing

```bash
carton exec -- ./Build test
```

Author tests (POD coverage, manifest, syntax of POD) are gated behind `AUTHOR_TESTING`:

```bash
AUTHOR_TESTING=1 carton exec -- ./Build test
```

## License

Same terms as Perl itself.
