# CryptoKit

A modular cryptographic toolkit for Perl. Provides password hashing, secure random password generation, ECC key management, hybrid encryption, HMAC signing, TOTP, file encryption, split file vaults, self-verifying identifiers, and secure memory handling — each as an independent, lazily loaded submodule.

Built on [CryptX](https://metacpan.org/pod/CryptX) and [Crypt::Argon2](https://metacpan.org/pod/Crypt::Argon2), with security-critical version pins.

## Features

| Module | Purpose |
|---|---|
| `CryptoKit::Hash` | Argon2id password hashing with random salts |
| `CryptoKit::Password` | Cryptographically strong random password generation |
| `CryptoKit::Key` | ECC key generation, ECDSA sign/verify |
| `CryptoKit::Encrypt` | Hybrid ECDH + HKDF + AES-256-GCM authenticated encryption |
| `CryptoKit::HMAC` | HMAC signing with constant-time verification |
| `CryptoKit::TOTP` | Time-based one-time passwords (Google Authenticator compatible) |
| `CryptoKit::FileEncrypt` | Streaming AES-256-GCM file encryption |
| `CryptoKit::FileVault` | Split a file into encrypted chunks, pack, and reassemble |
| `CryptoKit::HolopeinenID` | Self-verifying, time-ordered, shard-safe identifiers |
| `CryptoKit::Secure` | Secure memory buffers and constant-time comparison |

## Installation

### From source (development)

```bash
git clone <your-repo-url> CryptoKit
cd CryptoKit

carton install

carton exec -- perl Build.PL
carton exec -- ./Build
carton exec -- ./Build test
```

### As a library

```bash
cpanm CryptX Crypt::Argon2 Crypt::SecretBuffer Authen::OATH MIME::Base32
```

Then add the project's `lib/` to your `@INC`, or install with `./Build install`.

## Requirements

- Perl 5.16 or later
- **CryptX >= 0.088_001** — earlier versions have a timing side-channel in AEAD tag verification (`decrypt_done`), which is used by `CryptoKit::FileEncrypt` and `CryptoKit::FileVault` [citation:2]
- **Crypt::SecretBuffer >= 0.019** — earlier versions have a timing side-channel in `memcmp`
- `Crypt::Argon2` (any version)
- `Authen::OATH` (for TOTP)
- `MIME::Base32` (for the CLI `totp` command)
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
my $ok      = $kit->hash->verify($encoded, 'my secret password');

# Strong random password
my $pw = $kit->password->generate(24);

# ECC key pair
my $kp = $kit->key->generate;

# Sign with PRIVATE key, verify with PUBLIC key
my $sig   = $kit->key->sign($kp->{private_pem}, 'message');
my $valid = $kit->key->verify($kp->{public_pem}, $sig, 'message');

# Encrypt with PUBLIC key, decrypt with PRIVATE key
my $blob = $kit->encrypt->encrypt($kp->{public_pem}, 'secret text');
my $text = $kit->encrypt->decrypt($kp->{private_pem}, $blob);

# HMAC for API tokens
my $token   = $kit->hmac->create($secret_key, 'payload');
my $hmac_ok = $kit->hmac->verify($secret_key, 'payload', $token);

# TOTP for two-factor auth
my $code    = $kit->totp->generate($totp_secret);
my $totp_ok = $kit->totp->verify($totp_secret, $user_code);

# HolopeinenID for self-verifying identifiers
my $hid = $kit->holopeinen_id(key => $secret, shard => 'A3');
my $id  = $hid->issue(prefix => 'usr', payload => 'user_42');
my $r   = $hid->verify($id);

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

my $custom = CryptoKit::Password->new(charset => 'ab', length => 8);
my $short  = $custom->generate;
```

Default charset: `A-Z a-z 0-9 ! # $ % ^ & *`. Length defaults to 16. Rejects non-positive lengths and lengths above 4096.

### Key management and signing (`CryptoKit::Key`)

ECC with `secp256r1` (NIST P-256) and SHA-256 by default.

Signing uses the **private key** to sign and the **public key** to verify. This proves authenticity: anyone can verify, but only the key holder can sign. Signing does **not** provide confidentiality — for that, use `CryptoKit::Encrypt`.

```perl
my $k = CryptoKit::Key->new;

my $kp = $k->generate;

my $sig = $k->sign($kp->{private_pem}, 'message');
my $ok  = $k->verify($kp->{public_pem}, $sig, 'message');
```

The `object` field is a live `Crypt::PK::ECC` instance if you need lower-level access.

### Hybrid encryption (`CryptoKit::Encrypt`)

Encryption uses the **recipient's public key** to encrypt, and the **recipient's private key** to decrypt. This is the opposite direction from signing: only the holder of the private key can read the message.

`CryptoKit::Encrypt` implements the standard hybrid pattern, because ECC alone cannot encrypt arbitrary-length data:

1. Generate an ephemeral ECC key pair per message (forward secrecy)
2. ECDH: ephemeral private key + recipient public key → shared secret
3. HKDF-SHA256 derives a 32-byte AES key
4. AES-256-GCM encrypts and authenticates the payload
5. Serialize as `[4-byte BE DER length][DER][12-byte IV][16-byte tag][ciphertext]`

```perl
my $e = CryptoKit::Encrypt->new;

my $blob = $e->encrypt($kp->{public_pem}, 'secret message');
my $text = $e->decrypt($kp->{private_pem}, $blob);
```

`decrypt` returns `undef` and dies if the ciphertext was tampered with or the wrong private key was used.

### HMAC signing (`CryptoKit::HMAC`)

HMAC is a keyed hash used for API tokens, webhook signatures, and session cookies. It uses a **shared secret**, not a public/private key pair.

```perl
my $h = CryptoKit::HMAC->new;

my $token = $h->create($shared_secret, $payload);
if ($h->verify($shared_secret, $payload, $token)) {
    # authentic
}

my $raw = $h->raw($shared_secret, $payload);
my $b64 = $h->b64url($shared_secret, $payload);
```

Default hash is SHA256. `verify` uses constant-time comparison.

### Time-based one-time passwords (`CryptoKit::TOTP`)

TOTP generates 6-digit codes that change every 30 seconds, compatible with Google Authenticator, Authy, and 1Password.

```perl
my $t = CryptoKit::TOTP->new;

my $code = $t->generate($secret);
if ($t->verify($secret, $user_code)) {
    # correct
}
```

The `$secret` must be the **decoded** Base32 value, not the Base32 string itself:

```perl
use MIME::Base32 qw(decode_base32);
my $raw_secret = decode_base32($base32_from_qr);
my $code = $t->generate($raw_secret);
```

`verify` accepts an optional `$window` (default 1), checking the previous, current, and next timestep.

### File encryption (`CryptoKit::FileEncrypt`)

Streaming AES-256-GCM for files that may be larger than memory. Encrypts in 1 MiB chunks.

```perl
my $f = CryptoKit::FileEncrypt->new;

$f->encrypt_file($key32, 'plain.txt', 'secret.enc');
$f->decrypt_file($key32, 'secret.enc', 'plain.out');
```

The key must be **exactly 32 bytes** (AES-256). Generate one with `Crypt::PRNG`:

```perl
use Crypt::PRNG qw(random_bytes);
my $key32 = random_bytes(32);
```

Output format: `[12-byte IV][ciphertext][16-byte tag]`. The IV is random per encryption, so the same plaintext with the same key produces different ciphertext each time.

`decrypt_file` dies if the authentication tag does not match.

### File vault (`CryptoKit::FileVault`)

Splits a file into fixed-size chunks, encrypts each chunk independently with AES-256-GCM, and packs them with an encrypted manifest.

```perl
my $v = CryptoKit::FileVault->new;

my $info = $v->pack($key32, 'plain.txt', 'secret.ckfv');
$v->unpack($key32, 'secret.ckfv', 'plain.out');

my $info = $v->split($key32, 'plain.txt', 'vault-dir/');
$v->join($key32, 'vault-dir/plain.txt.ckfv-manifest', 'plain.out');
```

Each chunk has its own IV and tag, so a corrupted or missing chunk is identified precisely. The manifest records the number of chunks, chunk size, original filename, original size, and SHA-256 of the whole plaintext. The manifest itself is encrypted with the same key.

Split mode is useful for distributing files across storage, or for parallelizing decryption — each chunk can be decrypted independently.

### HolopeinenID (`CryptoKit::HolopeinenID`)

A HolopeinenID is a compact identifier that is **time-ordered**, **shard-safe**, **self-verifying**, and **scoped**. It looks like:

```
usr.00XkP9A3f7G2mN4qR8tYu.9tZ3x8LqR2fWn1A
[prefix].[timestamp+shard+random].[MAC]
```

```perl
my $hid = CryptoKit::HolopeinenID->new(key => $secret, shard => 'A3');

my $id = $hid->issue(prefix => 'usr', payload => 'user_42');

my $r = $hid->verify($id);
if ($r->{ok}) {
    printf "user=%s issued=%d shard=%s\n",
        $r->{payload}, $r->{timestamp}, $r->{shard};
} else {
    warn "Rejected: $r->{reason}\n";
}
```

**Properties:**

- **Time-ordered** — IDs from the same shard sort in creation order
- **Shard-safe** — different nodes use different `shard` codes; no collisions even with clock skew
- **Self-verifying** — tampering is detected without a database lookup
- **Scoped** — the prefix is bound into the MAC, so a `usr` ID cannot be used as an `inv` ID
- **Compact** — about 42 characters for an ID with no payload

The separator is `.` (dot), which is **not** in the base64url alphabet, so payload and MAC segments cannot be confused with the separator.

**Important:** the key is a shared secret. The payload is not encrypted — if you need to hide it, encrypt it first with `CryptoKit::Encrypt`.

### Secure memory (`CryptoKit::Secure`)

Wraps `Crypt::SecretBuffer` — an opaque buffer that wipes its memory on destruction — and provides constant-time comparison.

```perl
my $s = CryptoKit::Secure->new;

my $buf = $s->wrap('sensitive data');
my $eq  = $s->compare($a, $b);
```

Never use Perl's `eq` to compare security-sensitive strings — it short-circuits on the first differing byte, which leaks timing information.

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
| `hmac <key> <message>` | HMAC-SHA256 hex of the message |
| `totp <base32-secret>` | Current 6-digit TOTP code |
| `encrypt-file <key-hex> <in> <out>` | AES-256-GCM encrypted file |
| `decrypt-file <key-hex> <in> <out>` | Decrypted file (dies on tag mismatch) |
| `vault-pack <key-hex> <in> <out>` | Split + encrypt + pack a file into one container |
| `vault-unpack <key-hex> <in> <out>` | Reassemble a packed container |
| `hid-issue <key-hex> <prefix> [payload] [shard]` | Issue a HolopeinenID |
| `hid-verify <key-hex> <id>` | Verify a HolopeinenID |

Generate a file encryption key as 64 hex characters:

```bash
perl -MCrypt::PRNG=random_bytes -e 'print unpack("H*", random_bytes(32)), "\n"'
```

Full round-trip example:

```bash
KEY=$(perl -MCrypt::PRNG=random_bytes -e 'print unpack("H*", random_bytes(32))')
echo "secret contents" > plain.txt
cryptokit vault-pack "$KEY" plain.txt secret.ckfv
cryptokit vault-unpack "$KEY" secret.ckfv plain.out
diff plain.txt plain.out && echo "round-trip OK"
```

## Security Notes

- **Keep CryptX updated.** Version 0.088_001 fixed a timing side-channel in AEAD tag verification (`decrypt_done`), which is used by `FileEncrypt` and `FileVault` [citation:2].
- **Keep encrypt and sign directions straight.** Encrypt with the public key, decrypt with the private key. Sign with the private key, verify with the public key.
- **Only store hashed passwords.** `CryptoKit::Hash->create` returns the encoded string; store that, never the plaintext.
- **Authenticated encryption only.** `CryptoKit::Encrypt`, `CryptoKit::FileEncrypt`, and `CryptoKit::FileVault` always use AES-GCM. Do not add unauthenticated modes.
- **Constant-time comparison.** Use `CryptoKit::Secure->compare` or `CryptoKit::HMAC->verify` for tokens and HMACs, not `eq` or `==`.
- **TOTP secrets are sensitive.** A leaked TOTP secret lets an attacker generate valid codes forever. Store it encrypted at rest, and rotate it if compromised.
- **HMAC keys are shared secrets.** Anyone with the key can forge tokens. Distribute over a secure channel and rotate periodically.
- **File encryption keys are raw 32-byte values.** Store them separately from the encrypted files, and never in the same directory.
- **Private keys are sensitive.** `CryptoKit::Key` returns PEM strings in plain scalars. Pass them through `CryptoKit::Secure->wrap` before further use, and protect key files with mode `0600`.
- **HolopeinenID keys are shared secrets.** Anyone with the key can issue valid IDs. The payload is not encrypted; encrypt it first with `CryptoKit::Encrypt` if confidentiality is needed.

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
│       ├── HMAC.pm
│       ├── TOTP.pm
│       ├── FileEncrypt.pm
│       ├── FileVault.pm
│       ├── HolopeinenID.pm
│       └── Secure.pm
└── t/
    ├── 00-load.t
    ├── hash.t
    ├── password.t
    ├── key.t
    ├── encrypt.t
    ├── hmac.t
    ├── totp.t
    ├── fileencrypt.t
    ├── filevault.t
    ├── holopeinenid.t
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

## License

Same terms as Perl itself.
