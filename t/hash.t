use Test2::V0;
use lib 'lib';
use CryptoKit;

my $h = CryptoKit->new->hash;

# --- Argon2id (default) ---
{
    my $encoded = $h->create('correct horse battery staple');
    like $encoded, qr/^\$argon2id\$/, 'default backend is Argon2id';
    ok $h->verify($encoded, 'correct horse battery staple'), 'correct password verifies';
    ok !$h->verify($encoded, 'wrong password'), 'wrong password rejected';

    my $again = $h->create('correct horse battery staple');
    isnt $encoded, $again, 'salt makes hashes unique';
}

# --- Unknown backend rejected ---
{
    ok dies { $h->create('pw', backend => 'nonsense') }, 'unknown backend rejected';
}

# --- HiatalaMrk backend (skipped if not installed) ---
SKIP: {
    skip 'HiatalaMrk not installed', 6 unless $h->hiatala_available;

    my $encoded = $h->create('correct horse battery staple', backend => 'hiatala');
    like $encoded, qr/^\$hiatalamrk\$/, 'Hiatala backend produces Hiatala format';

    ok $h->verify($encoded, 'correct horse battery staple'),
        'correct password verifies (Hiatala)';
    ok !$h->verify($encoded, 'wrong password'),
        'wrong password rejected (Hiatala)';

    my $encoded2 = $h->create('pw', backend => 'hiatala', memory => 64, passes => 1);
    ok $h->verify($encoded2, 'pw'), 'custom params round-trip';

    # Cross-backend verify: Argon2id hash should not verify via Hiatala
    my $argon = $h->create('pw');
    ok $h->verify($argon, 'pw'), 'Argon2id hash verifies (backend-agnostic)';
    ok !$h->verify($encoded, 'correct horse battery staple' . 'x'),
        'wrong password rejected (Hiatala, with suffix)';
}

done_testing;
