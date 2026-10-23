use Test2::V0;
use lib 'lib';
use CryptoKit;

my $h = CryptoKit->new->hmac;

my $token = $h->create('secret-key', 'message');
ok $h->verify('secret-key', 'message', $token), 'correct HMAC verifies';
ok !$h->verify('secret-key', 'tampered', $token), 'wrong message rejected';
ok !$h->verify('wrong-key', 'message', $token), 'wrong key rejected';

my $raw = $h->raw('secret-key', 'message');
is length($raw), 32, 'raw HMAC is 32 bytes for SHA256';

my $b64 = $h->b64url('secret-key', 'message');
unlike $b64, qr/[+\/]/, 'URL-safe base64 has no + or /';

done_testing;
