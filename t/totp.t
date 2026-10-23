use Test2::V0;
use lib 'lib';
use CryptoKit;

my $t = CryptoKit->new->totp;

# RFC 6238 test vector: secret = "12345678901234567890" (ASCII)
my $secret = '12345678901234567890';
my $code   = $t->generate($secret, 59);
is $code, '287082', 'RFC 6238 test vector at T=59';

ok $t->verify($secret, $code, 59), 'correct code verifies';
ok !$t->verify($secret, '000000', 59), 'wrong code rejected';

# Window: code from T=59 should verify at T=60 within window 1
ok $t->verify($secret, $code, 60, 1), 'window accepts adjacent timestep';
ok !$t->verify($secret, $code, 60, 0), 'zero window rejects adjacent timestep';

done_testing;
