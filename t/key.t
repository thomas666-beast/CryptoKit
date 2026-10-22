use Test2::V0;
use lib 'lib';
use CryptoKit;

my $k  = CryptoKit->new->key;
my $kp = $k->generate;

like $kp->{public_pem},  qr/BEGIN PUBLIC KEY/,     'public PEM exported';
like $kp->{private_pem}, qr/BEGIN .*PRIVATE KEY/,  'private PEM exported';

my $msg = 'sign me';
my $sig = $k->sign($kp->{private_pem}, $msg);
ok  $k->verify($kp->{public_pem}, $sig, $msg),      'valid signature verifies';
ok !$k->verify($kp->{public_pem}, $sig, 'tampered'), 'tampered message rejected';

done_testing;
