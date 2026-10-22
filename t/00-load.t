use Test::More tests => 5;
BEGIN { use_ok('CryptoKit') }

my $kit = CryptoKit->new;
ok($kit->hash,     'Hash module loads');
ok($kit->password, 'Password module loads');
ok($kit->key,      'Key module loads');
ok($kit->secure,   'Secure module loads');
