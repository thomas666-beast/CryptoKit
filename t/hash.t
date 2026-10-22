use Test2::V0;
use lib 'lib';
use CryptoKit;

my $h = CryptoKit->new->hash;

my $encoded = $h->create('correct horse battery staple');
ok $h->verify($encoded, 'correct horse battery staple'), 'right password verifies';
ok !$h->verify($encoded, 'wrong password'),              'wrong password rejected';

my $again = $h->create('correct horse battery staple');
isnt $encoded, $again, 'salt makes hashes unique';

done_testing;
