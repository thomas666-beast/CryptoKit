use Test2::V0;
use lib 'lib';
use CryptoKit;

my $s = CryptoKit->new->secure;

my $buf = $s->wrap('s3cr3t');
isa_ok $buf, 'Crypt::SecretBuffer';

ok  $s->compare('abc', 'abc'),  'equal scalars match';
ok !$s->compare('abc', 'abd'),  'unequal scalars rejected';

my $a = $s->wrap('token');
my $b = $s->wrap('token');
ok $s->compare($a, $b), 'equal SecretBuffers match';

done_testing;
