use Test2::V0;
use lib 'lib';
use CryptoKit;

my $p = CryptoKit->new->password;

my $pw = $p->generate(20);
is length($pw), 20, 'respects length';
like $pw, qr/\A[A-Za-z0-9!#\$%\^&*]+\z/, 'uses expected charset';

my $custom = CryptoKit::Password->new(charset => 'ab', length => 8);
like $custom->generate, qr/\A[ab]{8}\z/, 'custom charset and length';

isnt $p->generate(32), $p->generate(32), 'random output differs';

done_testing;
