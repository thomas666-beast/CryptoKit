use Test2::V0;
use lib 'lib';
use CryptoKit;

my $e  = CryptoKit->new->encrypt;
my $k  = CryptoKit->new->key;
my $kp = $k->generate;

my $plaintext = 'secret message';
my $blob      = $e->encrypt($kp->{public_pem}, $plaintext);

isnt $blob, $plaintext, 'ciphertext differs from plaintext';

my $decrypted = $e->decrypt($kp->{private_pem}, $blob);
is $decrypted, $plaintext, 'round-trip decrypts to original';

# Empty plaintext
my $empty_blob = $e->encrypt($kp->{public_pem}, '');
is $e->decrypt($kp->{private_pem}, $empty_blob), '', 'empty plaintext round-trips';

# Long plaintext
my $long = 'x' x 10_000;
is $e->decrypt($kp->{private_pem}, $e->encrypt($kp->{public_pem}, $long)),
   $long, 'long plaintext round-trips';

# Each encryption uses a fresh ephemeral key => different ciphertext
isnt $e->encrypt($kp->{public_pem}, $plaintext),
     $e->encrypt($kp->{public_pem}, $plaintext),
     'fresh ephemeral key per message';

# Wrong private key must fail (GCM tag verification)
my $other = $k->generate;
ok dies { $e->decrypt($other->{private_pem}, $blob) },
   'wrong private key rejects decryption';

# Tampered ciphertext must fail
my $tampered = $blob;
substr($tampered, -1, 1) = chr(ord(substr($tampered, -1, 1)) ^ 0x01);
ok dies { $e->decrypt($kp->{private_pem}, $tampered) },
   'tampered ciphertext rejected';

done_testing;
