use Test2::V0;
use lib 'lib';
use CryptoKit;
use File::Temp qw(tempfile);
use Crypt::PRNG qw(random_bytes);

my $f   = CryptoKit->new->file_encrypt;
my $key = random_bytes(32);

my ($in_fh, $in_path) = tempfile();
print $in_fh "The quick brown fox jumps over the lazy dog\n";
close $in_fh;

my ($enc_fh, $enc_path) = tempfile();
close $enc_fh;
my ($out_fh, $out_path) = tempfile();
close $out_fh;

$f->encrypt_file($key, $in_path, $enc_path);
ok -s $enc_path, 'encrypted file is non-empty';

$f->decrypt_file($key, $enc_path, $out_path);
open my $out, '<:raw', $out_path or die;
my $recovered = do { local $/; <$out> };
close $out;

is $recovered, "The quick brown fox jumps over the lazy dog\n",
    'round-trip recovers original';

# Tampered file fails
open my $enc, '+<:raw', $enc_path or die;
seek $enc, -1, 2;
read $enc, my $last, 1;
seek $enc, -1, 2;
print $enc chr(ord($last) ^ 0xFF);
close $enc;

ok dies { $f->decrypt_file($key, $enc_path, $out_path) },
    'tampered ciphertext rejected';

unlink $in_path, $enc_path, $out_path;

done_testing;
