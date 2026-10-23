use Test2::V0;
use lib 'lib';
use CryptoKit;
use Crypt::PRNG qw(random_bytes);
use File::Temp qw(tempdir);
use Digest::SHA qw(sha256);

my $key = random_bytes(32);
my $dir = tempdir(CLEANUP => 1);

sub write_file {
    my ($path, $data) = @_;
    open my $fh, '>:raw', $path or die $!;
    print $fh $data;
    close $fh;
}

sub read_file {
    my ($path) = @_;
    open my $fh, '<:raw', $path or die $!;
    return do { local $/; <$fh> };
}

# Use a small chunk size so multi-chunk behavior is exercised
my $v = CryptoKit->new->file_vault(chunk_size => 256);

# --- Container mode: small file (single chunk) ---
{
    my $plain = "hello world\n";
    my $in    = "$dir/small.txt";
    my $enc   = "$dir/small.ckfv";
    my $out   = "$dir/small.out";
    write_file($in, $plain);

    my $info = $v->pack($key, $in, $enc);
    is $info->{n_chunks}, 1, 'single chunk for small file';
    is $info->{orig_size}, length($plain), 'orig_size recorded';

    $v->unpack($key, $enc, $out);
    is read_file($out), $plain, 'small file round-trips';
}

# --- Container mode: multi-chunk ---
{
    my $plain = join '', map { chr(65 + $_ % 26) } 1 .. 1000;
    my $in    = "$dir/multi.txt";
    my $enc   = "$dir/multi.ckfv";
    my $out   = "$dir/multi.out";
    write_file($in, $plain);

    my $info = $v->pack($key, $in, $enc);
    cmp_ok $info->{n_chunks}, '>', 1, 'multiple chunks for larger file';

    $v->unpack($key, $enc, $out);
    is read_file($out), $plain, 'multi-chunk round-trips';
}

# --- Container mode: empty file ---
{
    my $in  = "$dir/empty.txt";
    my $enc = "$dir/empty.ckfv";
    my $out = "$dir/empty.out";
    write_file($in, '');

    $v->pack($key, $in, $enc);
    $v->unpack($key, $enc, $out);
    is read_file($out), '', 'empty file round-trips';
}

# --- Wrong key ---
{
    my $in  = "$dir/wrongkey.txt";
    my $enc = "$dir/wrongkey.ckfv";
    write_file($in, 'secret');
    $v->pack($key, $in, $enc);

    my $other_key = random_bytes(32);
    ok dies { $v->unpack($other_key, $enc, "$dir/wrongkey.out") },
        'wrong key rejected';
}

# --- Tampered container ---
{
    my $in  = "$dir/tamper.txt";
    my $enc = "$dir/tamper.ckfv";
    write_file($in, 'x' x 500);
    $v->pack($key, $in, $enc);

    open my $fh, '+<:raw', $enc or die $!;
    seek $fh, -1, 2;
    read $fh, my $last, 1;
    seek $fh, -1, 2;
    print $fh chr(ord($last) ^ 0xFF);
    close $fh;

    ok dies { $v->unpack($key, $enc, "$dir/tamper.out") },
        'tampered container rejected';
}

# --- Split mode: round-trip with multiple chunks ---
{
    my $plain = join '', map { chr(65 + $_ % 26) } 1 .. 1000;
    my $in    = "$dir/split.txt";
    my $vdir  = "$dir/vault";
    my $out   = "$dir/split.out";
    write_file($in, $plain);

    my $info = $v->split($key, $in, $vdir);
    ok -e $info->{manifest}, 'manifest file written';
    cmp_ok scalar(@{ $info->{chunks} }), '>', 1, 'multiple chunk files written';

    $v->join($key, $info->{manifest}, $out);
    is read_file($out), $plain, 'split/join round-trips';
}

# --- Split mode: missing chunk ---
{
    my $plain = join '', map { chr(65 + $_ % 26) } 1 .. 1000;
    my $in    = "$dir/missing.txt";
    my $vdir  = "$dir/vault-missing";
    write_file($in, $plain);

    my $info = $v->split($key, $in, $vdir);
    unlink $info->{chunks}->[0];

    ok dies { $v->join($key, $info->{manifest}, "$dir/missing.out") },
        'missing chunk causes failure';
}

# --- SHA-256 integrity check in manifest ---
{
    my $plain = 'integrity test';
    my $in    = "$dir/int.txt";
    my $enc   = "$dir/int.ckfv";
    write_file($in, $plain);

    my $info = $v->pack($key, $in, $enc);
    is $info->{sha256}, unpack('H*', sha256($plain)),
        'manifest sha256 matches plaintext';
}

done_testing;
