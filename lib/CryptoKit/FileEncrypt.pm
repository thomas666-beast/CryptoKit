package CryptoKit::FileEncrypt;
use strict;
use warnings;
use Crypt::AuthEnc::GCM;
use Crypt::PRNG qw(random_bytes);

my $CHUNK = 1024 * 1024;  # 1 MiB

sub new { bless {}, shift }

sub encrypt_file {
    my ($self, $key, $in_path, $out_path) = @_;
    die "Key must be 32 bytes" unless defined $key && length($key) == 32;

    open my $in, '<:raw', $in_path or die "Cannot open $in_path: $!";
    open my $out, '>:raw', $out_path or die "Cannot open $out_path: $!";

    my $iv = random_bytes(12);
    print $out $iv;

    my $ae = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
    while (1) {
        my $n = read($in, my $buf, $CHUNK);
        last unless $n;
        print $out $ae->encrypt_add($buf);
    }
    my $tag = $ae->encrypt_done();
    print $out $tag;

    close $in;
    close $out;
    return 1;
}

sub decrypt_file {
    my ($self, $key, $in_path, $out_path) = @_;
    die "Key must be 32 bytes" unless defined $key && length($key) == 32;

    open my $in, '<:raw', $in_path or die "Cannot open $in_path: $!";
    open my $out, '>:raw', $out_path or die "Cannot open $out_path: $!";

    read($in, my $iv, 12) == 12 or die "Truncated IV";

    # Read whole file, last 16 bytes are the tag
    my $all = do { local $/; <$in> };
    die "Truncated ciphertext" if length($all) < 16;
    my $tag        = substr($all, -16);
    my $ciphertext = substr($all, 0, length($all) - 16);

    my $ae = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
    my $plaintext = '';
    for (my $off = 0; $off < length($ciphertext); $off += $CHUNK) {
        my $chunk = substr($ciphertext, $off, $CHUNK);
        $plaintext .= $ae->decrypt_add($chunk);
    }
    $ae->decrypt_done($tag) or die "Authentication failed";

    print $out $plaintext;
    close $in;
    close $out;
    return 1;
}

1;

__END__

=head1 NAME

CryptoKit::FileEncrypt - Streaming AES-GCM file encryption

=head1 SYNOPSIS

    my $f = CryptoKit::FileEncrypt->new;
    $f->encrypt_file($key32, 'plain.txt', 'secret.enc');
    $f->decrypt_file($key32, 'secret.enc', 'plain.out');

=head1 DESCRIPTION

Encrypts files in 1 MiB chunks using AES-256-GCM. The output format is:

    [12-byte IV][ciphertext][16-byte tag]

=head1 METHODS

=head2 encrypt_file

    $f->encrypt_file($key, $in, $out);

Key must be exactly 32 bytes.

=head2 decrypt_file

    $f->decrypt_file($key, $in, $out);

Dies if authentication fails.

=cut
