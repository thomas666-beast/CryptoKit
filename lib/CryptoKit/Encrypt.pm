package CryptoKit::Encrypt;
use strict;
use warnings;
use Crypt::PK::ECC;
use Crypt::KeyDerivation qw(hkdf);
use Crypt::AuthEnc::GCM   qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use Crypt::PRNG           qw(random_bytes);

my $CURVE     = 'secp256r1';
my $HKDF_INFO = 'CryptoKit-Encrypt-v1';

sub new { bless {}, shift }

sub encrypt {
    my ($self, $public_pem, $plaintext) = @_;
    die "Public key required" unless defined $public_pem;
    die "Plaintext required"  unless defined $plaintext;

    my $ephemeral = Crypt::PK::ECC->new;
    $ephemeral->generate_key($CURVE);

    my $recipient = Crypt::PK::ECC->new(\$public_pem);
    my $shared    = $ephemeral->shared_secret($recipient);

    my $aes_key = hkdf($shared, undef, 'SHA256', 32, $HKDF_INFO);

    my $iv = random_bytes(12);
    my ($ciphertext, $tag) = gcm_encrypt_authenticate(
        'AES', $aes_key, $iv, '', $plaintext
    );

    my $der = $ephemeral->export_key_der('public');
    return pack('N', length($der)) . $der . $iv . $tag . $ciphertext;
}

sub decrypt {
    my ($self, $private_pem, $blob) = @_;
    die "Private key required" unless defined $private_pem;
    die "Ciphertext required"  unless defined $blob;
    die "Ciphertext too short" if length($blob) < 4 + 12 + 16 + 1;

    my $der_len    = unpack('N', substr($blob, 0, 4));
    my $der        = substr($blob, 4,                 $der_len);
    my $iv         = substr($blob, 4 + $der_len,      12);
    my $tag        = substr($blob, 4 + $der_len + 12, 16);
    my $ciphertext = substr($blob, 4 + $der_len + 28);

    my $ephemeral = Crypt::PK::ECC->new(\$der);
    my $recipient = Crypt::PK::ECC->new(\$private_pem);
    my $shared    = $recipient->shared_secret($ephemeral);

    my $aes_key = hkdf($shared, undef, 'SHA256', 32, $HKDF_INFO);

    # Directly returns plaintext; returns undef when tag verification fails
    my $plaintext = gcm_decrypt_verify(
        'AES', $aes_key, $iv, '', $ciphertext, $tag
    );

    die "Decryption failed: authentication tag mismatch"
        unless defined $plaintext;

    return $plaintext;
}

1;

__END__

=head1 NAME

CryptoKit::Encrypt - Hybrid ECC + AES-GCM encryption

=head1 SYNOPSIS

    my $e  = CryptoKit::Encrypt->new;
    my $kp = CryptoKit::Key->new->generate;

    my $blob = $e->encrypt($kp->{public_pem}, 'secret message');
    my $text = $e->decrypt($kp->{private_pem}, $blob);

=head1 DESCRIPTION

Implements hybrid encryption: an ephemeral ECC key pair is generated
per message, an ECDH shared secret is derived with the recipient's
public key, HKDF produces an AES-256 key, and AES-GCM encrypts the
payload with authentication.

The serialized format is:

    [4-byte BE DER length][ephemeral DER public key]
    [12-byte IV][16-byte GCM tag][ciphertext]

=head1 METHODS

=head2 new

Constructor.

=head2 encrypt

    my $blob = $e->encrypt($public_pem, $plaintext);

Returns a binary blob suitable for storage or transmission.

=head2 decrypt

    my $text = $e->decrypt($private_pem, $blob);

Returns the original plaintext, or dies if the ciphertext has been
tampered with or the wrong private key is used.

=cut
