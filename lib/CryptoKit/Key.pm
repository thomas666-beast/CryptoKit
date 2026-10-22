package CryptoKit::Key;
use strict;
use warnings;
use Crypt::PK::ECC;

sub new { bless {}, shift }

sub generate {
    my ($self, $curve) = @_;
    $curve //= 'secp256r1';
    my $pk = Crypt::PK::ECC->new;
    $pk->generate_key($curve);
    return {
        private_pem => $pk->export_key_pem('private'),
        public_pem  => $pk->export_key_pem('public'),
        object      => $pk,
    };
}

sub sign {
    my ($self, $private_pem, $message, $hash) = @_;
    $hash //= 'SHA256';
    my $pk = Crypt::PK::ECC->new(\$private_pem);
    return $pk->sign_message($message, $hash);
}

sub verify {
    my ($self, $public_pem, $signature, $message, $hash) = @_;
    $hash //= 'SHA256';
    my $pk = Crypt::PK::ECC->new(\$public_pem);
    return $pk->verify_message($signature, $message, $hash);
}

1;

__END__

=head1 NAME

CryptoKit::Key - ECC key generation and signatures

=head1 SYNOPSIS

    my $k  = CryptoKit::Key->new;
    my $kp = $k->generate;
    my $sig = $k->sign($kp->{private_pem}, 'message');
    my $ok  = $k->verify($kp->{public_pem}, $sig, 'message');

=head1 DESCRIPTION

Wraps L<Crypt::PK::ECC> for ECC key generation, signing, and
verification. Defaults to the C<secp256r1> (NIST P-256) curve and
SHA-256.

=head1 METHODS

=head2 new

Constructor.

=head2 generate

    my $kp = $k->generate($curve);

Returns a hashref with C<private_pem>, C<public_pem>, and the live
C<object>.

=head2 sign

    my $sig = $k->sign($private_pem, $message, $hash);

Returns a binary signature.

=head2 verify

    my $ok = $k->verify($public_pem, $signature, $message, $hash);

Returns true if the signature is valid for the message.

=cut
