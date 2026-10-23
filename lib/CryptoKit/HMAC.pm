package CryptoKit::HMAC;
use strict;
use warnings;
use Crypt::Mac::HMAC qw(hmac hmac_hex hmac_b64u);
use Crypt::Misc qw(slow_eq);

sub new { bless {}, shift }

sub create {
    my ($self, $key, $message, $hash) = @_;
    $hash //= 'SHA256';
    die "Key required"     unless defined $key;
    die "Message required" unless defined $message;
    return hmac_hex($hash, $key, $message);
}

sub verify {
    my ($self, $key, $message, $expected_hex, $hash) = @_;
    $hash //= 'SHA256';
    return 0 unless defined $expected_hex;
    my $computed = hmac_hex($hash, $key, $message);
    return slow_eq($computed, $expected_hex) ? 1 : 0;
}

sub raw {
    my ($self, $key, $message, $hash) = @_;
    $hash //= 'SHA256';
    return hmac($hash, $key, $message);
}

sub b64url {
    my ($self, $key, $message, $hash) = @_;
    $hash //= 'SHA256';
    return hmac_b64u($hash, $key, $message);
}

1;

__END__

=head1 NAME

CryptoKit::HMAC - HMAC signing for API tokens and webhooks

=head1 SYNOPSIS

    my $h = CryptoKit::HMAC->new;
    my $token = $h->create($secret, 'message');
    my $ok    = $h->verify($secret, 'message', $token);

=head1 DESCRIPTION

Wraps L<Crypt::Mac::HMAC> with constant-time verification.

=head1 METHODS

=head2 new

Constructor.

=head2 create

    my $hex = $h->create($key, $message, $hash?);

Returns hex-encoded HMAC. Default hash is SHA256.

=head2 verify

    my $ok = $h->verify($key, $message, $expected_hex, $hash?);

Constant-time comparison.

=head2 raw

Returns raw binary HMAC.

=head2 b64url

Returns URL-safe Base64 HMAC.

=cut
