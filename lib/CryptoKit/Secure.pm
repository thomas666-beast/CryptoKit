package CryptoKit::Secure;
use strict;
use warnings;
use Crypt::SecretBuffer;
use Crypt::Misc qw(slow_eq);

sub new { bless {}, shift }

sub wrap {
    my ($self, $data) = @_;
    return Crypt::SecretBuffer->new($data);
}

sub compare {
    my ($self, $a, $b) = @_;
    # Accept both plain scalars and SecretBuffer objects.
    if (ref $a && $a->can('memcmp')) {
        return $a->memcmp($b) == 0;
    }
    return slow_eq($a, $b);
}

1;

__END__

=head1 NAME

CryptoKit::Secure - Secure memory and constant-time comparison

=head1 SYNOPSIS

    my $s = CryptoKit::Secure->new;
    my $buf = $s->wrap('secret');
    my $eq  = $s->compare($user_token, $stored_token);

=head1 DESCRIPTION

Wraps L<Crypt::SecretBuffer> for opaque buffers that wipe their
contents on destruction, and provides a constant-time comparison
that avoids timing side channels.

=head1 METHODS

=head2 new

Constructor.

=head2 wrap

    my $buf = $s->wrap($data);

Returns a L<Crypt::SecretBuffer> containing C<$data>.

=head2 compare

    my $eq = $s->compare($a, $b);

Constant-time comparison. Accepts SecretBuffer objects or plain
scalars.

=cut
