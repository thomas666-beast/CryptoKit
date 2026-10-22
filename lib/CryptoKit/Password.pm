package CryptoKit::Password;
use strict;
use warnings;
use Crypt::PRNG qw(random_string_from);

# Build the charset without literal special characters so shell history
# expansion or paste mangling cannot corrupt the source.
my $DEFAULT_CHARSET = join '',
    'A'..'Z', 'a'..'z', '0'..'9',
    map { chr } (0x21, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A);  # ! # $ % ^ & *

sub new {
    my ($class, %opts) = @_;
    return bless {
        charset => $opts{charset} // $DEFAULT_CHARSET,
        length  => $opts{length}  // 16,
    }, $class;
}

sub generate {
    my ($self, $length) = @_;
    $length //= $self->{length};
    die "Length must be a positive integer" unless $length =~ /\A[1-9][0-9]*\z/;
    die "Length too large" if $length > 4096;
    return random_string_from($self->{charset}, $length);
}

1;

__END__

=head1 NAME

CryptoKit::Password - Strong random password generation

=head1 SYNOPSIS

    my $p = CryptoKit::Password->new;
    my $pw = $p->generate(20);

    my $custom = CryptoKit::Password->new(charset => 'ab', length => 8);
    my $short  = $custom->generate;

=head1 DESCRIPTION

Generates cryptographically strong random passwords using
L<Crypt::PRNG> (ChaCha20, part of CryptX).

=head1 METHODS

=head2 new

    CryptoKit::Password->new(%opts)

Options: C<charset> (default alphanumerics plus C<! # $ % ^ & *>) and
C<length> (default 16).

=head2 generate

    my $pw = $p->generate($length);

Returns a random password. Defaults to the length given to C<new>.
Rejects non-positive or absurdly large lengths.

=cut
