package CryptoKit::Password;
use strict;
use warnings;
use Crypt::PRNG qw(random_bytes);

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
    die "Length must be a positive integer"
        unless defined $length && $length =~ /^\A[1-9][0-9]*\z/;
    die "Length too large (max 4096)" if $length > 4096;

    my $charset = $self->{charset};
    my $cs_len  = length $charset;
    die "Charset must be non-empty" unless $cs_len;

    # Reject the high tail that would bias the modulo.
    # 256 % cs_len is the number of values in the biased tail.
    my $limit = 256 - (256 % $cs_len);

    my $out = '';
    while (length($out) < $length) {
        for my $b (unpack('C*', random_bytes(64))) {
            next if $b >= $limit;
            $out .= substr($charset, $b % $cs_len, 1);
            last if length($out) == $length;
        }
    }
    return $out;
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
L<Crypt::PRNG> (ChaCha20, part of CryptX), with rejection sampling
to avoid modulo bias.

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
