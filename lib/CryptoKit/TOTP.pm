package CryptoKit::TOTP;
use strict;
use warnings;
use Authen::OATH;

sub new {
    my ($class, %opts) = @_;
    return bless {
        digits   => $opts{digits}   // 6,
        digest   => $opts{digest}   // 'Digest::SHA',
        timestep => $opts{timestep} // 30,
    }, $class;
}

sub _oath {
    my ($self) = @_;
    return Authen::OATH->new(
        digits   => $self->{digits},
        digest   => $self->{digest},
        timestep => $self->{timestep},
    );
}

sub generate {
    my ($self, $secret, $time) = @_;
    die "Secret required" unless defined $secret;
    my $oath = $self->_oath;
    return defined $time
        ? $oath->totp($secret, $time)
        : $oath->totp($secret);
}

sub verify {
    my ($self, $secret, $code, $time, $window) = @_;
    $window //= 1;
    return 0 unless defined $secret && defined $code;
    my $oath = $self->_oath;
    my $now  = defined $time ? $time : time;
    for my $offset (-$window .. $window) {
        my $candidate = $oath->totp($secret, $now + $offset * $self->{timestep});
        return 1 if $candidate eq $code;
    }
    return 0;
}

1;

__END__

=head1 NAME

CryptoKit::TOTP - Time-based one-time passwords

=head1 SYNOPSIS

    my $t = CryptoKit::TOTP->new;
    my $code = $t->generate($secret);
    my $ok   = $t->verify($secret, $user_code);

=head1 DESCRIPTION

Wraps L<Authen::OATH> for TOTP generation and verification.
Compatible with Google Authenticator. The secret must be decoded
from Base32 before passing it here.

=head1 METHODS

=head2 new

    CryptoKit::TOTP->new(digits => 6, digest => 'Digest::SHA', timestep => 30)

=head2 generate

    my $code = $t->generate($secret, $time?);

=head2 verify

    my $ok = $t->verify($secret, $code, $time?, $window?);

Default window is 1 (checks previous, current, and next timestep).

=cut
