package CryptoKit::Hash;
use strict;
use warnings;
use Crypt::Argon2 qw(argon2id_pass argon2_verify);
use Crypt::PRNG     qw(random_bytes);

sub new { bless {}, shift }

sub create {
    my ($self, $password) = @_;
    die "Password required" unless defined $password;
    my $salt = random_bytes(16);
    return argon2id_pass($password, $salt, 3, '32M', 1, 32);
}

sub verify {
    my ($self, $encoded, $password) = @_;
    return argon2_verify($encoded, $password);
}

1;

__END__

=head1 NAME

CryptoKit::Hash - Argon2id password hashing

=head1 SYNOPSIS

    my $h = CryptoKit::Hash->new;
    my $encoded = $h->create('password');
    my $ok      = $h->verify($encoded, 'password');

=head1 DESCRIPTION

Wraps L<Crypt::Argon2> with sensible parameters (3 iterations,
32 MiB memory, 1 lane, 32-byte tag) and a random 16-byte salt.

=head1 METHODS

=head2 new

Constructor.

=head2 create

    my $encoded = $h->create($password);

Returns an Argon2id-encoded hash string (safe to store in a database).

=head2 verify

    my $ok = $h->verify($encoded, $password);

Returns true if the password matches the encoded hash.

=cut
