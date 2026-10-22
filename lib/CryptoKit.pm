package CryptoKit;
use strict;
use warnings;
our $VERSION = '0.01';

my %MODULES = (
    hash     => 'CryptoKit::Hash',
    password => 'CryptoKit::Password',
    key      => 'CryptoKit::Key',
    encrypt  => 'CryptoKit::Encrypt',
    secure   => 'CryptoKit::Secure',
);

sub new { bless {}, shift }

sub module {
    my ($self, $name) = @_;
    my $pkg = $MODULES{$name} or die "Unknown CryptoKit module: $name";
    unless ($pkg->can('new')) {
        (my $file = $pkg) =~ s{::}{/}g;
        require "$file.pm";
    }
    return $pkg;
}

sub hash     { $_[0]->module('hash')->new(@_[1..$#_]) }
sub password { $_[0]->module('password')->new(@_[1..$#_]) }
sub key      { $_[0]->module('key')->new(@_[1..$#_]) }
sub encrypt  { $_[0]->module('encrypt')->new(@_[1..$#_]) }
sub secure   { $_[0]->module('secure')->new(@_[1..$#_]) }

1;

__END__

=head1 NAME

CryptoKit - A modular cryptographic toolkit for Perl

=head1 SYNOPSIS

    use CryptoKit;
    my $kit = CryptoKit->new;

    my $hash = $kit->hash->create('password');
    my $pw   = $kit->password->generate(20);
    my $kp   = $kit->key->generate;
    my $sig  = $kit->key->sign($kp->{private_pem}, 'message');
    my $ok   = $kit->key->verify($kp->{public_pem}, $sig, 'message');

    my $blob = $kit->encrypt->encrypt($kp->{public_pem}, 'secret');
    my $text = $kit->encrypt->decrypt($kp->{private_pem}, $blob);

=head1 DESCRIPTION

CryptoKit provides password hashing (Argon2id), secure random password
generation, ECC key management with sign/verify, hybrid encryption,
and secure memory handling, all through lazily loaded submodules.

=head1 METHODS

=head2 new

    my $kit = CryptoKit->new;

Creates a new CryptoKit instance.

=head2 module

    my $pkg = $kit->module('hash');

Returns the package name for a given submodule key, loading it on
demand.

=head2 hash

Returns a L<CryptoKit::Hash> instance for Argon2id password hashing.

=head2 password

Returns a L<CryptoKit::Password> instance for strong random passwords.

=head2 key

Returns a L<CryptoKit::Key> instance for ECC key generation and
signing.

=head2 encrypt

Returns a L<CryptoKit::Encrypt> instance for hybrid ECC + AES-GCM
encryption.

=head2 secure

Returns a L<CryptoKit::Secure> instance for secure memory handling
and constant-time comparison.

=cut
