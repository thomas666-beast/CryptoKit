package CryptoKit::Hash;
use strict;
use warnings;
use Crypt::Argon2 qw(argon2id_pass argon2_verify);
use Crypt::PRNG     qw(random_bytes);

my $HIATALA_AVAILABLE = eval {
    require HiatalaMrk;
    1;
} ? 1 : 0;

sub new { bless {}, shift }

sub hiatala_available { $HIATALA_AVAILABLE }

sub create {
    my ($self, $password, %opt) = @_;
    die "Password required" unless defined $password;

    my $backend = $opt{backend} // 'argon2';

    if ($backend eq 'argon2') {
        my $salt = random_bytes(16);
        return argon2id_pass($password, $salt, 3, '32M', 1, 32);
    }
    if ($backend eq 'hiatala') {
        die "HiatalaMrk backend not available (install HiatalaMrk first)\n"
            unless $HIATALA_AVAILABLE;
        return HiatalaMrk::hiatala_mrk_hash({
            password => $password,
            memory   => $opt{memory} // 16384,
            passes   => $opt{passes} // 3,
            outlen   => $opt{outlen} // 32,
        });
    }
    die "Unknown backend '$backend' (use 'argon2' or 'hiatala')\n";
}

sub verify {
    my ($self, $encoded, $password, %opt) = @_;
    return 0 unless defined $encoded && defined $password;

    if ($encoded =~ /^\$argon2id\$/) {
        return argon2_verify($encoded, $password) ? 1 : 0;
    }
    if ($encoded =~ /^\$hiatalamrk\$/) {
        return 0 unless $HIATALA_AVAILABLE;
        return HiatalaMrk::hiatala_mrk_verify($encoded, $password) ? 1 : 0;
    }
    return 0;
}

1;

__END__

=head1 NAME

CryptoKit::Hash - Argon2id password hashing (with optional HiatalaMrk backend)

=head1 SYNOPSIS

    my $h = CryptoKit::Hash->new;

    # Default: Argon2id
    my $encoded = $h->create($password);
    my $ok      = $h->verify($encoded, $password);

    # Optional: HiatalaMrk
    if ($h->hiatala_available) {
        my $enc = $h->create($password, backend => 'hiatala');
        my $ok  = $h->verify($enc, $password);
    }

=head1 DESCRIPTION

Wraps L<Crypt::Argon2> for production password hashing. When
L<HiatalaMrk> is installed, an alternative backend is available via
C<< backend => 'hiatala' >>.

The encoded string is self-describing: C<verify> dispatches on the
prefix (C<$argon2id$> or C<$hiatalamrk$>), so the caller does not need
to remember which backend produced the hash.

=head1 METHODS

=head2 new

Constructor.

=head2 create

    my $encoded = $h->create($password);
    my $encoded = $h->create($password, backend => 'hiatala');
    my $encoded = $h->create($password, backend => 'hiatala', memory => 32768);

Default backend is C<'argon2'>. HiatalaMrk options: C<memory>, C<passes>,
C<outlen>.

=head2 verify

    my $ok = $h->verify($encoded, $password);

Dispatches on the encoded prefix. Returns 1 or 0.

=head2 hiatala_available

    if ($h->hiatala_available) { ... }

Returns true if L<HiatalaMrk> is installed.

=cut
