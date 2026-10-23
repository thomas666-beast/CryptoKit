package CryptoKit::HolopeinenID;
use strict;
use warnings;
use Crypt::Mac::HMAC qw(hmac);
use Crypt::PRNG qw(random_bytes);
use Crypt::Misc qw(slow_eq);
use Time::HiRes qw(time);
use MIME::Base64 qw(encode_base64url decode_base64url);

my $B62      = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
my $MAC_LEN  = 16;
my $TS_CHARS = 8;
my $SH_CHARS = 2;
my $RN_CHARS = 10;
my $CORE_LEN = $TS_CHARS + $SH_CHARS + $RN_CHARS;
my $SEP      = '.';   # not in base64url alphabet, safe as separator

sub new {
    my ($class, %opt) = @_;
    my $key = $opt{key};
    die "HolopeinenID requires a key (32+ bytes recommended)\n"
        unless defined $key && length($key) >= 16;
    my $shard = $opt{shard} // '00';
    die "shard must be exactly 2 base62 characters (got '$shard')\n"
        unless $shard =~ /^[0-9A-Za-z]{2}$/;
    return bless {
        key     => $key,
        shard   => $shard,
        mac_len => $opt{mac_len} // $MAC_LEN,
    }, $class;
}

sub issue {
    my ($self, %opt) = @_;
    my $prefix = $opt{prefix}
        or die "prefix required\n";
    die "prefix must match ^[a-z]{2,10}\$ (got '$prefix')\n"
        unless $prefix =~ /^[a-z]{2,10}$/;

    my $ms   = int(time() * 1000);
    my $ts   = _b62_encode_fixed($ms, $TS_CHARS, 'timestamp');
    my $core = $ts . $self->{shard} . _b62_random($RN_CHARS);

    my $payload_seg = '';
    my $mac_input   = $prefix . $SEP . $core;
    if (defined $opt{payload} && length $opt{payload}) {
        $payload_seg = encode_base64url($opt{payload});
        $mac_input  .= $SEP . $payload_seg;
    }

    my $mac = encode_base64url($self->_mac($mac_input));
    return join $SEP, $prefix, $core, ($payload_seg ? ($payload_seg) : ()), $mac;
}

sub verify {
    my ($self, $id) = @_;
    my %out = (ok => 0, reason => 'unknown');

    return { %out, reason => 'undef id' } unless defined $id;

    my @parts = split /\Q$SEP\E/, $id, -1;
    return { %out, reason => 'malformed' }
        unless @parts == 3 || @parts == 4;

    my $prefix = shift @parts;
    my $core   = shift @parts;
    my $mac_b64 = pop @parts;
    my $payload_seg = @parts ? $parts[0] : undef;

    return { %out, reason => 'malformed' }
        unless $prefix =~ /^[a-z]{2,10}$/;
    return { %out, reason => 'malformed' }
        unless length($core) == $CORE_LEN && $core =~ /^[0-9A-Za-z]+$/;

    my $mac_input = $prefix . $SEP . $core;
    $mac_input .= $SEP . $payload_seg if defined $payload_seg;

    my $expected_mac = $self->_mac($mac_input);
    my $actual_mac   = eval { decode_base64url($mac_b64) };
    return { %out, reason => 'bad mac encoding' } unless defined $actual_mac;
    return { %out, reason => 'mac mismatch' }
        unless length($actual_mac) == length($expected_mac)
            && slow_eq($actual_mac, $expected_mac);

    my $ts    = _b62_decode(substr($core, 0,  $TS_CHARS));
    my $shard = substr($core, $TS_CHARS,     $SH_CHARS);
    my $rand  = substr($core, $TS_CHARS + $SH_CHARS, $RN_CHARS);

    my $payload = '';
    if (defined $payload_seg && length $payload_seg) {
        my $decoded = eval { decode_base64url($payload_seg) };
        return { %out, reason => 'bad payload encoding' } unless defined $decoded;
        $payload = $decoded;
    }

    return {
        ok        => 1,
        reason    => 'ok',
        prefix    => $prefix,
        timestamp => $ts,
        shard     => $shard,
        random    => $rand,
        payload   => $payload,
    };
}

sub _mac {
    my ($self, $input) = @_;
    my $full = hmac('SHA256', $self->{key}, $input);
    return substr($full, 0, $self->{mac_len});
}

sub _b62_encode_fixed {
    my ($n, $width, $what) = @_;
    my $max = 62 ** $width;
    die "$what out of range for $width base62 chars (max $max)\n"
        if $n < 0 || $n >= $max;
    my $out = '';
    while ($n > 0) {
        my $d = $n % 62;
        $out = substr($B62, $d, 1) . $out;
        $n = int($n / 62);
    }
    $out = '0' x ($width - length($out)) . $out if length($out) < $width;
    return $out;
}

sub _b62_decode {
    my ($s) = @_;
    my $n = 0;
    $n = $n * 62 + index($B62, $_) for split //, $s;
    return $n;
}

sub _b62_random {
    my ($len) = @_;
    my $out = '';
    while (length($out) < $len) {
        for my $b (unpack('C*', random_bytes(64))) {
            next if $b >= 248;
            $out .= substr($B62, $b % 62, 1);
            last if length($out) == $len;
        }
    }
    return $out;
}

1;

__END__

=head1 NAME

CryptoKit::HolopeinenID - self-verifying, time-ordered, shard-safe IDs

=head1 SYNOPSIS

    my $hid = CryptoKit::HolopeinenID->new(key => $secret, shard => 'A3');
    my $id  = $hid->issue(prefix => 'usr', payload => 'user_42');
    # e.g. "usr.00XkP9A3f7G2mN4qR8tYu.dXNlcl80Mg.9tZ3x8LqR2fWn1A"

    my $r = $hid->verify($id);

=head1 DESCRIPTION

Format:

    [prefix].[timestamp+shard+random](.[payload])?.[MAC]

The separator is a dot (C<.>), which is not in the base64url alphabet,
so payload and MAC segments cannot be confused with the separator.

=cut
