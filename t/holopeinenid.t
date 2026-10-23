use Test2::V0;
use lib 'lib';
use CryptoKit;
use Crypt::PRNG qw(random_bytes);

my $key = random_bytes(32);
my $hid = CryptoKit->new->holopeinen_id(key => $key, shard => 'A3');

# --- Basic issue + verify ---
{
    my $id = $hid->issue(prefix => 'usr', payload => 'user_42');
    like $id, qr/^usr\.[0-9A-Za-z]{20}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
        'ID has prefix, core, payload, MAC';

    my $r = $hid->verify($id);
    ok $r->{ok}, 'verify succeeds';
    is $r->{prefix}, 'usr', 'prefix extracted';
    is $r->{payload}, 'user_42', 'payload extracted';
    is $r->{shard}, 'A3', 'shard extracted';
    cmp_ok $r->{timestamp}, '>', 1_700_000_000_000, 'timestamp is plausible';
}

# --- No payload ---
{
    my $id = $hid->issue(prefix => 'ses');
    like $id, qr/^ses\.[0-9A-Za-z]{20}\.[A-Za-z0-9_-]+$/,
        'ID without payload has prefix, core, MAC';
    my $r = $hid->verify($id);
    ok $r->{ok}, 'no-payload ID verifies';
    is $r->{payload}, '', 'payload is empty';
}

# --- Tampered core rejected ---
{
    my $id = $hid->issue(prefix => 'usr');
    my @p = split /\./, $id;
    $p[1] =~ s/^./X/;
    my $tampered = join '.', @p;
    ok !$hid->verify($tampered)->{ok}, 'tampered core rejected';
}

# --- Tampered prefix rejected ---
{
    my $id = $hid->issue(prefix => 'usr');
    my @p = split /\./, $id;
    $p[0] = 'inv';
    my $tampered = join '.', @p;
    ok !$hid->verify($tampered)->{ok}, 'cross-prefix forgery rejected';
}

# --- Tampered payload rejected ---
{
    my $id = $hid->issue(prefix => 'usr', payload => 'abc');
    my @p = split /\./, $id;
    $p[2] = 'X' . $p[2];
    my $tampered = join '.', @p;
    ok !$hid->verify($tampered)->{ok}, 'tampered payload rejected';
}

# --- Wrong key rejected ---
{
    my $id = $hid->issue(prefix => 'usr');
    my $other = CryptoKit->new->holopeinen_id(key => random_bytes(32), shard => 'A3');
    ok !$other->verify($id)->{ok}, 'wrong key rejected';
}

# --- Different shard still verifies ---
{
    my $id = $hid->issue(prefix => 'usr');
    my $other = CryptoKit->new->holopeinen_id(key => $key, shard => 'B7');
    my $r = $other->verify($id);
    ok $r->{ok}, 'different shard verifies with same key';
    is $r->{shard}, 'A3', 'shard preserved from ID';
}

# --- Time ordering within a shard ---
{
    my @ids;
    for (1 .. 5) {
        push @ids, $hid->issue(prefix => 'seq');
        select undef, undef, undef, 0.002;
    }
    my @sorted = sort @ids;
    is \@sorted, \@ids, 'IDs sort in creation order';
}

# --- Uniqueness ---
{
    my %seen;
    my $dups = 0;
    for (1 .. 1000) {
        my $id = $hid->issue(prefix => 'tok', payload => 'same');
        $dups++ if $seen{$id}++;
    }
    is $dups, 0, '1000 IDs with same payload are distinct';
}

# --- Malformed ---
{
    for my $bad ('garbage', '', undef, 'usr.short', 'usr_a_b_c_d') {
        my $r = $hid->verify($bad);
        ok !$r->{ok}, 'malformed rejected: ' . (defined $bad ? "'$bad'" : 'undef');
    }
}

# --- Constructor validation ---
{
    ok dies { CryptoKit::HolopeinenID->new() }, 'constructor requires key';
    ok dies { CryptoKit::HolopeinenID->new(key => 'short') }, 'key < 16 bytes rejected';
    ok dies { CryptoKit::HolopeinenID->new(key => 'x' x 16, shard => 'X') }, 'shard length 1 rejected';
    ok dies { CryptoKit::HolopeinenID->new(key => 'x' x 16, shard => 'XYZ') }, 'shard length 3 rejected';
    ok dies { CryptoKit::HolopeinenID->new(key => 'x' x 16, shard => 'X!') }, 'shard non-base62 rejected';
    ok lives { CryptoKit::HolopeinenID->new(key => 'x' x 16, shard => '0Z') }, 'valid shard accepted';
}

done_testing;
