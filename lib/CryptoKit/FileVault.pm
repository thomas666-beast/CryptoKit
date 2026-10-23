package CryptoKit::FileVault;
use strict;
use warnings;
use Crypt::AuthEnc::GCM;
use Crypt::PRNG qw(random_bytes);
use Digest::SHA;
use File::Basename qw(basename);
use File::Path qw(make_path);

my $DEFAULT_CHUNK = 1024 * 1024;
my $MAGIC         = 'CKFV1';
my $IV_LEN        = 12;
my $TAG_LEN       = 16;
my $KEY_LEN       = 32;

sub new {
    my ($class, %opts) = @_;
    return bless {
        chunk_size => $opts{chunk_size} // $DEFAULT_CHUNK,
    }, $class;
}

# ---------------------------------------------------------------------------
# Container mode: pack
# ---------------------------------------------------------------------------
sub pack {
    my ($self, $key, $in_path, $out_path, %opt) = @_;
    _check_key($key);

    my $chunk_size = $opt{chunk_size} // $self->{chunk_size};
    die "chunk_size must be a positive integer"
        unless $chunk_size =~ /^\d+$/ && $chunk_size > 0;

    open my $in, '<:raw', $in_path or die "Cannot open $in_path: $!";
    open my $out, '>:raw', $out_path or die "Cannot open $out_path: $!";

    my $sha      = Digest::SHA->new(256);
    my $total    = 0;
    my $n_chunks = 0;

    # We need to write the manifest first but it contains the SHA-256 of
    # the whole plaintext. Two passes over the input solves this without
    # any seeks: first pass hashes, second pass encrypts.
    while (read($in, my $buf, $chunk_size)) {
        $sha->add($buf);
        $total += length($buf);
        $n_chunks++;
    }
    close $in;

    # Empty file still gets one empty chunk in the container
    my $empty_chunk = 0;
    if ($n_chunks == 0) {
        $n_chunks    = 1;
        $empty_chunk = 1;
    }

    my $hex = $sha->hexdigest;

    my $manifest = join("\n",
        $MAGIC,
        "version=1",
        "chunk_size=$chunk_size",
        "n_chunks=$n_chunks",
        "orig_size=$total",
        "orig_name=" . basename($in_path),
        "sha256=$hex",
    ) . "\n";

    my $m_iv  = random_bytes($IV_LEN);
    my $m_ae  = Crypt::AuthEnc::GCM->new('AES', $key, $m_iv);
    my $m_ct  = $m_ae->encrypt_add($manifest);
    my $m_tag = $m_ae->encrypt_done();
    my $mblob = $m_iv . $m_ct . $m_tag;

    print $out $MAGIC, CORE::pack('N', length($mblob)), $mblob;

    if ($empty_chunk) {
        my $iv  = random_bytes($IV_LEN);
        my $ae  = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
        my $ct  = $ae->encrypt_add('');
        my $tag = $ae->encrypt_done();
        print $out CORE::pack('N', 0), $iv, $tag, $ct;
    }
    else {
        open $in, '<:raw', $in_path or die "Cannot reopen $in_path: $!";
        while (read($in, my $buf, $chunk_size)) {
            my $iv  = random_bytes($IV_LEN);
            my $ae  = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
            my $ct  = $ae->encrypt_add($buf);
            my $tag = $ae->encrypt_done();
            print $out CORE::pack('N', length($buf)), $iv, $tag, $ct;
        }
        close $in;
    }

    close $out;
    return {
        n_chunks   => $n_chunks,
        orig_size  => $total,
        chunk_size => $chunk_size,
        sha256     => $hex,
    };
}

# ---------------------------------------------------------------------------
# Container mode: unpack
# ---------------------------------------------------------------------------
sub unpack {
    my ($self, $key, $in_path, $out_path) = @_;
    _check_key($key);

    open my $in, '<:raw', $in_path or die "Cannot open $in_path: $!";

    read($in, my $magic, 5) == 5 or die "Truncated: no magic";
    die "Not a CryptoKit FileVault file (bad magic)" unless $magic eq $MAGIC;

    read($in, my $mlen_buf, 4) == 4 or die "Truncated: no manifest length";
    my $mlen = CORE::unpack('N', $mlen_buf);
    read($in, my $mblob, $mlen) == $mlen or die "Truncated: manifest";

    my $m_iv  = substr($mblob, 0, $IV_LEN);
    my $m_tag = substr($mblob, -$TAG_LEN);
    my $m_ct  = substr($mblob, $IV_LEN, length($mblob) - $IV_LEN - $TAG_LEN);

    my $m_ae = Crypt::AuthEnc::GCM->new('AES', $key, $m_iv);
    my $manifest = $m_ae->decrypt_add($m_ct);
    $m_ae->decrypt_done($m_tag) or die "Manifest authentication failed";

    my %meta;
    for my $line (split /\n/, $manifest) {
        next unless $line;
        my ($k, $v) = split /=/, $line, 2;
        $meta{$k} = $v;
    }
    die "Unsupported manifest version" unless ($meta{version} // '') eq '1';

    my $n_chunks     = $meta{n_chunks}   or die "Manifest missing n_chunks";
    my $orig_size    = $meta{orig_size} // 0;
    my $expected_hex = $meta{sha256}     or die "Manifest missing sha256";

    open my $out, '>:raw', $out_path or die "Cannot open $out_path: $!";
    my $sha   = Digest::SHA->new(256);
    my $total = 0;

    for my $i (0 .. $n_chunks - 1) {
        read($in, my $len_buf, 4) == 4 or die "Truncated chunk $i: no length";
        my $pt_len = CORE::unpack('N', $len_buf);

        read($in, my $hdr, $IV_LEN + $TAG_LEN) == $IV_LEN + $TAG_LEN
            or die "Truncated chunk $i: no header";
        my $iv  = substr($hdr, 0, $IV_LEN);
        my $tag = substr($hdr, $IV_LEN, $TAG_LEN);

        my $ct = '';
        if ($pt_len > 0) {
            read($in, $ct, $pt_len) == $pt_len
                or die "Truncated chunk $i: short ciphertext";
        }

        my $ae = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
        my $pt = $ae->decrypt_add($ct);
        $ae->decrypt_done($tag) or die "Chunk $i authentication failed";

        print $out $pt;
        $sha->add($pt);
        $total += length($pt);
    }
    close $in;
    close $out;

    die "Reassembled size mismatch (expected $orig_size, got $total)"
        unless $total == $orig_size;

    my $actual_hex = $sha->hexdigest;
    die "Reassembled SHA-256 mismatch (expected $expected_hex, got $actual_hex)"
        unless $actual_hex eq $expected_hex;

    return {
        n_chunks  => $n_chunks,
        orig_size => $orig_size,
        sha256    => $actual_hex,
    };
}

# ---------------------------------------------------------------------------
# Split mode: split
# ---------------------------------------------------------------------------
sub split {
    my ($self, $key, $in_path, $out_dir, %opt) = @_;
    _check_key($key);

    make_path($out_dir) unless -d $out_dir;
    die "Not a directory: $out_dir" unless -d $out_dir;

    my $chunk_size = $opt{chunk_size} // $self->{chunk_size};
    die "chunk_size must be a positive integer"
        unless $chunk_size =~ /^\d+$/ && $chunk_size > 0;

    my $basename = basename($in_path);

    # First pass: hash and count chunks
    open my $in, '<:raw', $in_path or die "Cannot open $in_path: $!";
    my $sha   = Digest::SHA->new(256);
    my $total = 0;
    my $n     = 0;
    while (read($in, my $buf, $chunk_size)) {
        $sha->add($buf);
        $total += length($buf);
        $n++;
    }
    close $in;

    my $empty = 0;
    if ($n == 0) { $n = 1; $empty = 1; }
    my $hex = $sha->hexdigest;

    my $manifest = join("\n",
        $MAGIC,
        "version=1",
        "chunk_size=$chunk_size",
        "n_chunks=$n",
        "orig_size=$total",
        "orig_name=$basename",
        "sha256=$hex",
    ) . "\n";

    my $m_iv  = random_bytes($IV_LEN);
    my $m_ae  = Crypt::AuthEnc::GCM->new('AES', $key, $m_iv);
    my $m_ct  = $m_ae->encrypt_add($manifest);
    my $m_tag = $m_ae->encrypt_done();
    my $mblob = $m_iv . $m_ct . $m_tag;

    my $manifest_path = "$out_dir/$basename.ckfv-manifest";
    open my $mf, '>:raw', $manifest_path or die "Cannot write $manifest_path: $!";
    print $mf $MAGIC, CORE::pack('N', length($mblob)), $mblob;
    close $mf;

    my @chunk_files;
    if ($empty) {
        my $iv  = random_bytes($IV_LEN);
        my $ae  = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
        my $ct  = $ae->encrypt_add('');
        my $tag = $ae->encrypt_done();

        my $chunk_path = sprintf('%s/%s.ckfv-%04d', $out_dir, $basename, 0);
        open my $cf, '>:raw', $chunk_path or die "Cannot write $chunk_path: $!";
        print $cf CORE::pack('N', 0), $iv, $tag, $ct;
        close $cf;
        push @chunk_files, $chunk_path;
    }
    else {
        open $in, '<:raw', $in_path or die "Cannot reopen $in_path: $!";
        my $i = 0;
        while (read($in, my $buf, $chunk_size)) {
            my $iv  = random_bytes($IV_LEN);
            my $ae  = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
            my $ct  = $ae->encrypt_add($buf);
            my $tag = $ae->encrypt_done();

            my $chunk_path = sprintf('%s/%s.ckfv-%04d', $out_dir, $basename, $i);
            open my $cf, '>:raw', $chunk_path or die "Cannot write $chunk_path: $!";
            print $cf CORE::pack('N', length($buf)), $iv, $tag, $ct;
            close $cf;

            push @chunk_files, $chunk_path;
            $i++;
        }
        close $in;
    }

    return {
        manifest  => $manifest_path,
        chunks    => \@chunk_files,
        n_chunks  => $n,
        orig_size => $total,
        sha256    => $hex,
    };
}

# ---------------------------------------------------------------------------
# Split mode: join
# ---------------------------------------------------------------------------
sub join {
    my ($self, $key, $manifest_path, $out_path) = @_;
    _check_key($key);

    open my $mf, '<:raw', $manifest_path or die "Cannot open $manifest_path: $!";
    read($mf, my $magic, 5) == 5 or die "Truncated manifest: no magic";
    die "Not a CryptoKit FileVault manifest" unless $magic eq $MAGIC;

    read($mf, my $mlen_buf, 4) == 4 or die "Truncated manifest: no length";
    my $mlen = CORE::unpack('N', $mlen_buf);
    read($mf, my $mblob, $mlen) == $mlen or die "Truncated manifest: body";
    close $mf;

    my $m_iv  = substr($mblob, 0, $IV_LEN);
    my $m_tag = substr($mblob, -$TAG_LEN);
    my $m_ct  = substr($mblob, $IV_LEN, length($mblob) - $IV_LEN - $TAG_LEN);

    my $m_ae = Crypt::AuthEnc::GCM->new('AES', $key, $m_iv);
    my $manifest = $m_ae->decrypt_add($m_ct);
    $m_ae->decrypt_done($m_tag) or die "Manifest authentication failed";

    my %meta;
    for my $line (split /\n/, $manifest) {
        next unless $line;
        my ($k, $v) = split /=/, $line, 2;
        $meta{$k} = $v;
    }
    die "Unsupported manifest version" unless ($meta{version} // '') eq '1';

    my $n_chunks     = $meta{n_chunks}   or die "Manifest missing n_chunks";
    my $orig_size    = $meta{orig_size} // 0;
    my $expected_hex = $meta{sha256}     or die "Manifest missing sha256";
    my $basename     = $meta{orig_name}  // 'output';

    my $dir = $manifest_path;
    $dir =~ s{/[^/]+$}{};

    open my $out, '>:raw', $out_path or die "Cannot open $out_path: $!";
    my $sha   = Digest::SHA->new(256);
    my $total = 0;

    for my $i (0 .. $n_chunks - 1) {
        my $chunk_path = sprintf('%s/%s.ckfv-%04d', $dir, $basename, $i);
        open my $cf, '<:raw', $chunk_path or die "Cannot open chunk $i: $!";

        read($cf, my $len_buf, 4) == 4 or die "Truncated chunk $i: no length";
        my $pt_len = CORE::unpack('N', $len_buf);

        read($cf, my $hdr, $IV_LEN + $TAG_LEN) == $IV_LEN + $TAG_LEN
            or die "Truncated chunk $i: no header";
        my $iv  = substr($hdr, 0, $IV_LEN);
        my $tag = substr($hdr, $IV_LEN, $TAG_LEN);

        my $ct = '';
        if ($pt_len > 0) {
            read($cf, $ct, $pt_len) == $pt_len
                or die "Truncated chunk $i: short ciphertext";
        }
        close $cf;

        my $ae = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
        my $pt = $ae->decrypt_add($ct);
        $ae->decrypt_done($tag) or die "Chunk $i authentication failed";

        print $out $pt;
        $sha->add($pt);
        $total += length($pt);
    }
    close $out;

    die "Reassembled size mismatch (expected $orig_size, got $total)"
        unless $total == $orig_size;

    my $actual_hex = $sha->hexdigest;
    die "Reassembled SHA-256 mismatch (expected $expected_hex, got $actual_hex)"
        unless $actual_hex eq $expected_hex;

    return {
        n_chunks  => $n_chunks,
        orig_size => $orig_size,
        sha256    => $actual_hex,
    };
}

# ---------------------------------------------------------------------------
sub _check_key {
    my ($key) = @_;
    die "Key must be exactly 32 bytes (got "
        . (defined $key ? length($key) : 'undef') . ")\n"
        unless defined $key && length($key) == $KEY_LEN;
}

1;

__END__

=head1 NAME

CryptoKit::FileVault - Split, encrypt, pack, and reassemble files

=head1 SYNOPSIS

    my $v = CryptoKit::FileVault->new;
    my $key = random_bytes(32);

    # Container mode
    $v->pack($key, 'plain.txt', 'secret.ckfv');
    $v->unpack($key, 'secret.ckfv', 'plain.out');

    # Split mode
    my $info = $v->split($key, 'plain.txt', 'vault-dir/');
    $v->join($key, 'vault-dir/plain.txt.ckfv-manifest', 'plain.out');

=head1 DESCRIPTION

Splits a file into fixed-size chunks, encrypts each chunk independently
with AES-256-GCM, and packs them with an encrypted manifest.

Format:

    [magic "CKFV1"]
    [4-byte BE manifest length]
    [12-byte manifest IV][encrypted manifest][16-byte manifest tag]
    [4-byte BE plaintext length][12-byte IV][16-byte tag][ciphertext]
    ... repeat per chunk ...

The manifest records n_chunks, chunk_size, orig_size, orig_name, and
sha256 of the plaintext. Empty files are encoded as one empty chunk so
the on-disk format is uniform.

=head1 METHODS

=head2 new

    CryptoKit::FileVault->new(chunk_size => 1048576)

Chunk size defaults to 1 MiB.

=head2 pack

    my $info = $v->pack($key, $in, $out);

Returns a hashref with n_chunks, orig_size, chunk_size, sha256.

=head2 unpack

    my $info = $v->unpack($key, $in, $out);

Dies on wrong key, tampered chunk, size mismatch, or SHA-256 mismatch.

=head2 split

    my $info = $v->split($key, $in, $out_dir);

Writes one manifest and one file per chunk.

=head2 join

    my $info = $v->join($key, $manifest_path, $out_path);

=cut
