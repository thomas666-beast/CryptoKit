package CryptoKit::FileVault;
use strict;
use warnings;
use Crypt::AuthEnc::GCM;
use Crypt::PRNG qw(random_bytes);
use Digest::SHA qw(sha256);
use File::Basename qw(basename);
use File::Path qw(make_path);

my $DEFAULT_CHUNK = 1024 * 1024;  # 1 MiB
my $MAGIC         = 'CKFV1';      # CryptoKit File Vault, v1
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
# Pack: split + encrypt + pack
# ---------------------------------------------------------------------------
sub pack {
    my ($self, $key, $in_path, $out_path) = @_;
    _check_key($key);

    open my $in, '<:raw', $in_path or die "Cannot open $in_path: $!";

    # Read whole file to compute plaintext hash. For very large files,
    # you'd hash incrementally while streaming; see the note below.
    my $plaintext = do { local $/; <$in> };
    close $in;

    my $hash       = sha256($plaintext);
    my $total      = length($plaintext);
    my $chunk_size = $self->{chunk_size};
    my $n_chunks   = int(($total + $chunk_size - 1) / $chunk_size);
    $n_chunks = 1 if $n_chunks == 0;   # empty file still gets one chunk

    # Build manifest
    my $manifest = join("\n",
        $MAGIC,
        "version=1",
        "chunk_size=$chunk_size",
        "n_chunks=$n_chunks",
        "orig_size=$total",
        "orig_name=" . basename($in_path),
        "sha256=" . unpack('H*', $hash),
    ) . "\n";

    open my $out, '>:raw', $out_path or die "Cannot open $out_path: $!";

    # Encrypt manifest: [IV][ciphertext][tag]
    my $m_iv = random_bytes($IV_LEN);
    my $m_ae = Crypt::AuthEnc::GCM->new('AES', $key, $m_iv);
    my $m_ct = $m_ae->encrypt_add($manifest);
    my $m_tag = $m_ae->encrypt_done();

    # Header: magic (5) + manifest length (4 BE) + encrypted manifest
    print $out $MAGIC;
    print $out pack('N', $IV_LEN + length($m_ct) + $TAG_LEN);
    print $out $m_iv, $m_ct, $m_tag;

    # Encrypt each chunk independently
    for my $i (0 .. $n_chunks - 1) {
        my $offset = $i * $chunk_size;
        my $chunk  = substr($plaintext, $offset, $chunk_size);

        my $iv = random_bytes($IV_LEN);
        my $ae = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
        my $ct = $ae->encrypt_add($chunk);
        my $tag = $ae->encrypt_done();

        # Each record: [4 BE plaintext len][IV][tag][ciphertext]
        print $out pack('N', length($chunk));
        print $out $iv, $tag, $ct;
    }

    close $out;
    return {
        n_chunks   => $n_chunks,
        orig_size  => $total,
        chunk_size => $chunk_size,
        sha256     => unpack('H*', $hash),
    };
}

# ---------------------------------------------------------------------------
# Unpack: read + decrypt + reassemble
# ---------------------------------------------------------------------------
sub unpack {
    my ($self, $key, $in_path, $out_path) = @_;
    _check_key($key);

    open my $in, '<:raw', $in_path or die "Cannot open $in_path: $!";

    # Read and verify magic
    read($in, my $magic, 5) == 5 or die "Truncated file: no magic";
    die "Not a CryptoKit FileVault file (bad magic)" unless $magic eq $MAGIC;

    # Read and decrypt manifest
    read($in, my $mlen_buf, 4) == 4 or die "Truncated file: no manifest length";
    my $mlen = unpack('N', $mlen_buf);
    read($in, my $mblob, $mlen) == $mlen or die "Truncated file: manifest";

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

    my $n_chunks   = $meta{n_chunks}   or die "Manifest missing n_chunks";
    my $chunk_size = $meta{chunk_size} or die "Manifest missing chunk_size";
    my $orig_size  = $meta{orig_size} // 0;
    my $expected_sha = $meta{sha256}   or die "Manifest missing sha256";

    # Decrypt each chunk
    my $plaintext = '';
    for my $i (0 .. $n_chunks - 1) {
        read($in, my $len_buf, 4) == 4 or die "Truncated chunk $i: no length";
        my $pt_len = unpack('N', $len_buf);

        read($in, my $hdr, $IV_LEN + $TAG_LEN) == $IV_LEN + $TAG_LEN
            or die "Truncated chunk $i: no header";
        my $iv  = substr($hdr, 0, $IV_LEN);
        my $tag = substr($hdr, $IV_LEN, $TAG_LEN);

        my $ct_len = $pt_len;   # GCM ciphertext length equals plaintext length
        read($in, my $ct, $ct_len) == $ct_len
            or die "Truncated chunk $i: short ciphertext";

        my $ae = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
        my $pt = $ae->decrypt_add($ct);
        $ae->decrypt_done($tag) or die "Chunk $i authentication failed";

        $plaintext .= $pt;
    }
    close $in;

    die "Reassembled size mismatch (expected $orig_size, got "
        . length($plaintext) . ")" unless length($plaintext) == $orig_size;

    my $actual_sha = unpack('H*', sha256($plaintext));
    die "Reassembled SHA-256 mismatch (expected $expected_sha, got $actual_sha)"
        unless $actual_sha eq $expected_sha;

    open my $out, '>:raw', $out_path or die "Cannot open $out_path: $!";
    print $out $plaintext;
    close $out;

    return {
        n_chunks  => $n_chunks,
        orig_size => $orig_size,
        sha256    => $actual_sha,
    };
}

# ---------------------------------------------------------------------------
# Split into separate encrypted chunk files (for distribution)
# ---------------------------------------------------------------------------
sub split {
    my ($self, $key, $in_path, $out_dir, %opt) = @_;
    _check_key($key);

    make_path($out_dir) unless -d $out_dir;
    die "Not a directory: $out_dir" unless -d $out_dir;

    open my $in, '<:raw', $in_path or die "Cannot open $in_path: $!";
    my $plaintext = do { local $/; <$in> };
    close $in;

    my $hash       = sha256($plaintext);
    my $total      = length($plaintext);
    my $chunk_size = $opt{chunk_size} // $self->{chunk_size};
    my $n_chunks   = int(($total + $chunk_size - 1) / $chunk_size);
    $n_chunks = 1 if $n_chunks == 0;

    my $basename = basename($in_path);

    # Write manifest file (encrypted, same format as pack's header)
    my $manifest = join("\n",
        $MAGIC,
        "version=1",
        "chunk_size=$chunk_size",
        "n_chunks=$n_chunks",
        "orig_size=$total",
        "orig_name=$basename",
        "sha256=" . unpack('H*', $hash),
    ) . "\n";

    my $m_iv  = random_bytes($IV_LEN);
    my $m_ae  = Crypt::AuthEnc::GCM->new('AES', $key, $m_iv);
    my $m_ct  = $m_ae->encrypt_add($manifest);
    my $m_tag = $m_ae->encrypt_done();

    my $manifest_path = "$out_dir/$basename.ckfv-manifest";
    open my $mf, '>:raw', $manifest_path or die "Cannot write $manifest_path: $!";
    print $mf $MAGIC, pack('N', $IV_LEN + length($m_ct) + $TAG_LEN),
              $m_iv, $m_ct, $m_tag;
    close $mf;

    # Write each chunk as a separate file
    my @chunk_files;
    for my $i (0 .. $n_chunks - 1) {
        my $offset = $i * $chunk_size;
        my $chunk  = substr($plaintext, $offset, $chunk_size);

        my $iv  = random_bytes($IV_LEN);
        my $ae  = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
        my $ct  = $ae->encrypt_add($chunk);
        my $tag = $ae->encrypt_done();

        my $chunk_path = sprintf('%s/%s.ckfv-%04d', $out_dir, $basename, $i);
        open my $cf, '>:raw', $chunk_path or die "Cannot write $chunk_path: $!";
        print $cf pack('N', length($chunk)), $iv, $tag, $ct;
        close $cf;

        push @chunk_files, $chunk_path;
    }

    return {
        manifest   => $manifest_path,
        chunks     => \@chunk_files,
        n_chunks   => $n_chunks,
        orig_size  => $total,
        sha256     => unpack('H*', $hash),
    };
}

# ---------------------------------------------------------------------------
# Join separate encrypted chunk files back into a single file
# ---------------------------------------------------------------------------
sub join {
    my ($self, $key, $manifest_path, $out_path) = @_;
    _check_key($key);

    open my $mf, '<:raw', $manifest_path
        or die "Cannot open $manifest_path: $!";
    read($mf, my $magic, 5) == 5 or die "Truncated manifest: no magic";
    die "Not a CryptoKit FileVault manifest" unless $magic eq $MAGIC;

    read($mf, my $mlen_buf, 4) == 4 or die "Truncated manifest: no length";
    my $mlen = unpack('N', $mlen_buf);
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
    my $expected_sha = $meta{sha256}     or die "Manifest missing sha256";
    my $basename     = $meta{orig_name} // 'output';

    my $dir = $manifest_path;
    $dir =~ s{/[^/]+$}{};

    my $plaintext = '';
    for my $i (0 .. $n_chunks - 1) {
        my $chunk_path = sprintf('%s/%s.ckfv-%04d', $dir, $basename, $i);
        open my $cf, '<:raw', $chunk_path
            or die "Cannot open chunk $i ($chunk_path): $!";

        read($cf, my $len_buf, 4) == 4 or die "Truncated chunk $i: no length";
        my $pt_len = unpack('N', $len_buf);

        read($cf, my $hdr, $IV_LEN + $TAG_LEN) == $IV_LEN + $TAG_LEN
            or die "Truncated chunk $i: no header";
        my $iv  = substr($hdr, 0, $IV_LEN);
        my $tag = substr($hdr, $IV_LEN, $TAG_LEN);

        read($cf, my $ct, $pt_len) == $pt_len
            or die "Truncated chunk $i: short ciphertext";
        close $cf;

        my $ae = Crypt::AuthEnc::GCM->new('AES', $key, $iv);
        my $pt = $ae->decrypt_add($ct);
        $ae->decrypt_done($tag) or die "Chunk $i authentication failed";

        $plaintext .= $pt;
    }

    die "Reassembled size mismatch" unless length($plaintext) == $orig_size;
    my $actual_sha = unpack('H*', sha256($plaintext));
    die "Reassembled SHA-256 mismatch" unless $actual_sha eq $expected_sha;

    open my $out, '>:raw', $out_path or die "Cannot open $out_path: $!";
    print $out $plaintext;
    close $out;

    return {
        n_chunks  => $n_chunks,
        orig_size => $orig_size,
        sha256    => $actual_sha,
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

    # Single container
    $v->pack($key, 'plain.txt', 'secret.ckfv');
    $v->unpack($key, 'secret.ckfv', 'plain.out');

    # Split into separate files (for distribution)
    my $info = $v->split($key, 'plain.txt', 'vault-dir/');
    # $info->{manifest}, $info->{chunks}->[0..N]

    # Reassemble from split files
    $v->join($key, 'vault-dir/plain.txt.ckfv-manifest', 'plain.out');

=head1 DESCRIPTION

Splits a file into fixed-size chunks, encrypts each chunk independently
with AES-256-GCM, and packs them with a self-describing manifest.

Two modes:

=over 4

=item B<Container mode> (C<pack>/C<unpack>): one file containing
header + encrypted manifest + encrypted chunks.

=item B<Split mode> (C<split>/C<join>): one encrypted manifest file
plus one encrypted file per chunk, so chunks can be distributed or
decrypted in parallel.

=back

Each chunk gets its own random IV and its own GCM tag, so a corrupted
chunk is identified precisely. The manifest records the number of
chunks, chunk size, original filename, original size, and SHA-256 of
the whole plaintext. The manifest is itself encrypted with the same key.

=head1 FORMAT

Container mode:

    [5 bytes magic "CKFV1"]
    [4 bytes BE manifest length]
    [12-byte manifest IV][encrypted manifest][16-byte manifest tag]
    per chunk:
        [4 bytes BE plaintext length][12-byte IV][16-byte tag][ciphertext]

Split mode:

    <basename>.ckfv-manifest  - encrypted manifest (same header format)
    <basename>.ckfv-NNNN      - one encrypted chunk per file

=head1 METHODS

=head2 new

    CryptoKit::FileVault->new(chunk_size => 1048576)

Chunk size defaults to 1 MiB. Applies to pack and split.

=head2 pack

    my $info = $v->pack($key, $in_path, $out_path);

Returns a hashref with n_chunks, orig_size, chunk_size, sha256.

=head2 unpack

    my $info = $v->unpack($key, $in_path, $out_path);

Dies on wrong key, tampered chunk, size mismatch, or SHA-256 mismatch.

=head2 split

    my $info = $v->split($key, $in_path, $out_dir, chunk_size => 65536);

Writes one manifest and one file per chunk. Returns manifest path,
chunk paths, n_chunks, orig_size, sha256.

=head2 join

    my $info = $v->join($key, $manifest_path, $out_path);

Dies on wrong key, tampered chunk, or SHA-256 mismatch.

=cut
