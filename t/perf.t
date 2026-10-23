use Test2::V0;
use lib 'lib';
use CryptoKit;
use Time::HiRes qw(time);
use Crypt::PRNG qw(random_bytes);
use File::Temp qw(tempdir);

SKIP: {
    skip 'set AUTHOR_TESTING=1 to run perf benchmarks', 10
        unless $ENV{AUTHOR_TESTING};

    my $kit = CryptoKit->new;
    my $dir = tempdir(CLEANUP => 1);

    # --- Password generation throughput ---
    {
        my $p = $kit->password;
        my $n = 10_000;
        my $t0 = time;
        $p->generate(20) for 1 .. $n;
        my $dt = time - $t0;
        diag sprintf("Password->generate(20) x %d: %.3fs (%.0f/s)",
            $n, $dt, $n / $dt);
    }

    # --- HMAC throughput ---
    {
        my $h = $kit->hmac;
        my $key = 'benchmark-key-32-bytes-long-here';
        my $n = 10_000;
        my $t0 = time;
        $h->create($key, 'message') for 1 .. $n;
        my $dt = time - $t0;
        diag sprintf("HMAC->create x %d: %.3fs (%.0f/s)", $n, $dt, $n / $dt);
    }

    # --- Argon2id hashing time (one shot, not a loop) ---
    {
        my $h = $kit->hash;
        my $t0 = time;
        $h->create('benchmark-password');
        my $dt = time - $t0;
        diag sprintf("Hash->create (Argon2id, 32 MiB, 3 passes): %.3fs", $dt);
    }

    # --- FileEncrypt round-trip on 10 MB ---
    {
        my $f   = $kit->file_encrypt;
        my $key = random_bytes(32);
        my $size = 10 * 1024 * 1024;
        my $in  = "$dir/plain-10mb.bin";
        my $enc = "$dir/enc-10mb.bin";
        my $out = "$dir/dec-10mb.bin";

        open my $fh, '>:raw', $in or die $!;
        my $buf = random_bytes(1024 * 1024);
        print $fh $buf for 1 .. 10;
        close $fh;

        my $t0 = time;
        $f->encrypt_file($key, $in, $enc);
        my $t_enc = time - $t0;

        my $t1 = time;
        $f->decrypt_file($key, $enc, $out);
        my $t_dec = time - $t1;

        diag sprintf("FileEncrypt 10 MB: encrypt %.3fs, decrypt %.3fs, total %.3fs",
            $t_enc, $t_dec, $t_enc + $t_dec);

        open my $a, '<:raw', $in  or die $!;
        open my $b, '<:raw', $out or die $!;
        my $da = do { local $/; <$a> };
        my $db = do { local $/; <$b> };
        close $a; close $b;
        is length($db), length($da), 'FileEncrypt round-trip preserves size';
    }

    # --- FileVault pack/unpack on 10 MB ---
    {
        my $v   = $kit->file_vault;
        my $key = random_bytes(32);
        my $in  = "$dir/vault-in-10mb.bin";
        my $enc = "$dir/vault-10mb.ckfv";
        my $out = "$dir/vault-out-10mb.bin";

        open my $fh, '>:raw', $in or die $!;
        my $buf = random_bytes(1024 * 1024);
        print $fh $buf for 1 .. 10;
        close $fh;

        my $t0 = time;
        $v->pack($key, $in, $enc);
        my $t_pack = time - $t0;

        my $t1 = time;
        $v->unpack($key, $enc, $out);
        my $t_unpack = time - $t1;

        diag sprintf("FileVault 10 MB: pack %.3fs, unpack %.3fs, total %.3fs",
            $t_pack, $t_unpack, $t_pack + $t_unpack);

        open my $a, '<:raw', $in  or die $!;
        open my $b, '<:raw', $out or die $!;
        my $da = do { local $/; <$a> };
        my $db = do { local $/; <$b> };
        close $a; close $b;
        is length($db), length($da), 'FileVault round-trip preserves size';
    }

    # --- Memory high-water mark for FileEncrypt/FileVault ---
    # Uses getrusage to check RSS; Linux-specific but useful
    {
        require BSD::Resource;
        my $before = (BSD::Resource::getrusage())[2];   # ru_maxrss in KB on Linux
        my $f = $kit->file_encrypt;
        my $key = random_bytes(32);
        my $in = "$dir/rss-in.bin";
        open my $fh, '>:raw', $in or die $!;
        my $buf = random_bytes(1024 * 1024);
        print $fh $buf for 1 .. 50;
        close $fh;
        $f->encrypt_file($key, $in, "$dir/rss-out.enc");
        my $after = (BSD::Resource::getrusage())[2];
        diag sprintf("FileEncrypt 50 MB: max RSS before %d KB, after %d KB (delta %d KB)",
            $before, $after, $after - $before);
    }
}

ok 1, 'perf baseline complete';
done_testing;
