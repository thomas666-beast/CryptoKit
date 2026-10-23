# Runtime dependencies for CryptoKit

requires 'perl',                '5.016';
requires 'CryptX',              '0.088_001';
requires 'Crypt::Argon2',       '0';
requires 'Crypt::SecretBuffer', '0.019';
requires 'Authen::OATH',        '0';
requires 'MIME::Base32',        '0';

# Core modules are listed for completeness; they are always available
requires 'Digest::SHA',   '0';
requires 'MIME::Base64',  '0';
requires 'Getopt::Long',  '0';
requires 'FindBin',       '0';
requires 'File::Basename', '0';
requires 'File::Path',    '0';

# Optional: HiatalaMrk backend for CryptoKit::Hash.
# Uncomment and adjust the path if you have HiatalaMrk installed locally.
# requires 'HiatalaMrk', '0.06';

on 'test' => sub {
    requires 'Test2::V0', '0';
};

on 'develop' => sub {
    requires 'Test2::V0',       '0';
    requires 'BSD::Resource',   '0';   # for t/perf.t RSS measurement
    requires 'Pod::Checker',    '0';
    requires 'Test::Pod',       '0';
    requires 'Test::Pod::Coverage', '0';
};
