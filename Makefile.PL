use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'CryptoKit',
    VERSION_FROM     => 'lib/CryptoKit.pm',
    ABSTRACT         => 'A modular cryptographic toolkit for Perl',
    AUTHOR           => 'Thomas H selfworker112@mailfence.com',
    LICENSE          => 'perl',
    MIN_PERL_VERSION => '5.016',
    PREREQ_PM        => {
        'CryptX'              => '0.088_001',
        'Crypt::Argon2'       => '0',
        'Crypt::SecretBuffer' => '0.019',
        'Authen::OATH'        => '0',
        'MIME::Base32'        => '0',
        'MIME::Base64'        => '0',
        'Digest::SHA'         => '0',
        'Getopt::Long'        => '0',
        'Test2::V0'           => '0',
    },
    EXE_FILES        => [ 'bin/cryptokit' ],
    META_MERGE       => {
        resources => {
            repository => 'https://github.com/thomas666-beast/CryptoKit',
            bugtracker => 'https://github.com/thomas666-beast/CryptoKit/issues',
            homepage   => 'https://github.com/thomas666-beast/CryptoKit',
        },
    },
    clean            => {
        FILES => 'CryptoKit-*.tar.gz',
    },
);
