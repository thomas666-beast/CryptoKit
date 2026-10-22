use 5.008003;
use strict;
use warnings;
use Module::Build;
Module::Build->VERSION('0.4004');

my $builder = Module::Build->new(
    module_name         => 'CryptoKit',
    license             => 'artistic_2',
    dist_author         => ['Thomas Holopeinen <selfworker112@mailfence.com>'],
    dist_version_from   => 'lib/CryptoKit.pm',
    release_status      => 'stable',
    configure_requires => {
        'Module::Build' => '0.4004',
    },
    test_requires => {
        'Test::More' => '0',
    },
    requires => {
        'perl'                 => '5.016',
        'CryptX'               => '0',
        'Crypt::Argon2'        => '0',
        'Crypt::SecretBuffer'  => '0',
        'Crypt::PRNG'          => '0',
    },
    add_to_cleanup     => [ 'CryptoKit-*' ],
);

$builder->create_build_script();
