use Module::Build;
my $build = Module::Build->new
(
module_name => 'Apache::OneTimeURL',
license => 'perl',
requires => {
             'perl'           => '5.6.0',
             'Apache'         => 0,
             'Digest::MD5'    => 0,
             'DB_File'        => 0,
             'MLDBM'          => 0,
             'Mail::Send'     => 0
            },
create_makefile_pl => 'passthrough'
);
$build->create_build_script;
