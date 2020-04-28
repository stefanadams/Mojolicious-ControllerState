use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
  NAME         => 'Mojolicious::ControllerState',
  VERSION_FROM => 'lib/Mojolicious/ControllerState.pm',
  ABSTRACT     => 'Collect controller state into a single object',
  AUTHOR       => 'Stefan Adams <sadams@cpan.org>',
  LICENSE      => '',
  META_MERGE   => {
    dynamic_config => 0,
    'meta-spec'    => {version => 2},
    no_index       => {
      directory => [qw(t)],
    },
    prereqs   => {runtime => {requires => {perl => '5.010001'}}},
    resources => {
      bugtracker => {web => 'https://github.com/stefanadams/Mojolicious-ControllerState/issues'},
      homepage   => 'https://stefan.adams.fm',
      license    => ['http://www.opensource.org/licenses/artistic-license-2.0'],
      repository => {
        type => 'git',
        url  => 'https://github.com/stefanadams/Mojolicious-ControllerState.git',
        web  => 'https://github.com/stefanadams/Mojolicious-ControllerState',
      },
      x_IRC => 'irc://irc.freenode.net/#mojo'
    },
  },
  PREREQ_PM    => {
    'Mojolicious' => '8.40',
    'Clone' => '0.45',
  },
  test         => {TESTS => 't/*.t'}
);
