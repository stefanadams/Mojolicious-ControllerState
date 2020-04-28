use Test::More;
use Test::Mojo;

use Mojo::File qw(curfile);
use lib curfile->dirname->sibling('lib')->to_string;

use Mojolicious;
use Mojolicious::ControllerState;

my $t = Test::Mojo->new(Mojolicious->new);
$t->app->helper(state => sub { Mojolicious::ControllerState->new(shift) });
$t->app->routes->get('/:p' => {p => 2} => sub {
  my $c = shift;
  my $state = $c->state;
  is $state->param('p'), $c->param('p');
  is $state->stash->{test}, undef;
  is $state->stash('test'), undef;
  $c->stash(test => 123);
  is $state->stash('test'), undef;
  is $c->state->stash('test'), 123;
  is $state->param('a'), 321 if $c->param('a');
  is $state->session('def'), 431 if $c->session('def');
  $c->session(def => 431)->render(json => $c->state->to_hash);
});

$t->get_ok('/')->status_is(200);
$t->get_ok('/abc' => form => {a => 321})->status_is(200);

done_testing;
