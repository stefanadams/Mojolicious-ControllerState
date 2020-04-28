package Mojolicious::ControllerState;
use Mojo::Base -base, -signatures;

use Clone 'clone';
use Mojo::Home;
use Mojo::Log;
use Mojo::Message::Request;
use Mojo::Util qw(decamelize hmac_sha1_sum secure_compare);
use Mojolicious;
use Mojolicious::Sessions;

our $VERSION = "0.01";

has home       => sub { Mojo::Home->new->detect };
has log        => sub { Mojo::Log->new };
has mode       => sub { $ENV{MOJO_MODE} || $ENV{PLACK_ENV} || 'development' };
has moniker    => sub { Mojo::Util::decamelize ref shift };
has req        => sub { Mojo::Message::Request->new };
has request_id => undef;
has secrets    => sub { [shift->moniker] };
has sessions   => sub { Mojolicious::Sessions->new };

# Reserved stash values
my %RESERVED = map { $_ => 1 } (
  qw(action app cb controller data extends format handler inline json layout),
  qw(namespace path status template text variant)
);

sub config { _ro_stash(config => @_) }

sub cookie ($self, $name) {
  # Request cookies
  return undef unless my $cookie = $self->req->cookie($name);
  return $cookie->value;
}

sub cookies ($self) { $self->req->cookies }

sub defaults { _ro_stash(defaults => @_) }

sub every_cookie ($self, $name) {
  [map { $_->value } @{$self->req->every_cookie($name)}];
}

sub every_param ($self, $name) {
  # Captured unreserved values
  my $captures = $self->stash->{'mojo.captures'} ||= {};
  if (!$RESERVED{$name} && exists $captures->{$name}) {
    my $value = $captures->{$name};
    return ref $value eq 'ARRAY' ? $value : [$value];
  }

  # Uploads or param values
  my $req     = $self->req;
  my $uploads = $req->every_upload($name);
  return @$uploads ? $uploads : $req->every_param($name);
}

sub every_signed_cookie ($self, $name) {
  my $secrets = $self->secrets;
  my @results;
  for my $value (@{$self->every_cookie($name)}) {

    # Check signature with rotating secrets
    if ($value =~ s/--([^\-]+)$//) {
      my $signature = $1;

      my $valid;
      for my $secret (@$secrets) {
        my $check = Mojo::Util::hmac_sha1_sum("$name=$value", $secret);
        ++$valid and last if Mojo::Util::secure_compare($signature, $check);
      }
      if ($valid) { push @results, $value }

      else { $self->log->debug(qq{Cookie "$name" has bad signature}) }
    }

    else { $self->log->debug(qq{Cookie "$name" is not signed}) }
  }

  return \@results;
}

sub load ($self, $c) {
  return $self unless ref $c && $c->isa('Mojolicious::Controller');
  $self->{config}   = clone $c->app->config;
  $self->{defaults} = clone $c->app->defaults;
  $self->{session}  = clone $c->session;
  $self->{stash}    = clone $c->stash;
  $self->home($c->app->home)
       ->log($c->log)
       ->mode($c->app->mode)
       ->moniker($c->app->moniker)
       ->req($c->req->clone)
       ->request_id($c->req->request_id)
       ->secrets($c->app->secrets)
       ->sessions($c->app->sessions);
}

sub new { shift->SUPER::new->load(shift) }

sub param ($self, $name) { $self->every_param($name)->[-1] }

sub params ($self) {
  my $req = $self->req;
  return $self->{params}
    ||= $req->body_params->clone->append($req->query_params);
}

sub session { _ro_stash(session => @_) }

sub signed_cookie ($self, $name) {
  # Request cookie
  return $self->every_signed_cookie($name)->[-1];
}

sub stash { _ro_stash(stash => @_) }

sub to_hash ($self) {
  {
    body => $self->req->body,
    config => $self->config,
    cookies => $self->cookies,
    defaults => $self->defaults,
    home => $self->home->to_string,
    json => $self->req->json,
    mode => $self->mode,
    moniker => $self->moniker,
    params => $self->params->to_hash,
    request_id => $self->request_id,
    url => $self->req->url->to_abs->to_string,
    session => $self->session,
    stash => $self->stash,
  }
}

sub _ro_stash ($name, $self, $key=undef) {
  # Hash
  return $self->{$name} ||= {} unless $key;

  # Get
  return $self->{$name}{$key};
}

1;
__END__
package Mojolicious::ControllerState::Base;
use Mojo::Base -base;

has state => sub { Mojolicious::ControllerState->new };

sub config { shift->state->config(@_) }
sub cookie { shift->state->cookie(@_) }
sub cookies { shift->state->cookies }
sub every_cookie { shift->state->every_cookie(@_) }
sub every_param { shift->state->every_param(@_) }
sub every_signed_cookie { shift->state->every_signed_cookie(@_) }
sub defaults { shift->state->defaults(@_) }
sub home { shift->state->home }
sub log { shift->state->log }
sub mode { shift->state->mode }
sub moniker { shift->state->moniker }
sub param { shift->state->param(@_) }
sub req { shift->state->req }
sub request_id { shift->request_id }
sub secrets { shift->state->secrets }
sub session { shift->state->session(@_) }
sub sessions { shift->state->sessions }
sub signed_cookie { shift->state->signed_cookie(@_) }
sub stash { shift->state->stash(@_) }

1;