#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

package Termnet::TelnetIn;

use Termnet::Boilerplate 'class';

use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;
use Stream::Telnet;

has fh => (
    is => 'ro',
    required => 1,
);

has handle => (
    is => 'ro',
    isa => 'AnyEvent::Handle',
    required => 1,
    lazy => 1,
    init_arg => '_handle',
    builder => '_build_handle',
);

sub _build_handle($self) {
    AnyEvent::Socket::tcp_nodelay($self->fh, 1);

    my $handle = AnyEvent::Handle->new(
        fh => $self->fh,
        on_error => sub($h, $fatal, $error) {
            $self->disconnect_peer();
            $self->handle->destroy();
        },
        on_eof => sub($h) {
            $self->disconnect_peer();
            $self->handle->destroy();

            if (defined($self->eof_cb)) {
                $self->eof_cb->($self);
            }
        },
        on_read => sub($h) {
            my $data = $self->get();
            $self->peer_put($data);
        }
    );

    return $handle;
}

has telnet => (
    is => 'ro',
    isa => 'Stream::Telnet',
    required => 1,
    init_arg => '_telnet',
    builder => '_build_telnet',
);

sub _build_telnet($self) {
    my $telnet = Stream::Telnet->new(
        readsub  => sub()      { $self->get_raw(); },
        writesub => sub($data) { $self->put_raw($data); },
    );

    $telnet->init_negotiate();

    return $telnet;
}

has type => (
    is => 'ro',
    isa => 'Str',
    required => 1,
    init_arg => '_type',
    default => 'serial',
);

has pending_events => (
    is => 'ro',
    isa => 'Str',
    required => 1,
    init_arg => '_pending',
    default => sub { return {} },
    lazy => 1,
);

has peer => (
    is => 'rw',
);

has disconnect_peer_cb => (
    is => 'rw',
    isa => 'Maybe[CodeRef]',
);

has eof_cb => (
    is => 'rw',
    isa => 'Maybe[CodeRef]',
);

sub get($self) {
    return $self->telnet->get();
}

sub put($self, $data) {
    $self->telnet->put($data);
}

sub get_raw($self) {
    my $data = $self->handle->rbuf;
    $self->handle->rbuf = '';

    return $data;
}

sub put_raw($self, $data) {
    $self->handle->push_write($data);
}

sub peer_put($self, $data) {
    my $peer = $self->peer();

    if (defined($peer)) {
        $peer->put($data);
    }
}

sub connect_peer($self, $peer) {
    if (defined($self->peer)) {
        $self->disconnect_peer();
    }

    $self->peer($peer);

    if (!defined($peer->peer)) {
        $peer->connect_peer($self);
    }
}

sub disconnect_peer($self) {
    my $peer = $self->peer;
    if (!defined($peer)) { return; }

    $self->peer(undef);

    if (defined($peer->peer)) {
        $peer->disconnect_peer();
    }

    if (defined($self->disconnect_peer_cb)) {
        $self->disconnect_peer_cb->($self);
    }
}

sub is_connected($self) {
    return defined($self->peer);
}

__PACKAGE__->meta->make_immutable;

1;

