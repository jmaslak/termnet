#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

package Termnet::SerialOut;

use Termnet::Boilerplate 'class';

use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::SerialPort;

has port => (
    is => 'ro',
    isa => 'Str',
    required => 1,
);

has baud => (
    is => 'ro',
    isa => 'Int',
    required => 1,
    default => sub { return 9600 },
);

has send_on_connect => (
    is => 'rw',
    isa => 'Maybe[Str]',
    required => 1,
    default => "\n",
);

has handle => (
    is => 'ro',
    isa => 'AnyEvent::SerialPort',
    required => 1,
    lazy => 1,
    init_arg => '_serial',
    builder => '_build_serial',
);

sub _build_serial($self) {
    my $serial = AnyEvent::SerialPort->new(
        serial_port => [ $self->port, [ baudrate => $self->baud ] ],
        on_error => sub($h, $fatal, $error) {
            warn $error;
        },
        on_eof => sub($h) {
            warn "EOF on USB";
            if (defined($self->eof_cb)) {
                $self->eof_cb->($self);
            }
        },
        on_read => sub($h) {
            my $data = $self->get();
            $self->peer_put($data);
        }
    );

    return $serial;
}

has delay_start => (
    is => 'rw',
    isa => 'Int',
    required => 1,
    init_arg => '_delay_start',
    writer => '_delay_start',
    default => 0,
);

has type => (
    is => 'ro',
    isa => 'Str',
    required => 1,
    init_arg => '_type',
    default => 'serial',
);

has pending_events => (
    is => 'ro',
    isa => 'HashRef',
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
    my $data = $self->handle->rbuf;
    $self->handle->rbuf = '';

    if ($self->delay_start) {
        return '';
    } else {
        return $data;
    }
}

sub put($self, $data) {
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

    $self->handle->{serial_port}->dtr_active(0);
    $self->_delay_start(1);
    $self->pending_events->{dtr_pulse} = AnyEvent->timer(
        after => .1,
        cb    => sub {
            $self->_delay_start(0);
            $self->handle->{serial_port}->dtr_active(1);
            delete $self->pending_events->{dtr_pulse};
            if (defined($self->send_on_connect)) {
                $self->put( $self->send_on_connect );
            }
        },
    );

    if (!defined($peer->peer)) {
        $peer->connect_peer($self);
    }
}

sub disconnect_peer($self) {
    $self->_delay_start(0);  # This is okay, because we'll still do the .1
                             # second delay at initial connect.

    delete $self->pending_events->{dtr_pulse};
    $self->handle->{serial_port}->dtr_active(0);

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

