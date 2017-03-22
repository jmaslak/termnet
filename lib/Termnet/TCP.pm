#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

package Termnet::TCP;

use Termnet::Boilerplate 'class';

use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;

with 'Termnet::Lower';

has fh => (
    is       => 'ro',
    required => 1,
);

has handle => (
    is       => 'ro',
    isa      => 'AnyEvent::Handle',
    required => 1,
    lazy     => 1,
    init_arg => '_handle',
    builder  => '_build_handle',
);

sub _build_handle($self) {
    AnyEvent::Socket::tcp_nodelay( $self->fh, 1 );

    my $handle = AnyEvent::Handle->new(
        fh       => $self->fh,
        on_error => sub ( $h, $fatal, $error ) {
            $self->do_error( $h, $error );
        },
        on_eof => sub($h) {
            $self->do_eof($h);
        },
        on_read => sub($h) {
            $self->do_read($h);
        }
    );

    return $handle;
}

has type => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
    init_arg => '_type',
    default  => 'tcp',
);

has pending_events => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
    init_arg => '_pending',
    default  => sub { return {} },
    lazy     => 1,
);

has eof_cb => (
    is  => 'rw',
    isa => 'Maybe[CodeRef]',
);

around '_build_id' => sub($orig, $self) {
    return $self->type . ":" . $self->$orig();
};

sub accept_input_from_upper ( $self, $upper, $data ) {
    $self->handle->push_write($data);
}

sub accept_command_from_upper ( $self, $upper, $cmd, @data ) {
    if ( $cmd eq 'OPEN SESSION' ) {
        # NOP
    } elsif ( $cmd eq 'DISCONNECT SESSION' ) {
        $self->handle->push_shutdown;
        if ( defined( $self->upper ) ) {
            $upper->accept_command_from_lower( $self, 'EOF' );
        }
    } else {
        die("Unknown cmd received form upper layer: $cmd");
    }
}

sub do_read ( $self, $handle ) {
    my $data = $self->handle->rbuf;
    $self->handle->rbuf = '';
    if ( $data eq '' ) { return }

    if ( defined( $self->upper ) ) {
        $self->upper->accept_input_from_lower( $self, $data );
    }
}

sub do_eof ( $self, $handle ) {
    if ( defined( $self->upper ) ) {
        $self->upper->accept_command_from_lower( $self, 'EOF' );
    }
    if ( defined( $self->eof_cb ) ) {
        $self->eof_cb->($self);
    }
}

sub do_error ( $self, $handle, $error ) {
    warn($error);
    if ( defined( $self->upper ) ) {
        $self->upper->accept_command_from_lower( $self, 'EOF' );
    }
}

__PACKAGE__->meta->make_immutable;

1;

