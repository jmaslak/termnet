    #!/usr/bin/perl

#
# Copyright (C) 2017 Joelle Maslak
# All Rights Reserved - See License
#

package Termnet::Serial;

use Termnet::Boilerplate 'class';

use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::SerialPort;

with 'Termnet::Lower';

has port => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
);

has baud => (
    is       => 'ro',
    isa      => 'Int',
    required => 1,
    default  => sub { return 9600 },
);

has test_fh => ( is => 'ro', );

has send_on_connect => (
    is       => 'rw',
    isa      => 'Maybe[Str]',
    required => 1,
    default  => "\n",
);

has handle => (
    is       => 'ro',
    isa      => 'AnyEvent::Handle',
    required => 1,
    lazy     => 1,
    init_arg => '_serial',
    builder  => '_build_serial',
);

sub _build_serial($self) {
    if ( !defined $self->test_fh ) {
        my $serial = AnyEvent::SerialPort->new(
            serial_port => [ $self->port, [ baudrate => $self->baud ] ],
            on_error => sub ( $h, $fatal, $error ) {
                warn $error;
            },
            on_eof => sub($h) {
                $self->do_eof($h);
            },
            on_read => sub($h) {
                $self->do_read($h);
            },
        );

        # We enable hardware handshaking
        $serial->serial_port->handshake('rts');

        return $serial;
    } else {
        my $serial = AnyEvent::Handle->new(
            fh     => $self->test_fh,
            on_eof => sub($h) {
                $self->do_eof($h);
            },
            on_read => sub($h) {
                $self->do_read($h);
            },
        );

        return $serial;
    }
}

has delay_start => (
    is       => 'rw',
    isa      => 'Int',
    required => 1,
    init_arg => '_delay_start',
    writer   => '_delay_start',
    default  => 0,
);

has type => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
    init_arg => '_type',
    default  => 'serial',
);

has pending_events => (
    is       => 'ro',
    isa      => 'HashRef',
    required => 1,
    init_arg => '_pending',
    default  => sub { return {} },
    lazy     => 1,
);

has peer => ( is => 'rw', );

has eof_cb => (
    is  => 'rw',
    isa => 'Maybe[CodeRef]',
);

has del_to_backspace => (
    is       => 'rw',
    isa      => 'Bool',
    required => 1,
    default  => 0,
);

sub accept_input_from_upper ( $self, $upper, $data ) {
    if ( $self->del_to_backspace ) { $data =~ s/\x7f/\x08/gs; }
    $self->handle->push_write($data);
}

sub accept_command_from_upper ( $self, $upper, $command, @data ) {
    if ( $command eq 'OPEN SESSION' ) {
        $self->pulse_dtr();
    } elsif ( $command eq 'DISCONNECT SESSION' ) {
        $self->handle->{serial_port}->dtr_active(0);
        $self->_delay_start(1);
    } else {
        die("Unknown command received from upper layer: $command");
    }
}

sub pulse_dtr($self) {
    $self->handle->{serial_port}->dtr_active(0);
    $self->_delay_start(1);
    $self->pending_events->{dtr_pulse} = AnyEvent->timer(
        after => .1,
        cb    => sub {
            $self->_delay_start(0);
            $self->handle->{serial_port}->dtr_active(1);
            delete $self->pending_events->{dtr_pulse};
            if ( defined( $self->send_on_connect ) ) {
                $self->handle->rbuf = '';
                $self->handle->push_write( $self->send_on_connect );
            }
        },
    );
}

sub do_read ( $self, $handle ) {
    my $data = $self->handle->rbuf;
    $self->handle->rbuf = '';

    if ( !$self->delay_start ) {
        if ( defined( $self->upper ) ) {
            $self->upper->accept_input_from_lower( $self, $data );
        }
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

__PACKAGE__->meta->make_immutable;

1;

