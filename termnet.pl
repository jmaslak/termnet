#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

use lib 'lib';

use Termnet::Boilerplate 'script';

use AnyEvent;
use AnyEvent::Socket;
use Termnet::SerialOut;
use Termnet::TelnetIn;

my %endpoints;

MAIN: {
    my $cv = AnyEvent->condvar;

    my $host = '::';
    my $port = 44244;

    my $serial = Termnet::SerialOut->new(
        port => '/dev/ttyUSB0',
        baud => 9600,
        eof_cb => sub { delete $endpoints{serial} },
    );
    $endpoints{serial} = $serial;

    tcp_server(
        $host, $port,
        sub ( $fh, $host, $port ) {
            my $id = get_new_id();
            my $tn = Termnet::TelnetIn->new(
                fh => $fh,
                eof_cb => sub { delete $endpoints{$id} },
            );
            $endpoints{$id} = $tn;

            if ($serial->is_connected()) {
                $tn->put( "Serial port in use, sorry.\n\r" );
            } else {
                $tn->put( "Connecting to serial port...\n\r" );
                $tn->connect_peer($serial);
            }
        },
    );

    $cv->recv;
}

sub get_new_id() {
    state $id= 1;
    ### ID: $id

    return $id++;
}

