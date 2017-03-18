#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

use lib 'lib';

use Termnet::Boilerplate 'script';

use AnyEvent;
use AnyEvent::Socket;
use Termnet::Matrix;
use Termnet::Menu;
use Termnet::Serial;
use Termnet::TCP;
use Termnet::TelnetIn;

MAIN: {
    my $cv = AnyEvent->condvar;
    
    my $matrix = Termnet::Matrix->new();

    my $host = '::';
    my $port = 44244;

    my $serial = Termnet::Serial->new(
        port => '/dev/ttyUSB0',
        baud => 9600,
        id => 'serial:srx1',
    );
    $matrix->register_lower($serial);
    $matrix->register_name($serial, 'srx1');

    $serial = Termnet::Serial->new(
        port => '/dev/ttyACM0',
        baud => 9600,
        id => 'serial:gps',
    );
    $matrix->register_lower($serial);
    $matrix->register_name($serial, 'gps');

    $serial = Termnet::Serial->new(
        port => '/dev/ttyUSB1',
        baud => 9600,
        id => 'serial:wlc',
    );
    $matrix->register_lower($serial);
    $matrix->register_name($serial, 'wlc');

    $serial = Termnet::Serial->new(
        port => '/dev/ttyUSB2',
        baud => 9600,
        id => 'serial:sw02fpc0',
    );
    $matrix->register_lower($serial);
    $matrix->register_name($serial, 'sw02fpc0');

    tcp_server(
        $host, $port,
        sub ( $fh, $host, $port ) {
            my $tcp = Termnet::TCP->new(
                fh => $fh,
            );

            my $tn = Termnet::TelnetIn->new();
            $tn->register_lower($tcp);

            my $menu = Termnet::Menu->new();
            $menu->register_lower($tn);

            $matrix->register_lower($menu);

            # $matrix->connect_lowers($menu->id, $serial->id);
        },
    );

    $cv->recv;
}

