#!/usr/bin/perl

#
# Copyright (C) 2017-2019 Joelle Maslak
# All Rights Reserved - See License
#

use lib 'lib';

use Termnet::Boilerplate 'script';

use AnyEvent;
use AnyEvent::Socket;
use Termnet::Matrix;
use Termnet::Menu;
use Termnet::Serial;
use Termnet::SSHIn;
use Termnet::TCP;
use Termnet::TelnetIn;

MAIN: {
    my $cv = AnyEvent->condvar;

    my $matrix = Termnet::Matrix->new();

    my $host        = '::';
    my $telnet_port = 44244;
    my $ssh_port    = 44245;

    my $serial = Termnet::Serial->new(
        port => '/dev/ttyUSB0',
        baud => 9600,
        id   => 'serial:labsw01',
    );
    $matrix->register_lower($serial);
    $matrix->register_name( $serial, 'labsw01' );

    $serial = Termnet::Serial->new(
        port => '/dev/ttyACM0',
        baud => 9600,
        id   => 'serial:gps',
    );
    $matrix->register_lower($serial);
    $matrix->register_name( $serial, 'gps' );

    $serial = Termnet::Serial->new(
        port => '/dev/ttyUSB1',
        baud => 115200,
        id   => 'serial:wlc',
    );
    $matrix->register_lower($serial);
    $matrix->register_name( $serial, 'wlc' );

    $serial = Termnet::Serial->new(
        port => '/dev/ttyUSB2',
        baud => 9600,
        id   => 'serial:sw02fpc0',
    );
    $matrix->register_lower($serial);
    $matrix->register_name( $serial, 'sw02fpc0' );

    $serial = Termnet::Serial->new(
        port => '/dev/ttyUSB4',
        baud => 9600,
        id   => 'serial:labsw02',
    );
    $matrix->register_lower($serial);
    $matrix->register_name( $serial, 'labsw02' );

    # $serial = Termnet::Serial->new(
    #    port             => '/dev/ttyUSB3',
    #    baud             => 115200,
    #    id               => 'serial:z80',
    #    del_to_backspace => 1,
    #);
    #$matrix->register_lower($serial);
    #$matrix->register_name( $serial, 'z80' );

    tcp_server(
        $host,
        $telnet_port,
        sub ( $fh, $host, $telnet_port ) {
            my $tcp = Termnet::TCP->new( fh => $fh, peer_host => $host, peer_port => $telnet_port );

            my $tn = Termnet::TelnetIn->new();
            $tn->register_lower($tcp);

            my $menu = Termnet::Menu->new();
            $menu->register_lower($tn);

            $matrix->register_lower($menu);

            # $matrix->connect_lowers($menu->id, $serial->id);
        },
    );

    tcp_server(
        $host,
        $ssh_port,
        sub ( $fh, $host, $ssh_port ) {
            my $tcp = Termnet::TCP->new( fh => $fh, peer_host => $host, peer_port => $ssh_port );

            my $ssh = Termnet::SSHIn->new();
            $ssh->register_lower($tcp);

            my $menu = Termnet::Menu->new();
            $menu->register_lower($ssh);

            $matrix->register_lower($menu);

            # $matrix->connect_lowers($menu->id, $serial->id);
        },
    );

    # Serial input
    $serial = Termnet::Serial->new(
        port             => '/dev/ttyUSB3',
        baud             => 115200,
        id               => 'console:oob-dongle',
        del_to_backspace => 1,
        handshake        => 'none',
    );
    do {
        my $menu = Termnet::Menu->new( allow_exit => undef );
        $menu->register_lower($serial);
        $matrix->register_lower($menu);
    };

    $cv->recv;
}

