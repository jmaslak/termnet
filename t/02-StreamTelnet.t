#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

use Test2::Bundle::Extended 0.000058;
use Termnet::Boilerplate 'script';

use Stream::Telnet;

subtest 'Published API Methods Unchanged' => \&published_api;
subtest 'Check Basic API Operations'      => \&basic_api;

done_testing;

#
# SUBTESTS
#

sub published_api() {
    my $tn = Stream::Telnet->new(
        readsub  => sub        { '' },
        writesub => sub($data) { return undef },
    );

    isa_ok( $tn, ['Stream::Telnet'], 'Proper Object Class' );

    my (@methods) = qw(readsub writesub read_buffer write_buffer char_interrupt
      telnet_goahead pending_do pending_will opt_receive_binary
      opt_send_binary init_negotiate get put ack_if_needed
      handle_will handle_wont handle_do handle_dont get_opt_name
      send_will send_wont send_do send_dont);
    can_ok( $tn, \@methods, 'Public API Methods Exist' );
}

sub basic_api() {
    my (@check) = (
        "" . "\xff\xfb\x00"    # WILL BINARY
          . "\xff\xfb\x01"     # WILL ECHO
          . "\xff\xfb\x03"     # WILL SUPPRESS-GO-AHEAD
          . "\xff\xfd\x00"     # DO BINARY
          . "\xff\xfd\x01"     # DO ECHO
          . "\xff\xfd\x03"     # DO SUPPRESS-GO-AHEAD
    );
    my $sent;
    my $received;

    # Format:
    #   ->[0] = What is received via Telnet from Stream
    #   ->[1] = What is sent to Telnet from user code
    #   ->[2] = What is returned from Telnet to user code
    #   ->[3] = What is sent from Telnet via Stream
    #   ->[4] = Test Name

    my (@tests) = (
        [ "\xff\xf4",                 undef, "\x03",   undef, 'Convert IAC IA to CTRL-C' ],
        [ "\xff\xf1",                 undef, "",       undef, 'Convert IAC NOP to Nothing' ],
        [ "Test\n\0",                 undef, "Test\n", undef, 'Strip \0 before DO/WILL BINARY' ],
        [ "Test\r\n",                 undef, "Test\n", undef, 'Strip \r before DO/WILL BINARY' ],
        [ "\xff\xfb\x00\xff\xfd\x00", '',    "",       undef, 'Turn on Binary' ],
        [ "\xff\xfb\x00",             undef, "", "\xff\xfd\x00", 'Repeat Turn on Binary 1' ],
        [ "\xff\xfd\x00",             undef, "", "\xff\xfb\x00", 'Repeat Turn on Binary 2' ],
        [ "\xff\xfb\x01\xff\xfd\x01", undef, "", undef,          'Turn on Echo' ],
        [ "\xff\xfb\x03\xff\xfd\x03", undef, "", undef,          'Turn off GA' ],
        [ "Test\n\0", undef,  "Test\n\0", undef,          'No strip \0 after DO/WILL BINARY' ],
        [ "Test\r\n", undef,  "Test\r\n", undef,          'No strip \r after DO/WILL BINARY' ],
        [ "\xff\xff", undef,  "\xff",     undef,          'Convert IAC IAC to IAC' ],
        [ "\xff",     undef,  "",         undef,          'Split Turn On Binary Part 1' ],
        [ "\xfb",     undef,  "",         undef,          'Split Turn on Binary Part 2' ],
        [ "\x00",     '',     "",         "\xff\xfd\x00", 'Repeat Turn on Binary 3' ],
        [ '',         "Test", '',         "Test",         'Send basic text' ],
        [ '', "Test\0\r\n\0\xff",     '', "Test\0\r\n\0\xff\xff",       'Send binary text 1' ],
        [ '', "Test\0\r\n\n\n\0\xff", '', "Test\0\r\n\n\n\0\xff\xff", 'Send binary text 2' ],
        [ "\xff\xfc\x00\xff\xfe\x00", '', "", "\xff\xfe\x00\xff\xfc\x00", 'Turn off Binary' ],
        [ '', "Test\n\xff", '', "Test\r\n\xff\xff", 'Send non-binary text' ],
    );

    my $recv_buff = '';
    my $recv      = sub() {
        my $data = $recv_buff;
        $recv_buff = '';

        return $data;
    };
    my $send = sub($data) {
        if ( !defined($sent) ) { $sent = '' }
        $sent .= $data;
    };

    my $tn = Stream::Telnet->new( readsub => $recv, writesub => $send );
    isa_ok( $tn, ['Stream::Telnet'], 'Proper Object Class' );

    ok( lives( sub { $tn->init_negotiate() } ), 'Initial Option Negotiation Lives' );
    is( $sent, shift @check, 'Initial Negotation is Proper' );
    $sent = undef;

    foreach my $t (@tests) {
        $recv_buff = $t->[0];
        my $send_buffer = $t->[1];
        my $expect_recv = $t->[2];
        my $expect_send = $t->[3];
        my $test        = $t->[4];

        my $got_recv = $tn->get();
        is( $got_recv, $expect_recv, "$test - received expected data" );

        if ( defined($send_buffer) ) {
            $tn->put($send_buffer);
        }

        is( h($sent), h($expect_send), "$test - streamed expected data" );
        $sent = undef;
    }
}

sub h($str) {
    if ( !defined($str) ) { return $str; }

    return join ' ', map { sprintf( "%02x", ord($_) ) } split( //, $str );
}
