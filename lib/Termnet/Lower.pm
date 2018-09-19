#!/usr/bin/perl

#
# Copyright (C) 2017 Joelle Maslak
# All Rights Reserved - See License
#

package Termnet::Lower;

my $cnt = 0;

use Termnet::Boilerplate 'role';

requires 'accept_input_from_upper', 'accept_command_from_upper';

has id => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    builder  => '_build_id',
    lazy     => 1,
);

sub _build_id($self) {
    if ( $cnt > 2_000_000_000 ) { $cnt = 0; }
    return join ':', scalar(time), rand(1_000_000), $cnt++;
}

has upper => (
    is  => 'rw',
    isa => 'Maybe[Termnet::Upper]',
);

1;

