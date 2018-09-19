#!/usr/bin/perl

#
# Copyright (C) 2017 Joelle Maslak
# All Rights Reserved - See License
#

package Termnet::SSH::Mac;

use Termnet::Boilerplate 'role';

requires 'id';

requires 'out_size', 'key_size', 'make_key', 'id', 'digest';

has key => (
    is       => 'rw',
    isa      => 'Str',
);

sub get_creator($self) {
    return sub(@args) { $self->new(@args); }
}

sub BUILDARGS($self, @args) {
    my %h;
    if (scalar(@args) == 1) {
        %h = $args[0]->%*;
    } else {
        %h = @args;
    }

    if (exists($h{key})) {
        $h{key} = $self->make_key($h{key});
    }

    return \%h;
}


1;

