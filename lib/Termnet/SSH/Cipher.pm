#!/usr/bin/perl

#
# Copyright (C) 2017,2019 Joelle Maslak
# All Rights Reserved - See License
#

package Termnet::SSH::Cipher;

use Termnet::Boilerplate 'role';

requires 'block_size', 'key_size', 'id', 'encrypt', 'decrypt';

has iv => (
    is  => 'rw',
    isa => 'Str',
);

has key => (
    is  => 'rw',
    isa => 'Str',
);

sub get_creator($self) {
    return sub(@args) { $self->new(@args); }
}

sub BUILDARGS ( $self, @args ) {
    my %h;
    if ( scalar(@args) == 1 ) {
        %h = $args[0]->%*;
    } else {
        %h = @args;
    }

    if ( exists( $h{key} ) ) {
        $h{key} = substr( $h{key}, 0, $self->key_size );
    }
    if ( exists( $h{iv} ) ) {
        $h{iv} = substr( $h{iv}, 0, $self->block_size );
    }

    return \%h;
}

1;

