#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

package Termnet::UpperMultipleChildren;

use Termnet::Boilerplate 'role';

use Termnet::Types;

with 'Termnet::Upper';

has lower => (
    is      => 'rw',
    isa     => 'HashRef[Termnet::LowerObj]',
    default => sub { return {} },
);

sub register_lower ( $self, $lower ) {
    my $id = $lower->id;
    $self->lower->{$id} = $lower;
    $lower->upper($self);
}

sub deregister_lower ( $self, $lower ) {
    my $id = $lower->id;
    $lower->upper(undef);
    delete $self->lower->{$id};
}

1;

