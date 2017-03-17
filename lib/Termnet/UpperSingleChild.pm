#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

package Termnet::UpperSingleChild;

use Termnet::Boilerplate 'role';

use Termnet::Types;

with 'Termnet::Upper';

has lower => (
    is      => 'rw',
    isa     => 'Maybe[Termnet::LowerObj]',
    default => sub { return undef },
);

sub register_lower ( $self, $lower ) {
    ### assert: $lower->DOES('Termnet::Lower')
    $self->lower($lower);
    $lower->upper($self);

    if ($self->DOES('Termnet::Lower')) {
        $self->id($lower->id);
    }
}

sub deregister_lower ( $self, $lower ) {
    ### assert: $lower->DOES('Termnet::Lower')
    $lower->upper(undef);
    $self->lower(undef);
}

1;

