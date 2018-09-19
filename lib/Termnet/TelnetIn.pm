#!/usr/bin/perl

#
# Copyright (C) 2017 Joelle Maslak
# All Rights Reserved - See License
#

package Termnet::TelnetIn;

use Termnet::Boilerplate 'class';

use Stream::Telnet;

with 'Termnet::Lower', 'Termnet::UpperSingleChild';

has telnet => (
    is       => 'ro',
    isa      => 'Stream::Telnet',
    required => 1,
    init_arg => '_telnet',
    builder  => '_build_telnet',
);

sub _build_telnet($self) {
    my $telnet = Stream::Telnet->new(
        readsub => sub() {
            my $d = $self->input_buffer;
            $self->input_buffer(undef);
            return $d;
        },
        writesub => sub($data) {
            if (defined($self->lower)) {
                $self->lower->accept_input_from_upper( $self, $data );
            }
        },
    );

    return $telnet;
}

has input_buffer => (
    is  => 'rw',
    isa => 'Maybe[Str]',
);

has type => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
    init_arg => '_type',
    default  => 'telnet',
);

sub accept_input_from_lower ( $self, $lower, $data ) {
    $self->input_buffer($data);
    my $cleandata = $self->telnet->get();

    if ( $cleandata ne '' ) {
        $self->upper->accept_input_from_lower( $self, $cleandata );
    }
}

sub accept_command_from_lower ( $self, $lower, $cmd, @data ) {
    if ( !defined( $self->upper ) ) { return; }

    return $self->upper->accept_command_from_lower( $self, $cmd, @data );
}

sub accept_input_from_upper ( $self, $upper, $data ) {
    $self->telnet->put($data);
}

sub accept_command_from_upper ( $self, $upper, $cmd, @data ) {
    $self->lower->accept_command_from_upper( $self, $cmd, @data );

    if ( $cmd eq 'DISCONNECT SESSION' ) {
        $self->upper(undef);
        $self->lower(undef);
    }
}

after 'register_lower' => sub ( $self, $lower ) {
    $self->telnet->init_negotiate();
};

__PACKAGE__->meta->make_immutable;

1;

