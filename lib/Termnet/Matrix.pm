#!/usr/bin/perl

#
# Copyright (C) 2017 Joelle Maslak
# All Rights Reserved - See License
#

package Termnet::Matrix;

use Termnet::Boilerplate 'class';

use Termnet::Upper;

with 'Termnet::UpperMultipleChildren';

has connection => (
    is       => 'rw',
    isa      => 'HashRef[Termnet::Lower]',
    required => 1,
    default  => sub { return {} },
);

has names => (
    is       => 'rw',
    isa      => 'HashRef[HashRef]',
    required => 1,
    default  => sub { return {} },
);

sub connect_lowers ( $self, $endpoint1, $endpoint2 ) {
    if ( !defined( $self->lower->{$endpoint1} ) ) {
        return;
    }

    if ( !defined( $self->lower->{$endpoint2} ) ) {
        return;
    }

    if ( exists $self->connection->{$endpoint1} ) {
        my $current = $self->connection->{$endpoint1};
        $self->disconnect($current);
    }

    if ( exists $self->connection->{$endpoint2} ) {
        my $current = $self->connection->{$endpoint2};
        $self->disconnect($current);
    }

    $self->connection->{$endpoint1} = $endpoint2;
    $self->connection->{$endpoint2} = $endpoint1;

    $self->lower->{$endpoint1}->accept_command_from_upper( $self, 'OPEN SESSION' );
    $self->lower->{$endpoint2}->accept_command_from_upper( $self, 'OPEN SESSION' );

    return;
}

sub disconnect ( $self, $endpoint1 ) {
    if ( !exists( $self->lower->{$endpoint1} ) ) {
        return;
    }
    if ( !exists( $self->connection->{$endpoint1} ) ) {
        return;    # No connection
    }

    my $endpoint2 = $self->connection->{$endpoint1};
    delete $self->connection->{$endpoint1};
    $self->disconnect($endpoint2);

    $self->lower->{$endpoint1}->accept_command_from_upper( $self, 'DISCONNECT SESSION' );

    return;
}

sub accept_command_from_lower ( $self, $lower, $cmd, @data ) {
    if ( $cmd eq 'EOF' ) {
        $self->disconnect( $lower->id );
        $self->deregister_lower($lower);
        return;
    } elsif ( $cmd eq 'LIST ACTIVITY' ) {
        return $self->get_activity();
    } elsif ( $cmd eq 'LIST NAMES' ) {
        return $self->get_names();
    } elsif ( $cmd eq 'CONNECT' ) {
        my ($peer) = @data;
        if ( ( $peer // '' ) eq '' )                   { return; }
        if ( !exists( $self->names->{$peer} ) )        { return; }
        if ( $lower->id eq $self->names->{$peer}{id} ) { return; }

        $self->connect_lowers( $lower->id, $self->names->{$peer}{id} );
        return 1;
    } elsif ( $cmd eq 'HANGUP' ) {
        $self->disconnect( $lower->id );
    } else {
        die("Unknown command received from lower layer: $cmd");
    }

    return;
}

sub accept_input_from_lower ( $self, $lower, $data ) {
    my $id = $lower->id;

    if ( !exists( $self->connection->{$id} ) ) { return; }    # Not connected
    my $peer_id = $self->connection->{$id};
    my $peer    = $self->lower->{$peer_id};

    $peer->accept_input_from_upper( $self, $data );

    return;
}

sub register_name ( $self, $lower, $name ) {
    my $id = $lower->id;

    $self->names->{$name} = { id => $lower->id };

    return;
}

before 'deregister_lower' => sub ( $self, $lower ) {
    my $id = $lower->id;
    $self->disconnect($id);
    delete $self->names->{$id};
};

sub get_activity($self) {
    my %out;
    foreach my $id ( sort keys $self->lower->%* ) {
        $out{$id} = {
            id         => $id,
            connection => exists( $self->connection->{$id} ) ? $self->connection->{$id} : undef,
        };
    }
    return \%out;
}

sub get_names($self) {
    my (%out) = $self->names->%*;

    foreach my $n ( sort keys %out ) {
        my $id = $out{$n}->{id};
        $out{$n}->{connection} =
          exists( $self->connection->{$id} ) ? $self->connection->{$id} : undef;
    }

    return \%out;
}

__PACKAGE__->meta->make_immutable;

1;

