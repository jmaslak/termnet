#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

package Termnet::Menu;

use Termnet::Boilerplate 'class';
use List::Util qw(max);

with 'Termnet::Lower', 'Termnet::UpperSingleChild';

has input_buffer => (
    is       => 'rw',
    isa      => 'Str',
    default  => sub { '' },
    required => 1,
);

has type => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
    init_arg => '_type',
    default  => 'menu',
);

has mode => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => 'menu',
);

has recv_nl => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\r",
);

has recv_bs => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x08",
);

has recv_del => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x7f",
);

has recv_ansi_del => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x1B[3~",
);

has send_nl => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\r\n",
);

has send_bs => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x08 \x08",
);

has send_bell => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x07",
);

has term_bright => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x1b[1m",
);

has term_green => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x1b[32m",
);

has term_yellow => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x1b[33m",
);

has term_blue => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x1b[34m",
);

has term_cyan => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x1b[36m",
);

has term_red => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x1b[31m",
);

has term_clear => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x1bc",
);

has term_normal => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x1b[0m",
);

has term_error => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x1b[1m\x1b[31m",
);

has term_prompt => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x1b[1m\x1b[32mTERMNET\x1b[33m->\x1b[0m ",
);

sub accept_input_from_lower ( $self, $lower, $data ) {
    my $snl = $self->send_nl;
    my $rnl = $self->recv_nl;

    my $rbs  = $self->recv_bs;
    my $rdel = $self->recv_del;
    my $sbs  = $self->send_bs;

    if ( $self->mode eq 'connected' ) {
        if (defined($self->upper)) {
            $self->upper->accept_input_from_lower($self, $data);
        }
        return;
    }

    if ( $self->mode eq 'menu' ) {

        my $out = '';
        if ( ( $data =~ m/${rbs}/s ) || ( $data =~ m/${rdel}/s ) ) {
            # Handle Backspace

            my $ib = $self->input_buffer();
            $self->input_buffer('');

            my $buffer = '';

            my (@chars) = split '', $ib;
            foreach my $c (@chars) {
                if ( $c eq "\n" ) {
                    $self->input_buffer( $self->input_buffer() . $buffer . $c );
                    $buffer = '';
                } else {
                    $buffer .= $c;
                }
            }

            $data =~ s/${rnl}/\n/gs;
            @chars = split '', $data;
            foreach my $c (@chars) {
                if ( $c eq "\n" ) {
                    $self->input_buffer( $self->input_buffer() . $buffer . $rnl );
                    $buffer = '';
                    $out .= $snl;
                } elsif ( ( $c eq $rbs ) || ( $c eq $rdel ) ) {
                    if ( length($buffer) > 0 ) {
                        $buffer =~ s/.$//s;
                        $out .= $sbs;
                    } else {
                        $out .= $self->send_bell();
                    }
                } else {
                    $buffer .= $c;
                    $out    .= $c;
                }
            }

            $data = $buffer;

        } else {
            $out = $data;
            $out =~ s/${rnl}/${snl}/gs;
            $data =~ s/${rnl}/\n/gs;
        }

        # Do Echo
        $lower->accept_input_from_upper( $self, $out );
    }

    while ( ( $self->input_buffer() . $data ) ne '' ) {
        $data = $self->input_buffer() . $data;
        $self->input_buffer('');

        if ( $data !~ m/\n/s ) {
            $self->input_buffer($data);
            return;
        }

        my ( $current, $next ) = $data =~ m/^([^\n]*)\n(.*)$/;

        $self->input_buffer($next // '');
        $data = $self->input_buffer;

        $current =~ s/^\s+//s;
        $current =~ s/\s+$//s;

        my (@parts) = split /\s+/, $current;
        my $cmd = fc( shift(@parts) // '' );

        if ( $cmd eq 'activity' ) {
            $self->do_activity( \@parts );
        } elsif ( ( $cmd eq 'c' ) || ( $cmd eq 'connect' ) ) {
            $self->do_connect( \@parts );
        } elsif ( $cmd eq 'exit' ) {
            $self->do_exit( \@parts );
        } elsif ( $cmd eq 'list' ) {
            $self->do_list( \@parts );
        } elsif ( $cmd eq '' ) {
            # Do nothing
        } else {
            $self->send_error("Invalid command!");
        }

        if ($self->mode eq 'menu') {
            $self->send_prompt();
        }
    }
}

sub do_exit ( $self, $params ) {
    $self->require_params( 0, $params ) or return;

    $self->send_status("Goodbye");
    if ( defined( $self->upper ) ) {
        $self->upper->deregister_lower($self);
    }
    $self->lower->accept_command_from_upper( $self, 'DISCONNECT SESSION' );
}

sub do_list ( $self, $params ) {
    $self->require_params( 0, $params ) or return;
    $self->require_upper() or return;

    my $snl = $self->send_nl();

    $self->send_header("Available Endpoints:");

    my $list = $self->upper->accept_command_from_lower( $self, 'LIST NAMES' );

    my $maxlen = max map { length $_ } keys $list->%*;
    foreach my $id (sort keys $list->%*) {
        my $status = $list->{$id}{connection} ? 'BUSY' : 'idle';
        my $out = sprintf("    %-${maxlen}s (%s)", $id, $status);

        if ($status eq 'BUSY') {
            $self->send_alert($out);
        } else {
            $self->send_notice($out);
        }
    }
}

sub do_activity ( $self, $params ) {
    $self->require_params( 0, $params ) or return;
    $self->require_upper() or return;

    my $snl = $self->send_nl();

    $self->send_header("Current activity:");

    my $lowers = $self->upper->accept_command_from_lower( $self, 'LIST ACTIVITY' );

    my $maxlen = max map { length $_ } keys $lowers->%*;
    foreach my $id (sort keys $lowers->%*) {
        my $connection = $lowers->{$id}{connection} // 'idle';
        my $isself = ( $id eq $self->id ) ? '*' : ' ';
        my $out = sprintf("  %s %-${maxlen}s %s", $isself, $id, $connection);

        if ($connection eq 'idle') {
            $self->send_notice($out);
        } else {
            $self->send_alert($out);
        }
    }
}

sub do_connect ( $self, $params ) {
    $self->require_params( 1, $params ) or return;
    $self->require_upper() or return;
    my ($peer) = @$params;

    my $snl = $self->send_nl();
    $peer = fc($peer);

    $self->send_status("Attempting to connect...");
    if (! $self->upper->accept_command_from_lower( $self, 'CONNECT', $peer )) {
        $self->send_status("Could not connect to $peer");
    }
}

sub require_upper($self) {
    if ( defined( $self->upper ) ) { return 1; }

    $self->send_error("Error, no upper!");
    return undef;
}

sub require_params ( $self, $count, $params ) {
    if ( $count eq scalar( $params->@* ) ) { return 1; }

    $self->send_error("Incorrect parameters!");
    return undef;
}

sub accept_command_from_lower ( $self, $lower, $cmd, @data ) {
    if ( !defined( $self->upper ) ) { return; }

    return $self->upper->accept_command_from_lower( $self, $cmd, @data );
}

sub accept_input_from_upper ( $self, $upper, $data ) {
    if ( defined( $self->lower ) ) {
        $self->lower->accept_input_from_upper( $self, $data );
    }
}

sub accept_command_from_upper ( $self, $upper, $cmd, @data ) {
    if ( !defined( $self->lower ) ) { return; }

    if ( $cmd eq 'DISCONNECT SESSION' ) {
        # $self->upper(undef);

        # my $lower = $self->lower;
        # $self->lower(undef);

        # $lower->accept_command_from_upper( $self, $cmd, @data );
        $self->mode('menu');
        $self->send_status('');
        $self->send_status('Disconnected.');
        $self->send_prompt();
    } elsif ( $cmd eq 'OPEN SESSION' ) {
        $self->mode('connected');
        $self->send_status("Connected.");
        $self->lower->accept_command_from_upper( $self, $cmd, @data );
    } else {
        $self->lower->accept_command_from_upper( $self, $cmd, @data );
    }
}

after 'register_lower' => sub ( $self, $lower ) {
    $self->send_prompt();
};

sub send_prompt($self) {
    if ( !defined( $self->lower ) ) { return; }
    $self->lower->accept_input_from_upper( $self, $self->term_prompt );
}

sub send_status ( $self, $status ) {
    if ( !defined( $self->lower ) ) { return; }
    my $out = $self->term_normal . $status . $self->send_nl;
    $self->lower->accept_input_from_upper( $self, $out );
}

sub send_notice ( $self, $notice ) {
    if ( !defined( $self->lower ) ) { return; }
    my $out = $self->term_bright . $self->term_yellow . $notice . $self->term_normal . $self->send_nl;
    $self->lower->accept_input_from_upper( $self, $out );
}

sub send_alert ( $self, $header ) {
    if ( !defined( $self->lower ) ) { return; }
    my $out = $self->term_bright . $self->term_red . $header . $self->term_normal . $self->send_nl;
    $self->lower->accept_input_from_upper( $self, $out );
}

sub send_header ( $self, $header ) {
    if ( !defined( $self->lower ) ) { return; }
    my $out = $self->term_bright . $self->term_cyan . $header . $self->term_normal . $self->send_nl;
    $self->lower->accept_input_from_upper( $self, $out );
}

sub send_error ( $self, $error ) {
    if ( !defined( $self->lower ) ) { return; }
    my $out = $self->term_error . $error . $self->term_normal . $self->send_nl;
    $self->lower->accept_input_from_upper( $self, $out );
}

__PACKAGE__->meta->make_immutable;

1;

