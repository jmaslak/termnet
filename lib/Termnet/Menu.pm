#!/usr/bin/perl

#
# Copyright (C) 2017-2019 Joelle Maslak
# All Rights Reserved - See License
#

package Termnet::Menu;

use Termnet::Boilerplate 'class';
use AnyEvent;
use List::Util qw(max);
use Time::HiRes qw(time);

with 'Termnet::Lower', 'Termnet::UpperSingleChild';

my (@possibilities) = qw(activity buffer connect exit hangup list resume spew);

has input_buffer => (
    is       => 'rw',
    isa      => 'Str',
    default  => sub { '' },
    required => 1,
);

has upper_buffer => (
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

#
# menu           = typical menu
# connected      = connected
# conn_suspended = esc seq received
#
has mode => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => 'menu',
);

has esc_char => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\x1b",
);

has escape_timeout => (
    is       => 'rw',
    isa      => 'Num',
    required => 1,
    default  => 1.0,
);

has last_escape_time => (
    is       => 'rw',
    isa      => 'Num',
    required => 1,
    default  => 1.0,
);

has needed_esc => (    # How many esc presses to enter menu?
    is       => 'rw',
    isa      => 'Int',
    required => 1,
    default  => 4,
);

has received_esc => (    # How many esc presses have we received?
    is       => 'rw',
    isa      => 'Int',
    required => 1,
    default  => 0,
);

has esc_housekeeping => (    # Used to keep the housekeeping function alive
    is       => 'rw',
    required => 0,
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

has recv_tab => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "\t",
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
    # default  => "\x1b[1m",
    default => "",
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
    # default  => "\x1b[1m\x1b[32mTERMNET\x1b[33m->\x1b[0m ",
    default => "\x1b[1m\x1b[32mTERMNET\x1b[0m->\x1b[0m ",
);

has allow_exit => (
    is       => 'rw',
    isa      => 'Bool',
    required => 1,
    default  => 1,
);

sub accept_input_from_lower ( $self, $lower, $data ) {
    if ( $data eq '' ) { return; }

    if ( $self->mode eq 'connected' ) {
        $self->accept_input_connected_mode( $lower, $data );
    } elsif ( $self->mode eq 'menu' ) {
        $self->accept_input_menu_mode( $lower, $data );
    } elsif ( $self->mode eq 'conn_suspended' ) {
        $self->accept_input_menu_mode( $lower, $data );
    } else {
        die( "unknown mode: " . $self->mode );
    }

    return;
}

sub accept_input_connected_mode ( $self, $lower, $data ) {
    my $esc  = $self->esc_char;
    my $tm   = $self->last_escape_time;
    my $to   = $self->escape_timeout;
    my $need = $self->needed_esc;
    my $now  = time;

    if ( defined( $self->upper ) ) {

        # We check to see if we got just escapes and we don't have too many.
        if ( ( $data =~ m/^${esc}+$/s ) && ( ( $self->received_esc + length($data) ) <= $need ) ) {
            if ( $self->received_esc == 0 ) {
                # New escape
                # So we need to ensure we didn't receive anything within
                # the last timeout period.

                if ( ( $tm + $to ) <= $now ) {
                    # We are within time to add our escapes
                    $self->received_esc( length($data) );
                    $self->last_escape_time($now);
                    $data = '';
                    $self->setup_esc_callback();
                }
            } else {
                # We already have escapes buffered
                # So we need to make sure that this esc is within the
                # timeout.

                if ( ( $tm + $to ) >= $now ) {
                    # We are within time to add escapes
                    $self->received_esc( $self->received_esc + length($data) );
                    $self->last_escape_time($now);
                    $data = '';
                    $self->setup_esc_callback();
                }
            }
        }

        if ( $data ne '' ) {
            if ( $self->received_esc > 0 ) {
                $data .= $esc x $self->received_esc;
                $self->received_esc(0);
                $self->esc_housekeeping(undef);
            }
            $self->upper->accept_input_from_lower( $self, $data );
            $self->last_escape_time($now);
        }
    }

    return;
}

sub setup_esc_callback($self) {
    my $cb = sub {
        if ( $self->received_esc == $self->needed_esc ) {
            # We have escapes!
            $self->received_esc(0);
            $self->mode('conn_suspended');
            $self->send_prompt();
            $self->esc_housekeeping(undef);
        } else {
            my $data = $self->esc_char x $self->received_esc;
            $self->received_esc(0);
            $self->last_escape_time(time);    # So we don't treat it like a new esc
            $self->accept_input_from_upper( $self->upper, $data );
            $self->esc_housekeeping(undef);
        }
    };

    # Overwrite and thus blow away the old callback, if one exists.
    $self->esc_housekeeping( AnyEvent->timer( after => 1.0, cb => $cb ) );

    return;
}

sub accept_input_menu_mode ( $self, $lower, $data ) {

    # Shorter versions of common variables
    my $rbs  = $self->recv_bs;
    my $rdel = $self->recv_del;
    my $rnl  = $self->recv_nl;
    my $rtab = $self->recv_tab;
    my $sbs  = $self->send_bs;
    my $snl  = $self->send_nl;

    $data =~ s/${rnl}/\n/gs;

    my $out = '';    # what we send out

    my $line = $self->input_buffer();    # Current line being input
    $self->input_buffer('');

    my (@chars) = split '', $data;
    while ( length($data) > 0 ) {
        my $c;
        ( $c, $data ) = $data =~ m/^(.)(.*)$/s;

        if ( $c eq "\n" ) {
            # Handle newline

            # Output line
            $out .= $snl;
            $lower->accept_input_from_upper( $self, $out );
            $out = '';

            # Do command
            $self->do_command_line($line);
            $line = '';

            # Do we need to prompt?
            if ( $self->mode eq 'menu' ) {
                $self->send_prompt();
            } elsif ( $self->mode eq 'conn_suspended' ) {
                $self->send_prompt();
            } else {
                $self->input_buffer($data);
                $self->accept_input_from_lower( $lower, $data );    # Process command line
                return;    # We aren't in menu mode, so we return here.
            }

        } elsif ( $c eq $rtab ) {
            if ( $line =~ m/\s/s ) {
                # Only valid on first param (the command)
                $out .= $self->send_bell();
            } else {
                my (@choices) = $self->completions($line);
                if ( scalar(@choices) == 0 ) {
                    $out .= $self->send_bell();
                } elsif ( scalar(@choices) == 1 ) {
                    my $comp = $choices[0];
                    my $l    = fc($line);
                    $comp =~ s/^${l}//s;

                    $out  .= $comp . ' ';
                    $line .= $comp . ' ';
                } else {
                    $out .= $snl;
                    $self->lower->accept_input_from_upper( $self, $out );
                    $out = '';

                    foreach my $c (@choices) {
                        $self->send_status("    $c");
                    }
                    $self->send_prompt();
                    $self->lower->accept_input_from_upper( $self, $line );
                }
            }
        } elsif ( ( $c eq $rbs ) || ( $c eq $rdel ) ) {
            # Handle backspace

            if ( length($line) > 0 ) {
                $line =~ s/.$//s;
                $out .= $sbs;
            } else {
                # We are at start of line
                $out .= $self->send_bell();
            }
        } else {
            # All other characters

            $line .= $c;
            $out  .= $c;
        }
    }

    $self->input_buffer($line);
    if ( $out ne '' ) {
        $lower->accept_input_from_upper( $self, $out );    # Echo to client
    }

    return;
}

sub do_command_line ( $self, $line ) {
    # Handle a command line

    # Trim front and back of line
    $line =~ s/^\s+//s;
    $line =~ s/\s+$//s;

    my (@parts) = split /\s+/, $line;
    my $cmd = fc( shift(@parts) // '' );

    if ( $cmd eq 'activity' ) {
        $self->do_activity( \@parts );
    } elsif ( $cmd eq 'buffer' ) {
        $self->do_buffer( \@parts );
    } elsif ( ( $cmd eq 'c' ) || ( $cmd eq 'connect' ) ) {
        $self->do_connect( \@parts );
    } elsif ( $cmd eq 'exit' ) {
        if ( $self->allow_exit ) {
            $self->do_exit( \@parts );
        } else {
            $self->send_error("Cannot exit menu from permanent console");
        }
    } elsif ( $cmd eq 'hangup' ) {
        $self->do_hangup( \@parts );
    } elsif ( $cmd eq 'resume' ) {
        $self->do_resume( \@parts );
    } elsif ( $cmd eq 'spew' ) {
        $self->do_spew( \@parts );
    } elsif ( $cmd eq 'list' ) {
        $self->do_list( \@parts );
    } elsif ( $cmd eq '' ) {
        # Do nothing
    } else {
        $self->send_error("Invalid command!");
    }

    return;
}

sub do_exit ( $self, $params ) {
    $self->require_params( 0, $params ) or return;

    $self->esc_housekeeping(undef);

    $self->send_status("Goodbye");
    if ( defined( $self->upper ) ) {
        $self->upper->deregister_lower($self);
    }
    $self->lower->accept_command_from_upper( $self, 'DISCONNECT SESSION' );

    return;
}

sub do_hangup ( $self, $params ) {
    $self->require_params( 0, $params ) or return;
    if ( $self->mode ne 'conn_suspended' ) {
        $self->send_error("No connection is suspended!");
        return;
    }

    $self->send_status("Disconnecting currently connected session");
    $self->upper->accept_command_from_lower( $self, 'HANGUP' );
    $self->upper_buffer('');

    return;
}

sub do_resume ( $self, $params ) {
    $self->require_params( 0, $params ) or return;
    if ( $self->mode ne 'conn_suspended' ) {
        $self->send_error("No connection is suspended!");
        return;
    }

    $self->send_status("Resuming suspended session");
    $self->mode('connected');

    if ( $self->upper_buffer ne '' ) {
        my $data = $self->upper_buffer;
        $self->upper_buffer('');
        $self->accept_input_from_upper( $self->upper, $data );
    }

    return;
}

sub do_spew ( $self, $params ) {
    $self->require_params( 1, $params ) or return;
    $self->require_nonnegative_integer( $params->[0] ) or return;

    $self->send_noformat( "x" x $params->[0] );

    return;
}

sub do_list ( $self, $params ) {
    $self->require_params( 0, $params ) or return;
    $self->require_upper() or return;

    my $snl = $self->send_nl();

    $self->send_header("Available Endpoints:");

    my $list = $self->upper->accept_command_from_lower( $self, 'LIST NAMES' );

    my $maxlen = max map { length $_ } keys $list->%*;
    foreach my $id ( sort keys $list->%* ) {
        my $status = $list->{$id}{connection} ? 'BUSY' : 'idle';
        my $out    = sprintf( "    %-${maxlen}s (%s)", $id, $status );

        if ( $status eq 'BUSY' ) {
            $self->send_alert($out);
        } else {
            $self->send_notice($out);
        }
    }

    return;
}

sub do_activity ( $self, $params ) {
    $self->require_params( 0, $params ) or return;
    $self->require_upper() or return;

    my $snl = $self->send_nl();

    $self->send_header("Current activity:");

    my $lowers = $self->upper->accept_command_from_lower( $self, 'LIST ACTIVITY' );

    my $maxlen = max map { length $_ } keys $lowers->%*;
    foreach my $id ( sort keys $lowers->%* ) {
        my $connection = $lowers->{$id}{connection} // 'idle';
        my $isself     = ( $id eq $self->id ) ? '*' : ' ';
        my $out        = sprintf( "  %s %-${maxlen}s %s", $isself, $id, $connection );

        if ( $connection eq 'idle' ) {
            $self->send_notice($out);
        } else {
            $self->send_alert($out);
        }
    }

    return;
}

sub do_buffer ( $self, $params ) {
    $self->require_params( 0, $params ) or return;
    $self->require_upper() or return;

    if ( $self->mode ne 'conn_suspended' ) {
        $self->send_error("No connection is suspended!");
        return;
    }

    $self->send_status("Cleared receive buffer");
    $self->upper_buffer('');

    return;
}

sub do_connect ( $self, $params ) {
    $self->require_params( 1, $params ) or return;
    $self->require_upper() or return;
    my ($peer) = @$params;

    my $snl = $self->send_nl();
    $peer = fc($peer);

    $self->send_status("Attempting to connect...");
    if ( !$self->upper->accept_command_from_lower( $self, 'CONNECT', $peer ) ) {
        $self->send_status("Could not connect to $peer");
    }

    return;
}

sub require_upper($self) {
    if ( defined( $self->upper ) ) { return 1; }

    $self->send_error("Error, no upper!");
    return;
}

sub require_nonnegative_integer ( $self, $param ) {
    if ( !defined($param) ) {
        $self->send_error("No integer provided!");
        return;
    }
    if ( $param !~ m/^\d+$/s ) {
        $self->send_error("Invalid non-negative integer provided!");
        return;
    }

    return 1;
}

sub require_params ( $self, $count, $params ) {
    if ( $count eq scalar( $params->@* ) ) { return 1; }

    $self->send_error("Incorrect parameters!");
    return;
}

sub accept_command_from_lower ( $self, $lower, $cmd, @data ) {
    if ( !defined( $self->upper ) ) { return; }

    return $self->upper->accept_command_from_lower( $self, $cmd, @data );
}

sub accept_input_from_upper ( $self, $upper, $data ) {
    if ( defined( $self->lower ) ) {
        if ( $self->mode eq 'connected' ) {
            $self->lower->accept_input_from_upper( $self, $data );
        } elsif ( $self->mode eq 'conn_suspended' ) {
            $self->upper_buffer( $self->upper_buffer . $data );
        }
    }

    return;
}

sub accept_command_from_upper ( $self, $upper, $cmd, @data ) {
    if ( !defined( $self->lower ) ) { return; }

    if ( $cmd eq 'DISCONNECT SESSION' ) {
        $self->esc_housekeeping(undef);

        my $oldmode = $self->mode();
        $self->mode('menu');
        if ( $oldmode eq 'connected' ) {
            $self->send_status('');
            $self->send_status('Disconnected from remote.');
            $self->send_prompt();
        } else {
            # $self->send_status('');
            $self->send_status('Disconnected from remote.');
            # $self->send_prompt();
        }
    } elsif ( $cmd eq 'OPEN SESSION' ) {
        $self->mode('connected');
        $self->send_status("Connected.");
        $self->lower->accept_command_from_upper( $self, $cmd, @data );
    } else {
        $self->lower->accept_command_from_upper( $self, $cmd, @data );
    }

    return;
}

after 'register_lower' => sub ( $self, $lower ) {
    $self->send_prompt();
};

sub send_prompt($self) {
    if ( !defined( $self->lower ) ) { return; }
    $self->lower->accept_input_from_upper( $self, $self->term_prompt );

    return;
}

sub send_status ( $self, $status ) {
    if ( !defined( $self->lower ) ) { return; }
    my $out = $self->term_normal . $status . $self->send_nl;
    $self->lower->accept_input_from_upper( $self, $out );

    return;
}

sub send_noformat ( $self, $msg ) {
    if ( !defined( $self->lower ) ) { return; }
    $self->lower->accept_input_from_upper( $self, $msg );

    return;
}

sub send_notice ( $self, $notice ) {
    if ( !defined( $self->lower ) ) { return; }
    my $out =
      $self->term_bright . $self->term_yellow . $notice . $self->term_normal . $self->send_nl;
    $self->lower->accept_input_from_upper( $self, $out );

    return;
}

sub send_alert ( $self, $header ) {
    if ( !defined( $self->lower ) ) { return; }
    my $out = $self->term_bright . $self->term_red . $header . $self->term_normal . $self->send_nl;
    $self->lower->accept_input_from_upper( $self, $out );

    return;
}

sub send_header ( $self, $header ) {
    if ( !defined( $self->lower ) ) { return; }
    my $out = $self->term_bright . $self->term_cyan . $header . $self->term_normal . $self->send_nl;
    $self->lower->accept_input_from_upper( $self, $out );

    return;
}

sub send_error ( $self, $error ) {
    if ( !defined( $self->lower ) ) { return; }
    my $out = $self->term_error . $error . $self->term_normal . $self->send_nl;
    $self->lower->accept_input_from_upper( $self, $out );

    return;
}

sub completions ( $self, $line ) {
    if ( $line eq '' ) {
        return map { fc($_) } @possibilities;
    }
    my $l = fc($line);

    my @out;
    foreach my $c ( sort map { fc($_) } @possibilities ) {
        if ( $c =~ m/^${l}/s ) {
            push @out, $c;
        }
    }
    return @out;
}

__PACKAGE__->meta->make_immutable;

1;

