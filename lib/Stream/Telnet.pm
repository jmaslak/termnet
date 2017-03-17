#!/usr/bin/perl 
#
# Copyright (C) 2017 Joel C. Maslak

# All Rights Reserved - See License
#

package Stream::Telnet;
# ABSTRACT: Handle Telnet protocol in a stream/handle

use Termnet::Boilerplate 'class';

=head1 SYNOPSIS

    my $tn = Stream::Telnet->new();
        readsub  => sub { return <STDIN> },
        writesub => sub($data} { print $data },
    );

    my $received_data = tn->get();
    tn->put('foo');

=cut

=attr readsub

Stores a sub reference that reads data from some input stream.  Should
return either an empty string or the data that is read.

=cut

has readsub => (
    is       => 'rw',
    isa      => 'CodeRef',
    required => 1,
);

=attr writesub

Stores a sub reference that writes data from some input stream.  This should
take one parameter, a scalar string to send.  The return value is unused.

=cut

has writesub => (
    is       => 'rw',
    isa      => 'CodeRef',
    required => 1,
);

=cut

has read_buffer => (
    is => 'rw',
    isa => 'Str',
    default => '',
);


=attr read_buffer

Stores partial reads (primarily only when there is an IAC character but the
packet terminates after the IAC character).

=cut

has read_buffer => (
    is      => 'rw',
    isa     => 'Str',
    default => '',
);

=attr write_buffer

Stores pending writes. These occur when we're attempting to negotiate options
but we don't how the remote box will respond.

=cut

has write_buffer => (
    is      => 'rw',
    isa     => 'Str',
    default => '',
);

=attr char_interrupt

The character used as an interrupt character (C<IAC IC> gets replaced with
this).

=cut

has char_interrupt => (
    is      => 'rw',
    isa     => 'Str',
    default => sub { chr(3) },
);

=attr telnet_goahead

This sotres the characters sent as "go-ahead" characters under the current
telnet configuration.

=cut

has telnet_goahead => (
    is      => 'rw',
    isa     => 'Str',
    default => sub { chr(255) . chr(249) },
);

=attr pending_do

Stores pending DO commands.  These are used to avoid sending a C<DO>
or C<DONT> in response to a client senidng us a C<WILL> or C<WONT>, because
these are just responses to our requests.

This is a HASHREF of signal names.

=cut

has pending_do => (
    is      => 'rw',
    isa     => 'HashRef',
    default => sub { return {} },
);

=attr pending_will

Stores pending WILL commands.  These are used to avoid sending a C<WILL>
or C<WONT> in response to a client senidng us a C<DO> or C<DONT>, because
these are just responses to our requests.

Note also that while a pending WILL exists, we will not send any data to the
client, because we likely need this option to be processed for our data to
make sense to the client.

This is a HASHREF of signal names.

=cut

has pending_will => (
    is      => 'rw',
    isa     => 'HashRef',
    default => sub { return {} },
);

=attr opt_receive_binary

This is true if the remote is sending binary data, false otherwise.

=cut

has opt_receive_binary => (
    is      => 'rw',
    isa     => 'Bool',
    default => undef,
);

=attr opt_send_binary

This is true if we are sending binary data, false otherwise.

=cut

has opt_send_binary => (
    is      => 'rw',
    isa     => 'Bool',
    default => undef,
);

my (%TNOPTS) = (
    0 => 'BINARY',               # Implemented
    1 => 'ECHO',                 # Implemented (server side echo only)
    3 => 'SUPPRESS-GO-AHEAD',    # Implemented
    6 => 'TIMING-MARK',          # Implemented
);

=method init_negotiate()

    $tn->init_negotiate();

Sends initial negotiation (currently negotiates bidirectional binary mode,
no echo, and no "go ahead" messages.

=cut

sub init_negotiate($self) {
    $self->pending_will->{'BINARY'}            = 1;
    $self->pending_will->{'ECHO'}              = 1;
    $self->pending_will->{'SUPPRESS-GO-AHEAD'} = 1;

    $self->pending_do->{'BINARY'}            = 1;
    $self->pending_do->{'ECHO'}              = 1;
    $self->pending_do->{'SUPPRESS-GO-AHEAD'} = 1;

    $self->send_will( chr(0) );    # Send WILL BINARY
    $self->send_will( chr(1) );    # Send WILL ECHO
    $self->send_will( chr(3) );    # Send WILL SUPPRESS-GO-AHEAD

    $self->send_do( chr(0) );      # Send DO BINARY
    $self->send_dont( chr(1) );    # Send DO GO AHEAD
    $self->send_do( chr(3) );      # Send DO SUPPRESS-GO-AHEAD
}

=method put($data)

    $tn->put("Hello\n");

Translates the data passed as a scalar string into the proper format for the
current telnet connection and sends that data.

=cut

sub put ( $self, $data ) {
    if ( keys( $self->pending_will->%* ) ) {
        $self->write_buffer( $self->write_buffer . $data );
        return;
    }

    if ( !$self->opt_send_binary ) {
        # Handle EoL
        $data =~ s/\n/\r\n/gs;
    }

    $data =~ s/\xff/\xff\xff/gs;

    $self->writesub->($data);
}

=method get()

    $tn = $self->get();

Receives data from the current telnet connection, after processing it based on
the current options.

=cut

sub get($self) {
    my $data = $self->read_buffer . $self->readsub->();
    $self->read_buffer('');

    if ( $data eq '' ) { return '' }

    # Handle Telnet Commands
    my $parsed = '';
    while ( $data ne '' ) {
        my ( $part1, $part2 ) = $data =~ m/^([^\xff]*)(.*)/s;
        $data = '';

        if ( !$self->opt_receive_binary ) {
            $part1 =~ s/\r\n/\n/gs;    # Handle EoL
            $part1 =~ s/\0//gs;        # Handle NUL
        }

        $parsed .= $part1;
        if ( $part2 eq '' ) { next; }    # Not a command

        # If part 2 is just a IAC, but no command, we need more data.
        if ( $part2 =~ m/^\xff$/ ) {
            $self->read_buffer($part2);
            last;                        # Done with processing for now.
        }

        # We know we have the IAC (pos 0) and command (pos 1).
        my $cmd = substr( $part2, 1, 1 );
        my $payload = substr( $part2, 2 );

        if ( ord($cmd) == 255 ) {
            $parsed .= chr(255);
        } elsif ( ( ord($cmd) >= 251 ) && ( ord($cmd) <= 254 ) ) {
            if ( length($payload) < 1 ) {
                # We don't have enough data
                $self->read_buffer($part2);
                last;
            }
            my $opt = substr( $payload, 0, 1 );
            $payload = substr( $payload, 1 );

            if ( ord($cmd) == 251 ) {
                $self->handle_will($opt);
            } elsif ( ord($cmd) == 252 ) {
                $self->handle_wont($opt);
            } elsif ( ord($cmd) == 253 ) {
                $self->handle_do($opt);
            } elsif ( ord($cmd) == 254 ) {
                $self->handle_dont($opt);
            } else {
                warn( "Unknown option code: " . ord($opt) );
            }
        } elsif ( ord($cmd) == 249 ) {
            #### CMD: 'GA (go ahead)'
        } elsif ( ord($cmd) == 244 ) {
            #### CMD: 'IP (interrupt process)'
            $parsed .= $self->char_interrupt();
        } elsif ( ord($cmd) == 241 ) {
            #### CMD: 'NOP'
            # Do nothing
        } else {
            warn( "Unknown command code: " . ord($cmd) );
        }

        $data = $payload;
    }

    return $parsed;
}

=method ack_if_needed($opt, $response)

    $tn->ack_if_needed( chr(3), 'WILL' );

This will send a response type of C<$response> if that would not be duplicating
a previously-sent response that wasn't acked/nacked by the other end.  It, as
a side effect, removes the option from the C<pending_do> or C<pending_will>
response lists (depending on if the C<$response> is a C<DO>/C<DONT> or
a C<WILL>/C<WONT>), so that future packets of this type would get acked.
    
=cut

sub ack_if_needed ( $self, $opt, $response ) {
    my $optname = $self->get_opt_name($opt);

    # Send do/don't
    if ( $response eq 'DO' ) {
        if ( exists( $self->pending_do->{$optname} ) ) {
            delete( $self->pending_do->{$optname} );
        } else {
            $self->send_do($opt);
        }
        return undef;
    } elsif ( $response eq 'DONT' ) {
        if ( exists( $self->pending_do->{$optname} ) ) {
            delete( $self->pending_do->{$optname} );
        } else {
            $self->send_dont($opt);
        }
        return undef;
    }

    # Do we need to send any pending output data?
    if ( exists( $self->pending_will->{$optname} ) ) {
        # Do we have any pending will's on this?
        delete( $self->pending_will->{$optname} );

        if ( !keys( $self->pending_will->%* ) ) {
            my $data = $self->write_buffer;
            $self->write_buffer('');
            if ( $data ne '' ) { $self->put($data) }
        }
        return undef;
    }

    # Send will/won't
    if ( $response eq 'WILL' ) {
        $self->send_will($opt);
    } elsif ( $response eq 'WONT' ) {
        $self->send_wont($opt);
    } else {
        die("Unknown response type");
    }
}

=method handle_will($opt)

    $tn->handle_will($opt);

Process an incoming C<WILL> C<$opt> option.

=cut

sub handle_will ( $self, $opt ) {
    #### CMD: 'WILL ' . $self->get_opt_name($opt)
    my $optname  = $self->get_opt_name($opt);
    my $response = 'DONT';                      # Default

    if ( $optname eq 'BINARY' ) {
        $self->opt_receive_binary(1);
        $response = 'DO';
    } elsif ( $optname eq 'ECHO' ) {
        # We do NOT want to have remote do echo
        $response = 'DONT';
    } elsif ( $optname eq 'SUPPRESS-GO-AHEAD' ) {
        $response = 'DO';
    } else {
        $response = 'DONT';
    }

    $self->ack_if_needed( $opt, $response );
}

=method handle_wont($opt)

    $tn->handle_wont($opt);

Process an incoming C<WONT> C<$opt> option.

=cut

sub handle_wont ( $self, $opt ) {
    #### CMD: 'WONT ' . $self->get_opt_name($opt)
    my $optname  = $self->get_opt_name($opt);
    my $response = 'DONT';

    if ( $optname eq 'BINARY' ) {
        $self->opt_receive_binary(undef);
        $response = 'DONT';
    } elsif ( $optname eq 'ECHO' ) {
        $response = 'DONT';
    } elsif ( $optname eq 'SUPPRESS-GO-AHEAD' ) {
        $response = 'DONT';
    } else {
        $response = 'DONT';
    }

    $self->ack_if_needed( $opt, $response );
}

=method handle_do($opt)

    $tn->handle_do($opt);

Process an incoming C<DO> C<$opt> option.

=cut

sub handle_do ( $self, $opt ) {
    #### CMD: 'DO ' . $self->get_opt_name($opt)
    my $optname  = $self->get_opt_name($opt);
    my $response = 'WONT';

    if ( $optname eq 'BINARY' ) {
        $self->opt_send_binary(1);
        $response = 'WILL';
    } elsif ( $optname eq 'ECHO' ) {
        $response = 'WILL';
    } elsif ( $optname eq 'SUPPRESS-GO-AHEAD' ) {
        $self->telnet_goahead('');
        $response = 'WILL';
    } elsif ( $optname eq 'TIMING-MARK' ) {
        $response = 'WILL';
    } else {
        $response = 'WONT';
    }

    $self->ack_if_needed( $opt, $response );
}

=method handle_dont($opt)

    $tn->handle_dont($opt);

Process an incoming C<DONT> C<$opt> option.

=cut

sub handle_dont ( $self, $opt ) {
    #### CMD: 'DONT ' . $self->get_opt_name($opt)
    my $optname  = $self->get_opt_name($opt);
    my $response = 'WONT';

    if ( $optname eq 'BINARY' ) {
        $self->opt_send_binary(undef);
        $response = 'WONT';
    } elsif ( $optname eq 'ECHO' ) {
        $response = 'WONT';
    } elsif ( $optname eq 'SUPPRESS-GO-AHEAD' ) {
        $self->telnet_goahead( chr(255) . chr(249) );
        $response = 'WONT';
    } else {
        $response = 'WONT';
    }

    $self->ack_if_needed( $opt, $response );
}

=method get_opt_name($opt)

    my $nm = $tn->get_opt_name($opt)

Returns the option name for the character C<$opt>, if one is available.  If
the option has not been implemented, returns the numeric code of the option.

=cut

sub get_opt_name ( $self, $opt ) {
    if ( exists( $TNOPTS{ ord($opt) } ) ) {
        return $TNOPTS{ ord($opt) };
    } else {
        return ord($opt);
    }
}

=method send_will($opt)

    $tn->send_will($opt);

Sends a C<WILL> comamnd to the other side.

=cut

sub send_will ( $self, $opt ) {
    #### SEND: 'WILL ' . $self->get_opt_name($opt)
    $self->writesub->( chr(255) . chr(251) . $opt );
}

=method send_wont($opt)

    $tn->send_wont($opt);

Sends a C<WONT> comamnd to the other side.

=cut

sub send_wont ( $self, $opt ) {
    #### SEND: 'WONT ' . $self->get_opt_name($opt)
    $self->writesub->( chr(255) . chr(252) . $opt );
}

=method send_do($opt)

    $tn->send_do($opt);

Sends a C<DO> comamnd to the other side.

=cut

sub send_do ( $self, $opt ) {
    #### SEND: 'DO ' . $self->get_opt_name($opt)
    $self->writesub->( chr(255) . chr(253) . $opt );
}

=method send_dont($opt)

    $tn->send_dont($opt);

Sends a C<DONT> comamnd to the other side.

=cut

sub send_dont ( $self, $opt ) {
    #### SEND: 'DONT ' . $self->get_opt_name($opt)
    $self->writesub->( chr(255) . chr(254) . $opt );
}

__PACKAGE__->meta->make_immutable;

1;

