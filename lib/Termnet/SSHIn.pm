#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

package Termnet::SSHIn;

use Termnet::Boilerplate 'class';

use Bytes::Random::Secure qw(random_bytes);
use List::Util qw(any min);

# Key Exchange Algorithms
use Termnet::SSH::KexDHSha256;

# Server Host Key Algorithms
use Termnet::SSH::SHKRsa;

# Ciphers
use Termnet::SSH::CipherAes128Ctr;

# HMACs
use Termnet::SSH::MacSha256;

with 'Termnet::Lower', 'Termnet::UpperSingleChild';

my $crlf = "\r\n";

my $WINDOWSIZE = 2**31;    #  2 GB
my $PACKETSIZE = 2**15;    # 32 MB

my (%MSGID) = (
    SSH_MSG_DISCONNECT                => 1,
    SSH_MSG_IGNORE                    => 2,
    SSH_MSG_UNIMPLEMENTED             => 3,
    SSH_MSG_DEBUG                     => 4,
    SSH_MSG_SERVICE_REQUEST           => 5,
    SSH_MSG_SERVICE_ACCEPT            => 6,
    SSH_MSG_KEXINIT                   => 20,
    SSH_MSG_NEWKEYS                   => 21,
    SSH_MSG_USERAUTH_REQUEST          => 50,
    SSH_MSG_USERAUTH_FAILURE          => 51,
    SSH_MSG_USERAUTH_SUCCESS          => 52,
    SSH_MSG_USERAUTH_BANNER           => 53,
    SSH_MSG_GLOBAL_REQUEST            => 80,
    SSH_MSG_REQUEST_SUCCESS           => 81,
    SSH_MSG_REQUEST_FAILURE           => 82,
    SSH_MSG_CHANNEL_OPEN              => 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION => 91,
    SSH_MSG_CHANNEL_OPEN_FAILURE      => 92,
    SSH_MSG_CHANNEL_WINDOW_ADJUST     => 93,
    SSH_MSG_CHANNEL_DATA              => 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA     => 95,
    SSH_MSG_CHANNEL_EOF               => 96,
    SSH_MSG_CHANNEL_CLOSE             => 97,
    SSH_MSG_CHANNEL_REQUEST           => 98,
    SSH_MSG_CHANNEL_SUCCESS           => 99,
    SSH_MSG_CHANNEL_FAILURE           => 100,
);
my (%MSGNAME) = map { $MSGID{$_}, $_ } keys %MSGID;

# DR = Disconnect Reason
my (%DR) = (
    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT    => 1,
    SSH_DISCONNECT_PROTOCOL_ERROR                 => 2,
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED            => 3,
    SSH_DISCONNECT_RESERVED                       => 4,
    SSH_DISCONNECT_MAC_ERROR                      => 5,
    SSH_DISCONNECT_COMPRESSION_ERROR              => 6,
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE          => 7,
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED => 8,
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE        => 9,
    SSH_DISCONNECT_CONNECTION_LOST                => 10,
    SSH_DISCONNECT_BY_APPLICATION                 => 11,
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS           => 12,
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER         => 13,
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE => 14,
    SSH_DISCONNECT_ILLEGAL_USER_NAME              => 15,
);
my (%DRNAME) = map { $DR{$_}, $_ } keys %DR;

# OR = Open failure Reason
my (%OR) = (
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED => 1,
    SSH_OPEN_CONNECT_FAILED              => 2,
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE        => 3,
    SSH_OPEN_RESOURCE_SHORTAGE           => 4,
);

has type => (
    is       => 'ro',
    isa      => 'Str',
    required => 1,
    init_arg => '_type',
    default  => 'ssh',
);

has state => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    init_arg => '_state',
    default  => 'handshake',    # handshake - not yet received client version
                                # keyexchange - no keys have been
                                #               exchanged yet
                                # connect - we have a secure transport
);

has skip_next_key_exchange => (
    is       => 'rw',
    isa      => 'Bool',
    required => 1,
    init_arg => undef,
    default  => 0,
);

has block_size_c2s => (
    is       => 'rw',
    isa      => 'Int',
    required => 1,
    default  => 8,
);

has block_size_s2c => (
    is       => 'rw',
    isa      => 'Int',
    required => 1,
    default  => 8,
);

has lower_buffer => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    init_arg => '_lower_buffer',
    default  => '',
);

has upper_buffer => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    init_arg => '_upper_buffer',
    default  => '',
);

has send_seq_no => (
    is       => 'rw',
    isa      => 'Int',
    required => 1,
    init_arg => '_send_seq_no',
    default  => 0,
);

has recv_seq_no => (
    is       => 'rw',
    isa      => 'Int',
    required => 1,
    init_arg => '_recv_seq_no',
    default  => 0,
);

has kex_avail => (
    is       => 'rw',
    isa      => 'ArrayRef[Termnet::SSH::Kex]',
    required => 1,
    builder  => '_build_kex_avail',
);

sub _build_kex_avail($self) {
    my @kex;

    push @kex, Termnet::SSH::KexDHSha256->new();

    $self->kex_avail( \@kex );
}

has kex => (
    is  => 'rw',
    isa => 'Maybe[Termnet::SSH::Kex]',
);

has server_host_key_avail => (
    is       => 'rw',
    isa      => 'ArrayRef[Termnet::SSH::SHK]',
    required => 1,
    builder  => '_build_server_host_key_avail',
);

sub _build_server_host_key_avail($self) {
    my @shk;

    push @shk, Termnet::SSH::SHKRsa->new();

    $self->server_host_key_avail( \@shk );
}

has shk => (
    is  => 'rw',
    isa => 'Maybe[Termnet::SSH::SHK]',
);

has enc_c2s => (
    is  => 'rw',
    isa => 'Maybe[Termnet::SSH::Cipher]',
);

has enc_s2c => (
    is  => 'rw',
    isa => 'Maybe[Termnet::SSH::Cipher]',
);

has cipher_avail => (
    is       => 'rw',
    isa      => 'ArrayRef[Termnet::SSH::Cipher]',
    required => 1,
    builder  => '_build_cipher_avail',
);

sub _build_cipher_avail($self) {
    my @cipher;

    push @cipher, Termnet::SSH::CipherAes128Ctr->new();

    $self->cipher_avail( \@cipher );
}

has mac_avail => (
    is       => 'rw',
    isa      => 'ArrayRef[Termnet::SSH::Mac]',
    required => 1,
    builder  => '_build_mac_avail',
);

sub _build_mac_avail($self) {
    my @mac;

    push @mac, Termnet::SSH::MacSha256->new();

    $self->mac_avail( \@mac );
}

has mac_c2s => (
    is  => 'rw',
    isa => 'Maybe[Termnet::SSH::Mac]',
);

has mac_s2c => (
    is  => 'rw',
    isa => 'Maybe[Termnet::SSH::Mac]',
);

has v_client => (
    is  => 'rw',
    isa => 'Str',
);

has v_server => (
    is       => 'rw',
    isa      => 'Str',
    required => 1,
    default  => "SSH-2.0-TermNet_1.0",
);

has kexinit_client => (
    is  => 'rw',
    isa => 'Str',
);

has kexinit_server => (
    is  => 'rw',
    isa => 'Str',
);

has enc_builder_s2c => (
    is  => 'rw',
    isa => 'CodeRef',
);

has enc_builder_c2s => (
    is  => 'rw',
    isa => 'CodeRef',
);

has mac_builder_s2c => (
    is  => 'rw',
    isa => 'CodeRef',
);

has mac_builder_c2s => (
    is  => 'rw',
    isa => 'CodeRef',
);

has sign_c2s => (
    is  => 'rw',
    isa => 'Str',
);

has sign_s2c => (
    is  => 'rw',
    isa => 'Str',
);

has win_theirs => (
    is  => 'rw',
    isa => 'Int',
);

has win_ours => (
    is       => 'rw',
    isa      => 'Int',
    required => 1,
    default  => sub { $WINDOWSIZE },
);

has win_bytes_ours => (
    is       => 'rw',
    isa      => 'Int',
    required => 1,
    default  => sub { 0 },
);

has pkt_size_theirs => (
    is  => 'rw',
    isa => 'Int',
);

has pkt_size_ours => (
    is       => 'rw',
    isa      => 'Int',
    required => 1,
    default  => sub { $PACKETSIZE },
);

has channel => (
    is  => 'rw',
    isa => 'Int',
);

sub accept_input_from_lower ( $self, $lower, $data ) {

    $data = $self->lower_buffer . $data;
    $self->lower_buffer('');

    if ( $self->state eq 'handshake' ) {
        $self->get_handshake($data);

        # We need to let the next phase process this data
        $data = $self->lower_buffer;
        $self->lower_buffer('');
    }

    if ( $self->state ne 'handshake' ) {
        if ( $data eq '' ) { return; }
        $self->get_packet($data);
    }
}

sub accept_input_from_upper ( $self, $upper, $data ) {
    if ( $self->state ne 'connected' ) {
        ### Buffering input from upper
        $self->upper_buffer( $self->upper_buffer . $data );
        return;
    }

    $data = $self->upper_buffer . $data;
    $self->upper_buffer($data);

    if ( $self->state ne 'connected' ) { return; }
    if ( !defined( $self->channel ) )  { return; }

    $self->send_channel_data();
}

sub accept_command_from_upper ( $self, $upper, $cmd, @data ) {
    $self->lower->accept_command_from_upper( $self, $cmd, @data );

    if ( $cmd eq 'DISCONNECT SESSION' ) {
        $self->upper(undef);
        $self->lower(undef);
    }
}

sub accept_command_from_lower ( $self, $lower, $cmd, @data ) {
    if ( defined( $self->upper ) ) {
        $self->upper->accept_command_from_lower( $self, $cmd, @data );
    }
}

around 'register_lower' => sub ( $orig, $self, $lower ) {
    $self->$orig($lower);

    ### ID: $self->id
    my $id = $self->id;
    $id =~ s/^[^:]+:/ssh:/s;    # Make SSH
    $self->id($id);
    ### ID: $self->id

    $self->init_negotiate();
};

sub init_negotiate($self) {
    $self->send_raw_line( $self->v_server() );
}

sub get_handshake ( $self, $input ) {
    my ( $line, $rest ) = $input =~ m/^([^\r\n]*)[\r\n]+(.*)$/s;
    if ( !defined($line) ) {
        $self->lower_buffer($input);
        return;
    }

    $self->lower_buffer($rest);

    my ($ver) = $line =~ m/^SSH-(\d+\.\d+)-.*$/s;
    if ( !defined($ver) ) {
        $self->error(
            "Invalid SSH handshake",
            $DR{SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED},
            'Invalid SSH handshake'
        );
        return;
    }
    if ( $ver < 2.0 ) {
        $self->error(
            "Cannot negotiate SSH 2.0",
            $DR{SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED},
            'Cannot negotiate SSH 2.0'
        );
        return;
    }

    ### Negotiated SSH 2.0
    my ($c_ver) = $line =~ m/^(SSH-[^\r\n]+)/s;
    ### Handshake: $c_ver
    $self->v_client($c_ver);

    $self->state('keyexchange');
    $self->send_kexinit_packet();
}

sub get_packet ( $self, $input ) {
    if ( length($input) < 5 ) { return; }

    my $maclen = defined( $self->mac_c2s ) ? $self->mac_c2s->out_size : 0;

    my $len       = length($input);
    my $encrypted = $input;

    if ( $len < $self->block_size_c2s != 0 ) {
        $self->lower_buffer($input);
        return;
    }

    # Do we need to decrypt?
    my $iv;
    if ( defined( $self->enc_c2s ) ) {
        # decrypt start of packet
        $iv = $self->enc_c2s->iv;
        $input = $self->enc_c2s->decrypt( substr( $encrypted, 0, $self->block_size_c2s ) );
    } else {
        $input = substr( $encrypted, 0, $self->block_size_c2s );
    }

    my $packet_length  = unpack 'N', substr( $input, 0, 4 );
    my $padding_length = unpack 'C', substr( $input, 4, 1 );
    my $payload_length = $packet_length - $padding_length - 1;

    if ( length($encrypted) < ( 4 + $packet_length + $maclen ) ) {
        ### Entire packet not yet received
        if ( defined($iv) ) { $self->enc_c2s->iv($iv); }    # Reset IV
        $self->lower_buffer($encrypted);
        return;
    }

    if ( length($encrypted) > ( 4 + $packet_length + $maclen ) ) {
        ### Received more than one packet
        $self->lower_buffer( substr( $encrypted, 4 + $packet_length + $maclen ) );
        $encrypted = substr( $encrypted, 0, 4 + $packet_length + $maclen );
    }

    my ($mac);
    if ( $maclen > 0 ) {
        $mac = substr( $encrypted, length($encrypted) - $maclen );
        $encrypted = substr( $encrypted, 0, length($encrypted) - $maclen );
    }

    if ( length($encrypted) > $self->block_size_c2s ) {
        if ( defined( $self->enc_c2s ) ) {
            # Decrypt rest of packet
            $input .= $self->enc_c2s->decrypt( substr( $encrypted, $self->block_size_c2s ) );
        } else {
            $input .= substr( $encrypted, $self->block_size_c2s );
        }
    }

    if ( $padding_length < 4 ) { $self->error("Padding too short") }
    my $payload = $payload_length ? substr( $input, 5, $payload_length ) : '';
    my $padding = $padding_length ? substr( $input, 5 + $payload_length, $padding_length ) : '';

    my $seq = $self->recv_seq_no;
    $self->recv_seq_no( $self->recv_seq_no + 1 );
    if ( $maclen > 0 ) {
        my $validmac = $self->mac_c2s->digest( $seq, $input );
        if ( $validmac ne $mac ) {
            $self->error("MAC not valid");
        }
    }

    if ( $payload_length != length($payload) ) { $self->error("Corrupt payload length"); }
    if ( $padding_length != length($padding) ) { $self->error("Corrupt padding length"); }

    my $minlen = 1;
    if ( $payload_length < $minlen ) {
        $self->error("Message too short to make sense (${payload_length})");
    }

    my $msg_id = unpack 'C', $payload;
    my $msgname = $MSGNAME{$msg_id} // $msg_id;
    if ( ( $msg_id >= 30 ) && ( $msg_id <= 49 ) ) {    # RFC4251 7
        if ( !defined( $self->kex ) ) {
            $self->error("Key exchange packet received before KEXINIT");
        }
        if ( $self->skip_next_key_exchange ) {
            $self->skip_next_key_exchange(0);
        } else {
            $self->kex->handle_msg( $self, $payload );
        }
    } elsif ( $msgname eq 'SSH_MSG_DISCONNECT' ) {
        ### Received SSH_MSG_DISCONNECT
        $self->disconnect();
    } elsif ( $msgname eq 'SSH_MSG_IGNORE' ) {
        ### Received SSH_MSG_IGNORE
        # Ignore the message
    } elsif ( $msgname eq 'SSH_MSG_KEXINIT' ) {
        $self->recv_msg_kexinit($payload);
    } elsif ( $msgname eq 'SSH_MSG_NEWKEYS' ) {
        $self->kex->recv_newkeys( $self, $payload );
    } elsif ( $msgname eq 'SSH_MSG_SERVICE_REQUEST' ) {
        $self->recv_svc_request($payload);
    } elsif ( $msgname eq 'SSH_MSG_USERAUTH_REQUEST' ) {
        $self->recv_userauth_request($payload);
    } elsif ( $msgname eq 'SSH_MSG_GLOBAL_REQUEST' ) {
        $self->recv_global_request($payload);
    } elsif ( $msgname eq 'SSH_MSG_CHANNEL_OPEN' ) {
        $self->recv_channel_open($payload);
    } elsif ( $msgname eq 'SSH_MSG_CHANNEL_REQUEST' ) {
        $self->recv_channel_request($payload);
    } elsif ( $msgname eq 'SSH_MSG_CHANNEL_WINDOW_ADJUST' ) {
        $self->recv_channel_window_adjust($payload);
    } elsif ( $msgname eq 'SSH_MSG_CHANNEL_DATA' ) {
        $self->recv_channel_data($payload);
    } else {
        ### Unknown Packet Type: $msg_id
        $self->send_unimplemented_packet($seq);
    }

    if ( $self->lower_buffer ne '' ) {
        my $data = $self->lower_buffer;
        $self->lower_buffer('');
        $self->get_packet($data);
    }
}

sub send_newkeys_packet($self) {
    $self->send_packet( $self->ssh_uint8( $MSGID{'SSH_MSG_NEWKEYS'} ) );
}

sub send_unimplemented_packet ( $self, $seq ) {
    my $pkt = $self->ssh_uint8( $MSGID{'SSH_MSG_UNIMPLEMENTED'} );
    $pkt .= $self->ssh_uint32($seq);

    $self->send_packet($pkt);
}

sub send_userauth_failure( $self ) {
    ### Sending Message Type SSH_MSG_USERAUTH_FAILURE
    my $pkt = $self->ssh_uint8( $MSGID{'SSH_MSG_USERAUTH_FAILURE'} );
    $pkt .= $self->ssh_string('none');    # XXX Not RFC 4252 5.2 Compliant!
    $pkt .= $self->ssh_uint8(0);          # Not partially successful
    $self->send_packet($pkt);
}

sub send_userauth_success( $self ) {
    ### Sending Message Type SSH_MSG_USERAUTH_SUCCESS
    my $pkt = $self->ssh_uint8( $MSGID{'SSH_MSG_USERAUTH_SUCCESS'} );
    $self->send_packet($pkt);
}

sub send_request_failure( $self ) {
    ### Sending Message Type SSH_MSG_REQUEST_FAILURE
    my $pkt = $self->ssh_uint8( $MSGID{'SSH_MSG_REQUEST_FAILURE'} );
    $self->send_packet($pkt);
}

sub send_channel_open_failure ( $self, $channel, $type ) {
    if ( !exists( $OR{$type} ) ) {
        $self->error('Unknown channel failure type');
    }

    my $pkt = $self->ssh_uint8( $MSGID{SSH_MSG_CHANNEL_OPEN_FAILURE} );
    $pkt .= $self->ssh_uint32($channel);
    $pkt .= $self->ssh_uint32( $OR{$type} );
    $pkt .= $self->ssh_string($type);
    $pkt .= $self->ssh_string('en');

    $self->send_packet($pkt);
}

sub send_channel_open_confirmation($self) {
    ### Sending CHANNEL_OPEN_CONFIRMATION

    my $pkt = $self->ssh_uint8( $MSGID{SSH_MSG_CHANNEL_OPEN_CONFIRMATION} );
    $pkt .= $self->ssh_uint32( $self->channel );
    $pkt .= $self->ssh_uint32( $self->channel );         # We use their channel #
    $pkt .= $self->ssh_uint32( $self->win_ours );
    $pkt .= $self->ssh_uint32( $self->pkt_size_ours );

    $self->send_packet($pkt);
}

sub send_channel_success($self) {
    ### Sending CHANNEL_SUCCESS
    my $pkt = $self->ssh_uint8( $MSGID{SSH_MSG_CHANNEL_SUCCESS} );
    $pkt .= $self->ssh_uint32( $self->channel );

    $self->send_packet($pkt);
}

sub send_channel_failure($self) {
    ### Sending CHANNEL_FAILURE
    my $pkt = $self->ssh_uint8( $MSGID{SSH_MSG_CHANNEL_SUCCESS} );
    $pkt .= $self->ssh_uint32( $self->channel );

    $self->send_packet($pkt);
}

sub send_channel_window_adjust ( $self, $adjust_amt ) {
    ### Sending WINDOW_ADJUST
    ### assert: $adjust_amt > 0

    my $pkt = $self->ssh_uint8( $MSGID{SSH_MSG_CHANNEL_WINDOW_ADJUST} );
    $pkt .= $self->ssh_uint32( $self->channel );
    $pkt .= $self->ssh_uint32($adjust_amt);

    $self->send_packet($pkt);
}

sub send_channel_data($self) {
    ### assert: length($self->upper_buffer) > 0

    while ( ( $self->upper_buffer ne '' ) && ( $self->win_theirs > 0 ) ) {
        ##### Sending CHANNEL_DATA
        my $data = $self->upper_buffer;

        my $max_sz = min( $self->pkt_size_theirs, $self->win_theirs );
        if ( $max_sz == 0 ) { return; }    # Can't send right now

        if ( length($data) > $max_sz ) {
            $self->upper_buffer($self->safe_substr( $data, $max_sz ));
            $data = $self->safe_substr( $data, 0, $max_sz );
        } else {
            $self->upper_buffer('');
        }

        $self->win_theirs( $self->win_theirs - length($data) );

        my $pkt = $self->ssh_uint8( $MSGID{SSH_MSG_CHANNEL_DATA} );
        $pkt .= $self->ssh_uint32( $self->channel );
        $pkt .= $self->ssh_string($data);

        $self->send_packet($pkt);
    }
}

sub send_disconnect_packet ( $self, $reason_code, $reason ) {
    if ( !defined($reason_code) ) {
        $reason_code = $DR{SSH_DISCONNECT_PROTOCOL_ERROR};
    }
    if ( !defined($reason) ) {
        $reason = 'Protocol Violation';
    }

    my $pkt = $self->ssh_uint8( $MSGID{'SSH_MSG_DISCONNECT'} );
    $pkt .= $self->ssh_uint32($reason_code);
    $pkt .= $self->ssh_string($reason);
    $pkt .= $self->ssh_string('en');

    $self->send_packet($pkt);
}

sub send_kexinit_packet($self) {
    ### Sending KEXINIT
    my $cookie = random_bytes(16);
    my $kex_algorithms = $self->ssh_string( join ',', map { $_->id } $self->kex_avail->@* );

    my $server_host_key_algorithms =
      $self->ssh_string( join ',', map { $_->id } $self->server_host_key_avail->@* );
    my $encryption_client_to_server =
      $self->ssh_string( join ',', map { $_->id } $self->cipher_avail->@* );
    my $encryption_server_to_client =
      $self->ssh_string( join ',', map { $_->id } $self->cipher_avail->@* );
    my $mac_client_to_server = $self->ssh_string( join ',', map { $_->id } $self->mac_avail->@* );
    my $mac_server_to_client = $self->ssh_string( join ',', map { $_->id } $self->mac_avail->@* );
    my $compression_client_to_server = $self->ssh_string('none');
    my $compression_server_to_client = $self->ssh_string('none');
    my $languages_client_to_server   = $self->ssh_string('');
    my $languages_server_to_client   = $self->ssh_string('');

    my $first_kex_packet_follows = $self->ssh_uint8(0);
    my $future                   = $self->ssh_uint32(0);

    my $payload = join( '',
        $self->ssh_uint8( $MSGID{'SSH_MSG_KEXINIT'} ), $cookie,
        $kex_algorithms,                               $server_host_key_algorithms,
        $encryption_client_to_server,                  $encryption_server_to_client,
        $mac_client_to_server,                         $mac_server_to_client,
        $compression_client_to_server,                 $compression_server_to_client,
        $languages_client_to_server,                   $languages_server_to_client,
        $first_kex_packet_follows,                     $future,
    );
    $self->send_packet($payload);
    $self->kexinit_server($payload);
}

sub send_svc_accept_packet ( $self, $service ) {
    ### Sending SERVICE_ACCEPT for: $service
    my $pkt = $self->ssh_uint8( $MSGID{'SSH_MSG_SERVICE_ACCEPT'} );
    $pkt .= $self->ssh_string($service);

    $self->send_packet($pkt);
}

sub recv_msg_kexinit ( $self, $payload ) {
    ### Received Message Type KEXINIT
    
    if ($self->state eq 'connected') {
        # This is a rekey
        $self->send_kexinit_packet();
    }

    $self->kexinit_client($payload);

    my $msg_id = $self->ssh_decode_uint8( $self->safe_substr( $payload, 0, 1 ) );

    my $remainder = $self->safe_substr( $payload, 17 );
    my $kex_algorithms = $self->ssh_decode_string($remainder);

    $remainder = $self->safe_substr( $remainder, length($kex_algorithms) + 4 );
    my $host_key = $self->ssh_decode_string($remainder);

    $remainder = $self->safe_substr( $remainder, length($host_key) + 4 );
    my $cipher_c2s = $self->ssh_decode_string($remainder);

    $remainder = $self->safe_substr( $remainder, length($cipher_c2s) + 4 );
    my $cipher_s2c = $self->ssh_decode_string($remainder);

    $remainder = $self->safe_substr( $remainder, length($cipher_s2c) + 4 );
    my $mac_c2s = $self->ssh_decode_string($remainder);

    $remainder = $self->safe_substr( $remainder, length($mac_c2s) + 4 );
    my $mac_s2c = $self->ssh_decode_string($remainder);

    $remainder = $self->safe_substr( $remainder, length($mac_s2c) + 4 );
    my $compress_c2s = $self->ssh_decode_string($remainder);

    $remainder = $self->safe_substr( $remainder, length($compress_c2s) + 4 );
    my $compress_s2c = $self->ssh_decode_string($remainder);

    $remainder = $self->safe_substr( $remainder, length($compress_s2c) + 4 );
    my $lang_c2s = $self->ssh_decode_string($remainder);

    $remainder = $self->safe_substr( $remainder, length($lang_c2s) + 4 );
    my $lang_s2c = $self->ssh_decode_string($remainder);

    $remainder = $self->safe_substr( $remainder, length($lang_s2c) + 4 );
    my $kex_follows = $self->ssh_decode_uint8( $self->safe_substr( $remainder, 0, 1 ) );
    my $future = $self->ssh_decode_uint32( $self->safe_substr( $remainder, 1, 4 ) );

    # Determine KEX Algorithm
    my (@our_kex) = $self->kex_avail->@*;
    my (@their_kex) = split ',', $kex_algorithms, -1;
    if ( !@their_kex ) { $self->error("Remote did not send any KEX options"); }

    # Do we ignore the next key exchange specific message?
    if ($kex_follows) {
        if ( $our_kex[0] eq $their_kex[0] ) {
            $self->skip_next_key_exchange(0);
        } else {
            $self->skip_next_key_exchange(1);
        }
    } else {
        $self->skip_next_key_exchange(0);
    }

    while ( !defined( $self->kex ) ) {
        if ( !@their_kex ) {
            $self->error("Could not negotiate a key exchange algorithm");
        }

        my $k = shift @their_kex;
        if ( any { $_->id() eq $k } @our_kex ) {
            my $match = ( grep { $_->id() eq $k } @our_kex )[0];
            $self->kex($match);
        }
    }

    # Determine SHK Algorithm
    my (@our_shk) = $self->server_host_key_avail->@*;
    my (@their_shk) = split ',', $host_key, -1;
    if ( !@their_shk ) { $self->error("Remote did not send any server host key options"); }

    while ( !defined( $self->shk ) ) {
        if ( !@their_shk ) {
            $self->error("Could not negotiate a key exchange algorithm");
        }

        my $k = shift @their_shk;
        if ( any { $_->id() eq $k } @our_shk ) {
            my $match = ( grep { $_->id() eq $k } @our_shk )[0];
            $self->shk($match);
        }
    }

    # Determine Cipher Algorithm
    my (@our_cipher) = $self->cipher_avail->@*;
    my (@their_cipher_c2s) = split ',', $cipher_c2s, -1;
    if ( !@their_cipher_c2s ) {
        $self->error("Remote did not send any client to server cipher options");
    }

    while ( !defined( $self->enc_builder_c2s ) ) {
        if ( !@their_cipher_c2s ) {
            $self->error("Could not negotiate a client to server encryption algorithm");
        }

        my $k = shift @their_cipher_c2s;
        if ( any { $_->id() eq $k } @our_cipher ) {
            my $match = ( grep { $_->id() eq $k } @our_cipher )[0];
            $self->enc_builder_c2s( $match->get_creator() );
            ### C2S Cipher Negotiate: $match->id()
        }
    }

    my (@their_cipher_s2c) = split ',', $cipher_s2c, -1;
    if ( !@their_cipher_s2c ) {
        $self->error("Remote did not send any client to server cipher options");
    }

    while ( !defined( $self->enc_builder_s2c ) ) {
        if ( !@their_cipher_s2c ) {
            $self->error("Could not negotiate a client to server encryption algorithm");
        }

        my $k = shift @their_cipher_s2c;
        if ( any { $_->id() eq $k } @our_cipher ) {
            my $match = ( grep { $_->id() eq $k } @our_cipher )[0];
            $self->enc_builder_s2c( $match->get_creator() );
            ### S2C Cipher Negotiate: $match->id()
        }
    }

    # Determine MAC Algorithm
    my (@our_mac) = $self->mac_avail->@*;
    my (@their_mac_c2s) = split ',', $mac_c2s, -1;
    if ( !@their_mac_c2s ) { $self->error("Remote did not send any client to server MAC options"); }

    while ( !defined( $self->mac_builder_c2s ) ) {
        if ( !@their_mac_c2s ) {
            $self->error("Could not negotiate a client to server MAC algorithm");
        }

        my $k = shift @their_mac_c2s;
        if ( any { $_->id() eq $k } @our_mac ) {
            my $match = ( grep { $_->id() eq $k } @our_mac )[0];
            $self->mac_builder_c2s( $match->get_creator() );
            ### C2S MAC  Negotiate: $match->id()
        }
    }

    my (@their_mac_s2c) = split ',', $mac_s2c, -1;
    if ( !@their_mac_s2c ) { $self->error("Remote did not send any client to server MAC options"); }

    while ( !defined( $self->mac_builder_s2c ) ) {
        if ( !@their_mac_s2c ) {
            $self->error("Could not negotiate a client to server MAC algorithm");
        }

        my $k = shift @their_mac_s2c;
        if ( any { $_->id() eq $k } @our_mac ) {
            my $match = ( grep { $_->id() eq $k } @our_mac )[0];
            $self->mac_builder_s2c( $match->get_creator() );
            ### S2C MAC Negotiate: $match->id()
        }
    }

    ### KEX Negotiate: $self->kex->id
    ### KEX Skip: $self->skip_next_key_exchange
    ### SHK Negotiate: $self->shk->id
}

sub recv_svc_request ( $self, $payload ) {
    ### Received Message Type SERVICE_REQUEST
    if ( $self->state ne 'connected' ) {
        ### Wrong state: $self->state
        $self->error("Service request seen before secure transport established");
    }

    my $msg_id = $self->ssh_decode_uint8( $self->safe_substr( $payload, 0, 1 ) );
    my $service = $self->ssh_decode_string( $self->safe_substr( $payload, 1 ) );

    if ( lc($service) eq 'ssh-userauth' ) {
        ### Service request for ssh-userauth
        $self->send_svc_accept_packet($service);
    } elsif ( lc($service) eq 'foo' ) {
        # Foo
    } else {
        ### Unknown service request for: $service
        ## XXX Handle wrap-around better
        $self->send_unimplemented_packet( $self->recv_seq_no - 1 );
    }
}

sub recv_userauth_request ( $self, $payload ) {
    ### Received Message Type USERAUTH_REQUEST
    if ( $self->state ne 'connected' ) {
        ### Wrong state: $self->state
        $self->error("Authentication request seen before secure transport established");
    }

    my $remainder = $payload;
    my $msg_id = $self->ssh_decode_uint8( $self->safe_substr( $remainder, 0, 1 ) );
    $remainder = $self->safe_substr( $remainder, 1 );

    my $user = $self->ssh_decode_string($remainder);
    $remainder = $self->safe_substr( $remainder, 4 + length($user) );

    my $service = $self->ssh_decode_string($remainder);
    $remainder = $self->safe_substr( $remainder, 4 + length($service) );

    my $method = $self->ssh_decode_string($remainder);
    if ( length($method) + 4 >= length($remainder) ) {
        $remainder = '';
    } else {
        $remainder = $self->safe_substr( $remainder, 4 + length($method) );
    }

    ### User    : $user
    ### Service : $service
    ### Method  : $method

    if ( $service eq 'ssh-connection' ) {
        $self->send_userauth_success();
    } elsif ( $method ne 'none' ) {
        $self->send_userauth_failure();
    } else {
        $self->error(
            'Service not available',
            $DR{SSH_DISCONNECT_SERVICE_NOT_AVAILABLE},
            'Service not available'
        );
    }
}

sub recv_global_request ( $self, $payload ) {
    ### Received Message Type GLOBAL_REQUEST
    if ( $self->state ne 'connected' ) {
        ### Wrong state: $self->state
        $self->error("Global request seen before secure transport established");
    }

    my $remainder = $payload;
    my $msg_id = $self->ssh_decode_uint8( $self->safe_substr( $remainder, 0, 1 ) );
    $remainder = $self->safe_substr( $remainder, 1 );

    my $request_name = $self->ssh_decode_string($remainder);
    if ( length($request_name) + 4 >= length($remainder) ) {
        $remainder = '';
    } else {
        $remainder = $self->safe_substr( $remainder, 4 + length($request_name) );
    }

    ### Request Name: $request_name

    $self->send_request_failure();
}

sub recv_channel_open ( $self, $payload ) {
    ### Received Message Type CHANNEL_OPEN
    if ( $self->state ne 'connected' ) {
        ### Wrong state: $self->state
        $self->error("Channel open seen before secure transport established");
    }

    my $remainder = $payload;
    my $msg_id = $self->ssh_decode_uint8( $self->safe_substr( $remainder, 0, 1 ) );
    $remainder = $self->safe_substr( $remainder, 1 );

    my $channel_type = $self->ssh_decode_string($remainder);
    $remainder = $self->safe_substr( $remainder, 4 + length($channel_type) );

    my $sender_channel = $self->ssh_decode_uint32($remainder);
    $remainder = $self->safe_substr( $remainder, 4 );

    my $win_receive = $self->ssh_decode_uint32($remainder);
    $remainder = $self->safe_substr( $remainder, 4 );

    my $pkt_size_theirs = $self->ssh_decode_uint32($remainder);
    if ( 4 >= length($remainder) ) {
        $remainder = '';
    } else {
        $remainder = $self->safe_substr( $remainder, 4 );
    }

    if ( $channel_type ne 'session' ) {
        ### Unknown channel Type: $channel_type
        $self->send_channel_open_failure( $sender_channel, 'SSH_OPEN_UNKNOWN_CHANNEL_TYPE' );
        return;
    }

    # We know it's a session channel
    if ( defined( $self->channel ) ) {
        ### Attempting to open a second channel
        $self->send_channel_open_failure( $sender_channel, 'SSH_OPEN_ADMINISTRATIVELY_PROHIBITED' );
        return;
    }

    $self->channel($sender_channel);
    $self->win_theirs($win_receive);
    $self->pkt_size_theirs($pkt_size_theirs);

    ### Channel Type: $channel_type
    ### Channel Num : $self->channel
    ### Window Size : $self->win_theirs
    ### Packet Size : $self->pkt_size_theirs

    $self->send_channel_open_confirmation();
}

sub recv_channel_request ( $self, $payload ) {
    ### Received Message Type CHANNEL_REQUEST
    if ( $self->state ne 'connected' ) {
        ### Wrong state: $self->state
        $self->error("Channel request seen before secure transport established");
    }

    if ( !defined( $self->channel ) ) {
        ### No open channel
        $self->error("No currently open channel");
    }

    my $remainder = $payload;
    my $msg_id = $self->ssh_decode_uint8( $self->safe_substr( $remainder, 0, 1 ) );
    $remainder = $self->safe_substr( $remainder, 1 );

    my $channel = $self->ssh_decode_uint32($remainder);
    $remainder = $self->safe_substr( $remainder, 4 );

    my $request_type = $self->ssh_decode_string($remainder);
    $remainder = $self->safe_substr( $remainder, 4 + length($request_type) );

    my $want_reply = $self->ssh_decode_uint8($remainder);
    if ( 1 >= length($remainder) ) {
        $remainder = '';
    } else {
        $remainder = $self->safe_substr( $remainder, 4 );
    }

    if ( $self->channel != $channel ) {
        $self->error("Channel request on wrong channel");
    }

    ### Request Type: $request_type

    ### Reply desired
    if ( $request_type eq 'shell' ) {
        if ($want_reply) { $self->send_channel_success(); }

        # We need to see if we need to send anything
        if ( $self->upper_buffer ne '' ) {
            $self->send_channel_data();
        }
    } else {
        if ($want_reply) { $self->send_channel_failure(); }
    }
}

sub recv_channel_window_adjust ( $self, $payload ) {
    ### Received Message Type CHANNEL_WINDOW_ADJUST
    if ( $self->state ne 'connected' ) {
        ### Wrong state: $self->state
        $self->error("Channel window adjust seen before secure transport established");
    }

    if ( !defined( $self->channel ) ) {
        ### No open channel
        $self->error("No currently open channel");
    }

    my $remainder = $payload;
    my $msg_id = $self->ssh_decode_uint8( $self->safe_substr( $remainder, 0, 1 ) );
    $remainder = $self->safe_substr( $remainder, 1 );

    my $channel = $self->ssh_decode_uint32($remainder);
    $remainder = $self->safe_substr( $remainder, 4 );

    my $adjust = $self->ssh_decode_uint32($remainder);

    if ( $self->channel != $channel ) {
        $self->error("Channel request on wrong channel");
    }

    ### Old Window: $self->win_theirs
    ### Window Adjustment: $adjust
    ### New Window: $self->win_theirs + $adjust

    $self->win_theirs( $self->win_theirs + $adjust );
    if ( $self->win_theirs >= ( 2**32 ) ) {
        $self->error("Their window size grew too much.");
    }

    # We need to see if we need to send anything
    if ( $self->upper_buffer ne '' ) {
        $self->send_channel_data();
    }
}

sub recv_channel_data ( $self, $payload ) {
    ##### Received Message Type CHANNEL_DATA
    if ( $self->state ne 'connected' ) {
        ### Wrong state: $self->state
        $self->error("Channel data seen before secure transport established");
    }

    if ( !defined( $self->channel ) ) {
        ### No open channel
        $self->error("No currently open channel");
    }

    my $remainder = $payload;
    my $msg_id = $self->ssh_decode_uint8( $self->safe_substr( $remainder, 0, 1 ) );
    $remainder = $self->safe_substr( $remainder, 1 );

    my $channel = $self->ssh_decode_uint32($remainder);
    $remainder = $self->safe_substr( $remainder, 4 );

    my $data = $self->ssh_decode_string($remainder);

    if ( $self->channel != $channel ) {
        $self->error("Channel request on wrong channel");
    }

    # Window Management
    $self->win_bytes_ours( $self->win_bytes_ours + length($data) );
    if ( $self->win_bytes_ours > ( $self->win_ours / 2 ) ) {
        $self->win_bytes_ours( $self->win_bytes_ours - ( $self->win_ours / 2 ) );
        $self->send_channel_window_adjust( $self->win_ours / 2 );
    }

    $self->upper->accept_input_from_lower( $self, $data );
}

sub send_packet ( $self, $payload ) {
    if ( !defined( $self->lower ) ) { return; }    # We can't send to lower if it doesn't exist

    my $payloadlen = length($payload);
    my $paddinglen =
      ( ( ( 5 + $payloadlen ) % $self->block_size_s2c ) == 0 )
      ? 0
      : ( $self->block_size_s2c - ( ( 5 + $payloadlen ) % $self->block_size_s2c ) );

    $paddinglen = $paddinglen < 4 ? $paddinglen + $self->block_size_s2c : $paddinglen;
    my $padding = $paddinglen ? random_bytes($paddinglen) : 0;

    $payload = $self->ssh_uint8($paddinglen) . $payload . $padding;
    my $pktlen = length($payload);

    my $pkt = $self->ssh_uint32($pktlen) . $payload;

    my $seq = $self->send_seq_no;
    $self->send_seq_no( $self->send_seq_no + 1 );

    my $mac = '';
    if ( defined( $self->mac_s2c ) ) {
        $mac = $self->mac_s2c->digest( $seq, $pkt );
    }

    if ( defined( $self->enc_s2c ) ) {
        my $enc = $self->enc_s2c->encrypt($pkt);
        $pkt = $enc;
    }

    $pkt .= $mac;

    $self->lower->accept_input_from_upper( $self, $pkt );
}

sub ssh_string ( $self, $data ) {
    return ( pack 'N', length($data) ) . $data;
}

sub ssh_mpint ( $self, $num ) {
    my $s = Math::BigInt->from_hex( $num->to_hex )->to_bytes;
    my $firstval = ord( $self->safe_substr( $s, 0, 1 ) );
    if ( $firstval >= 128 ) { $s = chr(0) . $s; }

    return $self->ssh_string($s);
}

sub ssh_uint8 ( $self, $data ) {
    if ( !defined($data) ) { $self->error('Attempt to read data that does not exist') }
    return pack( 'C', $data );
}

sub ssh_uint32 ( $self, $data ) {
    return pack( 'N', $data );
}

sub ssh_decode_string ( $self, $data ) {
    my $len = $self->ssh_decode_uint32( $self->safe_substr( $data, 0, 4 ) );
    my $str = $self->safe_substr( $data, 4, $len );

    return $str;
}

sub ssh_decode_uint32 ( $self, $data ) {
    return unpack( 'N', $data );
}

sub ssh_decode_uint8 ( $self, $data ) {
    return unpack( 'C', $data );
}

sub error ( $self, $error, $reason_code = undef, $reason = undef ) {
    $self->send_disconnect_packet( $reason_code, $reason );
    $self->disconnect();
    confess($error);
}

sub disconnect($self) {
    if ( defined( $self->upper ) ) {
        ### Deregistering
        $self->upper->deregister_lower($self);
    }
    if (defined($self->lower)) {
        $self->lower->accept_command_from_upper( $self, 'DISCONNECT SESSION' );
    }
}

sub send_raw_line ( $self, $line ) {
    $self->lower->accept_input_from_upper( $self, "$line$crlf" );
}

sub safe_substr ( $self, $str, $offset, $len = undef ) {
    if ( !defined($str) ) {
        $self->error("Attempt to read from undefined string");
    }

    my $strlen = length($str);
    if ( $offset > ( $strlen - 1 ) ) {
        $self->error("Attempt to read with offset beyond end of message");
    }

    if ( !defined($len) ) { return substr( $str, $offset ); }

    if ( ( $offset + $len ) > $strlen ) {
        $self->error("Attempt to read with length beyond end of message");
    }

    return substr( $str, $offset, $len );
}

sub hexit($data) {
    return join '', map { sprintf( "%02x", ord($_) ) } split( '', $data );
}

__PACKAGE__->meta->make_immutable;

1;

