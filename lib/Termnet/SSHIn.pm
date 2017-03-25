#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

package Termnet::SSHIn;

use Termnet::Boilerplate 'class';

use Bytes::Random::Secure qw(random_bytes);
use List::Util qw(any);

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
    default  => 'handshake',
);

has skip_next_key_exchange => (
    is       => 'rw',
    isa      => 'Bool',
    required => 1,
    init_arg => undef,
    default  => 0,
);

has block_size_c2s => (
    is => 'rw',
    isa => 'Int',
    required => 1,
    default => 8,
);

has block_size_s2c => (
    is => 'rw',
    isa => 'Int',
    required => 1,
    default => 8,
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
    is => 'rw',
    isa => 'Maybe[Termnet::SSH::Cipher]',
);

has enc_s2c => (
    is => 'rw',
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
    is => 'rw',
    isa => 'Maybe[Termnet::SSH::Mac]',
);

has mac_s2c => (
    is => 'rw',
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
    is => 'rw',
    isa => 'Str',
);

has kexinit_server => (
    is => 'rw',
    isa => 'Str',
);

has enc_builder_s2c => (
    is => 'rw',
    isa => 'CodeRef',
);

has enc_builder_c2s => (
    is => 'rw',
    isa => 'CodeRef',
);

has mac_builder_s2c => (
    is => 'rw',
    isa => 'CodeRef',
);

has mac_builder_c2s => (
    is => 'rw',
    isa => 'CodeRef',
);

has sign_c2s => (
    is => 'rw',
    isa => 'Str',
);

has sign_s2c => (
    is => 'rw',
    isa => 'Str',
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
    $self->upper_buffer('');

    # if (defined($self->lower)) {
    #     $self->lower->accept_input_from_upper($self, $data);
    # }
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

after 'register_lower' => sub ( $self, $lower ) {
    $self->init_negotiate();
};

sub init_negotiate($self) {
    $self->send_raw_line($self->v_server());
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
        $self->error("Invalid SSH handshake");
        return;
    }
    if ( $ver < 2.0 ) {
        $self->error("Cannot negotiate SSH 2.0");
        return;
    }

    ### Negotiated SSH 2.0
    my ($c_ver) = $line =~ m/^(SSH-[^\r\n]+)/s;
    ### Handshake: $c_ver
    $self->v_client($c_ver);

    $self->state('connected');
    $self->send_kexinit_packet();
}

sub get_packet ( $self, $input ) {
    if ( length($input) < 5 ) { return; }

    my $maclen = defined($self->mac_c2s) ? $self->mac_c2s->out_size : 0;

    my $len = length($input);
    my $encrypted = $input;

    if ($len < $self->block_size_c2s != 0) {
        $self->lower_buffer($input);
        return;
    }

    # Do we need to decrypt?
    my $iv;
    if (defined($self->enc_c2s)) {
        # decrypt start of packet
        $iv = $self->enc_c2s->iv;
        $input = $self->enc_c2s->decrypt( substr($encrypted, 0, $self->block_size_c2s ));
    } else {
        $input = substr($encrypted, 0, $self->block_size_c2s);
    }

    my $packet_length  = unpack 'N', substr( $input, 0, 4 );
    my $padding_length = unpack 'C', substr( $input, 4, 1 );
    my $payload_length = $packet_length - $padding_length - 1;

    if ( length($encrypted) < ( 4 + $packet_length + $maclen ) ) {
        ### Packet Length longer than data available: $packet_length
        ### Our Len: length($encrypted)
        if (defined($iv)) { $self->enc_c2s->iv($iv); } # Reset IV 
        $self->lower_buffer($encrypted);
        return;
    }

    if ( length($encrypted) > ( 4 + $packet_length + $maclen ) ) {
        ### Received more than one packet
        ### Storing: hexit(substr($encrypted, 4 + $packet_length + $maclen))
        $self->lower_buffer(substr($encrypted, 4 + $packet_length + $maclen));
        $encrypted = substr($encrypted, 4 + $packet_length + $maclen);
    }

    my ($mac);
    if ($maclen > 0) {
        $mac = substr($encrypted, length($encrypted) - $maclen);
        $encrypted = substr($encrypted, 0, length($encrypted) - $maclen);
    }

    if (length($encrypted) > $self->block_size_c2s) {
        if (defined($self->enc_c2s)) {
            # Decrypt rest of packet
            $input .= $self->enc_c2s->decrypt( substr($encrypted, $self->block_size_c2s) );
        } else {
            $input .= substr($encrypted, $self->block_size_c2s);
        }
    }

    if ( $padding_length < 4 ) { $self->error("Padding too short"); }
    my $payload = $payload_length ? substr( $input, 5,                   $payload_length ) : '';
    my $padding = $padding_length ? substr( $input, 5 + $payload_length, $padding_length ) : '';

    my $seq = $self->recv_seq_no;
    $self->recv_seq_no($self->recv_seq_no + 1 );
    if ($maclen > 0) {
        my $validmac = $self->mac_c2s->digest($seq, $input);
        if ($validmac ne $mac) {
            ### MAC1: hexit($validmac)
            ### MAC2: hexit($mac)
            $self->error("MAC not valid");
        }
    }

    ### PL: $payload_length
    ### LP: length($payload)
    ### LE: length($encrypted)
    ### LI: length($input)
    if ( $payload_length != length($payload) ) { $self->error("Corrupt payload length"); }
    if ( $padding_length != length($padding) ) { $self->error("Corrupt padding length"); }

    my $minlen = 1;
    if ( $payload_length < $minlen ) { $self->error("Message too short to make sense (${payload_length})"); }

    my $msg_id = unpack 'C', $payload;
    if ( ( $msg_id >= 30 ) && ( $msg_id <= 49 ) ) {    # RFC4251 7
        if ( !defined( $self->kex ) ) {
            $self->error("Key exchange packet received before KEXINIT");
        }
        if ( $self->skip_next_key_exchange ) {
            $self->skip_next_key_exchange(0);
        } else {
            $self->kex->handle_msg( $self, $payload );
        }
    } elsif ( ( $MSGNAME{$msg_id} // '' ) eq 'SSH_MSG_DISCONNECT' ) {
        ### Received SSH_MSG_DISCONNECT
        $self->error("Disconnect at request of other side");
    } elsif ( ( $MSGNAME{$msg_id} // '' ) eq 'SSH_MSG_IGNORE' ) {
        ### Received SSH_MSG_IGNORE
        # Ignore the message
    } elsif ( ( $MSGNAME{$msg_id} // '' ) eq 'SSH_MSG_KEXINIT' ) {
        $self->recv_msg_kexinit($payload);
    } elsif ( ( $MSGNAME{$msg_id} // '' ) eq 'SSH_MSG_NEWKEYS' ) {
        $self->kex->recv_newkeys($self, $payload);
    } else {
        ### Unknown Packet Type: $msg_id
        $self->error("DISCONNECT");
    }
}

sub send_newkeys_packet($self) {
    $self->send_packet($self->ssh_uint8( $MSGID{'SSH_MSG_NEWKEYS'} ));
}

sub send_disconnect_packet($self) {
    $self->send_packet($self->ssh_uint8( $MSGID{'SSH_MSG_DISCONNECT'} ));
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

sub recv_msg_kexinit ( $self, $payload ) {
    ### Received Message Type KEXINIT

    $self->kexinit_client($payload);

    my $msg_id = $self->ssh_decode_uint8( $self->safe_substr( $payload, 0, 1 ) );
    my $cookie = $self->safe_substr( $payload, 1, 16 );

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
    if ( !@their_cipher_c2s ) { $self->error("Remote did not send any client to server cipher options"); }

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
    if ( !@their_cipher_s2c ) { $self->error("Remote did not send any client to server cipher options"); }

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

sub send_packet ( $self, $payload ) {
    my $payloadlen = length($payload);
    my $paddinglen = ( ( ( 5 + $payloadlen ) % $self->block_size_s2c ) == 0 ) ? 0 : ( $self->block_size_s2c - ( ( 5 + $payloadlen ) % $self->block_size_s2c ) );

    $paddinglen = $paddinglen < 4 ? $paddinglen + $self->block_size_s2c : $paddinglen;
    my $padding = $paddinglen ? random_bytes($paddinglen) : 0;

    $payload = $self->ssh_uint8($paddinglen) . $payload . $padding;
    my $pktlen = length($payload);

    my $pkt = $self->ssh_uint32($pktlen) . $payload;

    my $seq = $self->send_seq_no;
    $self->send_seq_no($self->send_seq_no + 1);
  
    my $mac = ''; 
    if (defined($self->mac_s2c)) {
        my $mac = $self->mac_s2c->digest($seq, $pkt);
    }

    if (defined($self->enc_s2c)) {
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
    my $s = Math::BigInt->from_hex($num->to_hex)->to_bytes;
    my $firstval = ord($self->safe_substr($s, 0, 1));
    if ($firstval >= 128) { $s = chr(0) . $s; }

    return $self->ssh_string($s);
}

sub ssh_uint8 ( $self, $data ) {
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

sub error ( $self, $error ) {
    $self->send_disconnect_packet();
    $self->disconnect();
    confess($error);
}

sub disconnect($self) {
    if ( defined( $self->upper ) ) {
        $self->upper->deregister_lower($self);
    }
    $self->lower->accept_command_from_upper( $self, 'DISCONNECT SESSION' );
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

