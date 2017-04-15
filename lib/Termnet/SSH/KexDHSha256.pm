#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

package Termnet::SSH::KexDHSha256;

use Termnet::Boilerplate 'class';

use Crypt::DH qw(-compat);
use Crypt::Digest::SHA256 qw(sha256);
use Crypt::Random;    # For DH
use Math::BigInt;
use Termnet::SSH::DHGroup;

with 'Termnet::SSH::Kex';

my (%MSGID) = (
    SSH_MSG_KEX_DH_GEX_REQUEST_OLD => 30,
    SSH_MSG_KEX_DH_GEX_GROUP       => 31,
    SSH_MSG_KEX_DH_GEX_INIT        => 32,
    SSH_MSG_KEX_DH_GEX_REPLY       => 33,
    SSH_MSG_KEX_DH_GEX_REQUEST     => 34,
);
my (%MSGNAME) = map { $MSGID{$_}, $_ } keys %MSGID;

my %DHGROUP;

has dh => (
    is  => 'rw',
    isa => 'Crypt::DH',
);

has min => (
    is  => 'rw',
    isa => 'Int',
);

has n => (
    is  => 'rw',
    isa => 'Int',
);

has max => (
    is  => 'rw',
    isa => 'Int',
);

has e => (
    is  => 'rw',
    isa => 'Math::BigInt',
);

has g => (
    is  => 'rw',
    isa => 'Math::BigInt',
);

has p => (
    is  => 'rw',
    isa => 'Math::BigInt',
);

has f => (
    is  => 'rw',
    isa => 'Math::BigInt',
);

has k => (
    is  => 'rw',
    isa => 'Math::BigInt',
);

has h => (
    is  => 'rw',
    isa => 'Str',
);

has session_id => (
    is  => 'rw',
    isa => 'Str',
);

has wait_for_newkey => (
    is => 'rw',
    isa => 'Bool',
    required => 1,
    default => 0,
);

sub BUILD ( $self, @args ) {
    state $dh;
}

sub id ($self) { return 'diffie-hellman-group-exchange-sha256'; }

sub handle_msg ( $self, $ssh, $payload ) {
    # Handle the message

    my $msg_id = $ssh->ssh_decode_uint8( $ssh->safe_substr( $payload, 0, 1 ) );
    if ( ( $MSGNAME{$msg_id} // '' ) eq 'SSH_MSG_KEX_DH_GEX_REQUEST' ) {
        $self->recv_msg_request( $ssh, $payload );
    } elsif ( ( $MSGNAME{$msg_id} // '' ) eq 'SSH_MSG_KEX_DH_GEX_INIT' ) {
        $self->recv_msg_init( $ssh, $payload );
    } else {
        ### Receive Unknown KEX Message Type: $msg_id
        $ssh->send_unimplemented_packet($ssh->prev_recv_seq_no);
    }
}

sub recv_msg_request ( $self, $ssh, $payload ) {
    ### Received Message Type SSH_MSG_KEX_DH_GEX_REQUEST

    my $msg_id = $ssh->ssh_decode_uint8( $ssh->safe_substr( $payload, 0, 1 ) );
    my $remainder = $ssh->safe_substr( $payload, 1 );

    $self->min( $ssh->ssh_decode_uint32( $ssh->safe_substr( $remainder, 0, 4 ) ) );
    $self->n( $ssh->ssh_decode_uint32( $ssh->safe_substr( $remainder, 4, 4 ) ) );
    $self->max( $ssh->ssh_decode_uint32( $ssh->safe_substr( $remainder, 8, 4 ) ) );

    ### MIN: $self->min
    ### N:   $self->n
    ### MAX: $self->max

    # We need to send a message to the server
    $self->send_msg_group($ssh);
}

sub recv_msg_init ( $self, $ssh, $payload ) {
    ### Received Message Type SSH_MSG_KEX_DH_GEX_INIT

    my $msg_id = $ssh->ssh_decode_uint8( $ssh->safe_substr( $payload, 0, 1 ) );
    my $remainder = $ssh->safe_substr( $payload, 1 );

    $self->e( $self->binary_to_bigint( $ssh->ssh_decode_string($remainder) ) );

    # We need to send a message to the server
    $self->send_msg_reply($ssh);
}

sub send_msg_group ( $self, $ssh ) {
    ### Sending Message Type SSH_MSG_KEX_DH_GEX_GROUP

    my $param = Termnet::SSH::DHGroup::get_param( $self->min, $self->n, $self->max );
    if ( !defined($param) ) {
        $ssh->error( "Could not negotiate a compatible DH group - "
              . $self->min . '/'
              . $self->n . '/'
              . $self->max );
    }

    ### Size: $param->{size}
    $self->g( Math::BigInt->new( $param->{g} ) );
    $self->p( $self->binary_to_bigint( $param->{p} ) );

    my $payload = join( '',
        $ssh->ssh_uint8( $MSGID{SSH_MSG_KEX_DH_GEX_GROUP} ),
        $ssh->ssh_mpint( $self->p ),
        $ssh->ssh_mpint( $self->g ),
    );
    $ssh->send_packet($payload);
}

sub send_msg_reply ( $self, $ssh ) {
    ### Sending Message Type SSH_MSG_KEX_DH_GEX_REPLY

    my $dh = Crypt::DH->new(
        p => $self->p,
        g => $self->g,
    );
    $self->dh($dh);
    $self->dh->generate_keys;
    $self->f( $self->dh->pub_key );
    $self->k( $self->dh->compute_secret( $self->e ) );

    if ( $self->e >= $self->p ) {    # RFC4419 Section 3
        $ssh->error("e is bigger than k");
    }
    if ( $self->f >= $self->p ) {    # RFC4419 Section 3
        $ssh->error("f is bigger than k");
    }
    if ( $self->k >= $self->p ) {    # RFC4419 Section 3
        $ssh->error("p is bigger than k");
    }

    my $hashstr = join '',
      $ssh->ssh_string( $ssh->v_client ),
      $ssh->ssh_string( $ssh->v_server ),
      $ssh->ssh_string( $ssh->kexinit_client ),
      $ssh->ssh_string( $ssh->kexinit_server ),
      $ssh->ssh_string( $ssh->shk->public_key($ssh) ),
      $ssh->ssh_uint32( $self->min ),
      $ssh->ssh_uint32( $self->n ),
      $ssh->ssh_uint32( $self->max ),
      $ssh->ssh_mpint( $self->p ),
      $ssh->ssh_mpint( $self->g ),
      $ssh->ssh_mpint( $self->e ),
      $ssh->ssh_mpint( $self->f ),
      $ssh->ssh_mpint( $self->k );
    if ( !defined($hashstr) ) { $ssh->error("Problem with hash combination") }
    $self->h( sha256($hashstr) );

    if (!defined($self->session_id)) {
        $self->session_id( $self->h );    # This is always the first H
    }

    my $signed = $ssh->shk->sign( $ssh, $self->h );
    my $sig = $ssh->ssh_string('ssh-rsa') . $ssh->ssh_string($signed);

    my $payload = join( '',
        $ssh->ssh_uint8( $MSGID{SSH_MSG_KEX_DH_GEX_REPLY} ),
        $ssh->ssh_string( $ssh->shk->public_key($ssh) ),
        $ssh->ssh_mpint( $self->f ),
        $ssh->ssh_string($sig),
    );

    ### Sending Message Type SSH_MSG_NEWKEYS
    $ssh->send_packet($payload);
    $ssh->send_newkeys_packet();

    # We can wait for a new key request now
    $self->wait_for_newkey(1);
    $ssh->state('connected');

    # Set server to client keys
    my $mpint_k = $ssh->ssh_mpint( $self->k );
    my $iv      = sha256( $mpint_k . $self->h . 'B' . $self->session_id );
    my $key     = sha256( $mpint_k . $self->h . 'D' . $self->session_id );

    my $enc = $ssh->enc_builder_s2c->( iv => $iv, key => $key );
    $ssh->enc_s2c($enc);

    $ssh->sign_s2c( sha256( $mpint_k . $self->h . 'F' . $self->session_id ) );
    $ssh->block_size_s2c( $ssh->enc_s2c->block_size );

    my $mac = $ssh->mac_builder_s2c->( key => $ssh->sign_s2c );
    $ssh->mac_s2c($mac);
}

sub recv_newkeys ( $self, $ssh, $payload ) {
    ### Received Message Type SSH_MSG_NEWKEYS

    if (! $self->wait_for_newkey) {
        $ssh->error('Received newkeys when not expecting newkeys');
    }
    $self->wait_for_newkey(0);

    # Set client to server keys
    my $mpint_k = $ssh->ssh_mpint( $self->k );
    my $iv      = sha256( $mpint_k . $self->h . 'A' . $self->session_id );
    my $key     = sha256( $mpint_k . $self->h . 'C' . $self->session_id );

    my $enc = $ssh->enc_builder_c2s->( iv => $iv, key => $key );
    $ssh->enc_c2s($enc);

    $ssh->sign_c2s( sha256( $mpint_k . $self->h . 'E' . $self->session_id ) );
    $ssh->block_size_c2s( $ssh->enc_c2s->block_size );

    my $mac = $ssh->mac_builder_c2s->( key => $ssh->sign_c2s );
    $ssh->mac_c2s($mac);
}

sub binary_to_bigint ( $self, $num ) {
    my $n = '00' . join '', map { sprintf( "%02x", ord($_) ) } split( '', $num );
    my $ret = Math::BigInt->from_hex($n);

    return $ret;
}

sub hexit($data) {
    return join '', map { sprintf( "%02x", ord($_) ) } split( '', $data );
}

__PACKAGE__->meta->make_immutable;

1;

