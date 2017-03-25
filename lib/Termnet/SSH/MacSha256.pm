#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

package Termnet::SSH::MacSha256;

use Termnet::Boilerplate 'class';

use Digest::SHA qw(hmac_sha256 sha256);

with 'Termnet::SSH::Mac';

sub id ($self) { return 'hmac-sha2-256' }

sub key_size { return 32; } # 256
sub out_size { return 32; } # 256

sub digest($self, $seq, $data) {
    ### SEQ: $seq
    ### DAT: hexit($data)
    return hmac_sha256(uint32($seq) . $data, $self->key);
}

sub uint32($data) {
    return pack('N', $data);
}

sub hexit($data) {
    return join '', map { sprintf( "%02x", ord($_) ) } split( '', $data );
}

sub make_key($self, $key) {
    if (length($key) > $self->key_size) {
        $key = sha256($key);
    }
    return $key;
}

__PACKAGE__->meta->make_immutable;

1;


