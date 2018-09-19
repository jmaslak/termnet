#!/usr/bin/perl

#
# Copyright (C) 2017 Joelle Maslak
# All Rights Reserved - See License
#

package Termnet::SSH::CipherAes128Ctr;

use Termnet::Boilerplate 'class';

use Crypt::OpenSSL::AES;

with 'Termnet::SSH::Cipher';

sub block_size { return 16; }
sub key_size   { return 16; }

has aes => (
    is       => 'rw',
    isa      => 'Crypt::OpenSSL::AES',
    required => 1,
    builder  => '_build_aes',
    lazy     => 1,
);

sub _build_aes($self) {
    return Crypt::OpenSSL::AES->new( $self->key() );
};

sub id ($self) { return 'aes128-ctr' }

sub decrypt ( $self, $msg ) {
    if (length($msg) % 16 != 0) {
        die("Trying to decrypt message not neatly broken into blocks");
    }
    my (@blocks) = unpack "a16" x (length($msg) / 16), $msg;

    my @out;
    foreach my $block (@blocks) {
        push @out, $self->aes->encrypt($self->iv) ^ $block;
        $self->next_iv();
    }

    return join '', @out;
}

sub encrypt ( $self, $msg) {
    if (length($msg) % 16 != 0) {
        die("Trying to encrypt message not neatly broken into blocks");
    }
    my (@blocks) = unpack "a16" x (length($msg) / 16), $msg;

    my @out;
    foreach my $block (@blocks) {
        push @out, $self->aes->encrypt($self->iv) ^ $block;
        $self->next_iv();
    }

    return join '', @out;
}

sub next_iv ( $self ) {
    my $iv = $self->iv;
    $iv = substr( $iv, 0, 16 );
    my (@c) = reverse split //, $iv;

    my @out;
    my $carry = 1;
    while (@c) {
        my $c = shift(@c);
        if ($carry) {
            $c = chr( ( ord($c) + 1 ) % 256 );
            if ( ord($c) > 0 ) {
                $carry = 0;
            }
        }
        unshift @out, $c;
    }

    $self->iv(join '', @out);
}

sub hexit($data) {
    return join '', map { sprintf( "%02x", ord($_) ) } split( '', $data );
}

__PACKAGE__->meta->make_immutable;

1;

