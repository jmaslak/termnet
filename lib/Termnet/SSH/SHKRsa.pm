#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

package Termnet::SSH::SHKRsa;

use Termnet::Boilerplate 'class';

with 'Termnet::SSH::SHK';

use Crypt::OpenSSL::RSA;
use Perl6::Slurp;

sub id ($self) { return 'ssh-rsa'; }

has rsa_public => (
    is => 'rw',
    isa => 'Crypt::OpenSSL::RSA',
);

has rsa_private => (
    is => 'rw',
    isa => 'Crypt::OpenSSL::RSA',
);

sub load_keys($self, $ssh) {
    if (!defined($self->rsa_public)) {
        my $public  = slurp '<public_key.pem';
        my $private = slurp '<private_key.pem';

        $self->rsa_public(Crypt::OpenSSL::RSA->new_public_key($public));
        $self->rsa_private(Crypt::OpenSSL::RSA->new_private_key($private));

        # XXX We should validate these keys belong with each other
    }
}

sub public_key($self, $ssh) {
    $self->load_keys($ssh);
    my ($n, $e, $d, $p, $q, $d_mod_p, $d_mod_q, $q_mod_p) =
        $self->rsa_public->get_key_parameters();

    my $blob = join '',
        $ssh->ssh_string('ssh-rsa'),
        $ssh->ssh_mpint($e),
        $ssh->ssh_mpint($n);

    return $blob;
}

sub sign($self, $ssh, $data) {
    return $self->rsa_private->sign($data);
}

sub hexit($data) {
    return join '', map { sprintf("%02x", ord($_)) } split('', $data);
}

__PACKAGE__->meta->make_immutable;

1;


