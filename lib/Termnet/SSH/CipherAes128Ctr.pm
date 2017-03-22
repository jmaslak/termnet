#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

package Termnet::SSH::CipherAes128Ctr;

use Termnet::Boilerplate 'class';

with 'Termnet::SSH::Cipher';

sub id ($self) { return 'aes128-ctr' }

__PACKAGE__->meta->make_immutable;

1;


