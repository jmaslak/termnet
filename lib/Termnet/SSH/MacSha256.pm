#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

package Termnet::SSH::MacSha256;

use Termnet::Boilerplate 'class';

with 'Termnet::SSH::Mac';

sub id ($self) { return 'hmac-sha2-256' }

__PACKAGE__->meta->make_immutable;

1;


