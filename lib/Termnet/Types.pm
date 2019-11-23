#!/usr/bin/perl

#
# Copyright (C) 2017,2019 Joelle Maslak
# All Rights Reserved - See License
#

package Termnet::Types;

use Termnet::Boilerplate 'script';

use Moose::Util::TypeConstraints;

role_type 'Termnet::LowerObj' => { role => 'Termnet::Lower' };

1;

