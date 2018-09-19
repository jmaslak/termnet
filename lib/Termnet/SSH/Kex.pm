#!/usr/bin/perl

#
# Copyright (C) 2017 Joelle Maslak
# All Rights Reserved - See License
#

package Termnet::SSH::Kex;

use Termnet::Boilerplate 'role';

requires 'id', 'handle_msg', 'recv_newkeys';

1;

