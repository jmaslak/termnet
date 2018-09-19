#!/usr/bin/perl

#
# Copyright (C) 2017 Joelle Maslak
# All Rights Reserved - See License
#

package Termnet::Upper;

use Termnet::Boilerplate 'role';

requires 'accept_input_from_lower', 'accept_command_from_lower',
  'register_lower', 'deregister_lower';

1;

