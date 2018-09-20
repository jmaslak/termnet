#!/bin/bash

#
# Copyright (C) 2018 Joelle Maslak
# All Rights Reserved - See License
#

doit() {
    openssl genrsa -out private_key.pem 2048
    openssl rsa -in private_key.pem -outform PEM -pubout -out public_key.pem
}

doit "$@"


