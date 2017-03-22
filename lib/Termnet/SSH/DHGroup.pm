#!/usr/bin/perl

#
# Copyright (C) 2017 Joel C. Maslak
# All Rights Reserved - See License
#

package Termnet::SSH::DHGroup;

use Termnet::Boilerplate 'script';

my (%DHPARAM) = (
    512 => [
        {
            g   => Math::BigInt->new(2),
            txt => [
                qw(
                  00:d1:5c:0f:47:d2:a2:70:3d:41:40:90:a5:d6:d7:
                  70:2c:8f:cd:60:2a:f3:59:0e:40:59:7e:df:99:59:
                  bf:26:fe:68:18:8c:11:ff:b0:54:2e:df:05:ef:4b:
                  9b:33:c3:a9:e9:5f:5d:ee:55:c5:8d:c9:ed:81:7d:
                  29:a0:46:1a:0b
                  )
            ],
        },
    ],
    1024 => [
        {
            g   => Math::BigInt->new(2),
            txt => [
                qw(
                  00:cf:f5:62:c6:d6:1b:62:85:89:02:e4:77:23:10:
                  b3:6c:68:eb:ca:2e:34:70:bb:1d:27:bb:36:36:bd:
                  af:b4:d5:32:95:08:36:40:0f:7f:6d:7d:ad:5b:99:
                  9c:46:5b:37:db:28:d5:ec:87:1d:55:a5:0f:b3:ee:
                  fd:d2:f4:e0:34:a0:30:b2:2b:43:63:91:5c:a5:8d:
                  be:91:bc:7b:80:fc:f8:a3:33:c1:79:fa:2e:b5:0a:
                  f6:69:ac:81:c4:57:d6:a2:2b:56:55:63:a2:0f:1a:
                  8d:69:17:9b:53:ef:71:3c:b1:20:0c:fe:30:04:5a:
                  d5:3b:a6:96:6d:2a:c1:50:d3
                  )
            ],
        },
    ],
    2048 => [
        {
            g   => Math::BigInt->new(2),
            txt => [
                qw(
                  00:bb:63:1a:4a:13:29:54:34:7f:11:ba:16:89:1c:
                  86:a8:ed:4b:32:eb:d9:93:e9:43:07:ce:a7:0c:dd:
                  aa:cb:86:b6:31:3e:74:a8:cd:fa:c1:eb:75:0b:14:
                  54:99:57:17:dd:92:13:e2:39:43:a6:67:93:d2:5b:
                  c9:e1:b7:e5:28:cc:15:25:cc:5c:8e:2c:28:a7:dc:
                  9b:f5:fb:07:2b:f3:88:0a:0a:ce:54:df:cf:36:89:
                  88:70:f1:05:f0:c7:d4:56:85:0d:97:80:28:3e:1b:
                  15:a2:c8:ee:8a:7b:60:03:20:2f:27:33:11:64:2c:
                  c9:6d:4b:26:e0:39:a8:46:93:bb:3d:f1:6d:26:81:
                  24:d0:5f:f3:23:4a:7d:db:54:4b:ab:c8:d6:2b:82:
                  3e:85:9a:b5:a2:a5:22:28:6b:e7:f2:4d:2f:bd:4b:
                  71:af:d6:ba:86:24:e2:f2:e8:f2:57:32:25:4a:f3:
                  d2:fc:ed:66:23:4e:17:f0:a0:e6:a5:69:f1:df:81:
                  ea:42:ac:7d:f3:38:67:76:e1:93:28:f7:a0:4b:71:
                  69:bd:96:db:cc:9e:87:4a:95:59:98:e5:a5:28:04:
                  32:74:c4:ec:f2:6a:6f:5b:aa:0d:b7:9b:5c:22:da:
                  50:ec:62:d1:41:4b:b1:04:b1:87:15:b3:0c:d4:4d:
                  2b:03
                  )
            ],
        },
    ],
    4096 => [
        {
            g   => Math::BigInt->new(2),
            txt => [
                qw(
                  00:e2:8b:f1:1d:c1:68:a3:42:b2:f4:a8:2a:ce:57:
                  5f:03:2f:83:4b:c9:f4:c3:04:01:95:fc:bf:4e:7b:
                  df:85:f9:fd:d9:51:07:52:9d:5c:69:62:f0:e3:c8:
                  86:02:1e:7e:f7:51:38:dd:04:e9:c6:4e:57:2b:4f:
                  08:ca:ce:a8:e3:33:78:a8:35:bb:22:dd:82:17:f2:
                  a8:68:36:95:97:50:f4:51:6b:23:cc:ae:de:4f:cd:
                  61:97:09:8b:4b:fa:99:2a:8f:fd:4c:c9:e6:30:36:
                  62:d9:16:92:ed:8e:8a:4b:83:0c:1d:3f:29:87:a1:
                  12:8a:2d:f7:fb:8c:af:f1:ca:3d:6f:1c:b9:08:e4:
                  b5:d3:ed:87:94:25:60:9c:15:76:4b:1e:f8:db:73:
                  a8:03:15:12:81:c6:42:5c:28:95:77:40:4d:8f:10:
                  ac:e7:d0:c3:b0:1d:fd:9c:81:45:b1:09:a9:b0:17:
                  a6:79:e6:8c:62:43:47:1d:27:49:c9:1e:63:ed:86:
                  bf:c9:3b:a6:e8:2a:af:cd:b1:7f:e7:14:61:69:cf:
                  57:bc:c7:43:e9:e4:a1:c5:4c:2d:34:27:c0:fd:52:
                  fd:d7:59:8b:35:d0:16:66:bd:df:60:3e:ac:5a:4c:
                  c2:1b:3f:ad:ea:68:30:6c:ef:64:3d:c9:c4:cc:c7:
                  af:3f:33:98:78:b2:88:b5:0b:af:16:95:15:6a:a1:
                  63:46:15:5e:26:d2:3c:f8:2e:5a:fb:40:df:45:40:
                  c4:60:22:d8:da:36:7e:bf:8e:b5:7d:60:0c:d5:ea:
                  f2:ba:b3:ad:c0:63:f4:fc:8e:fc:c0:d5:1e:72:2a:
                  1e:5d:87:77:cd:20:ff:70:1b:6a:14:bf:c7:50:7c:
                  b3:80:90:8c:d5:76:74:f0:19:de:dd:92:0e:26:71:
                  b8:bd:d4:4f:50:74:bf:ba:02:4b:64:f7:c1:77:3e:
                  f2:09:a2:05:84:ab:cf:65:88:54:66:ef:88:62:fa:
                  72:a9:0b:f4:ab:fb:96:37:db:ff:36:34:e6:14:7c:
                  cd:3a:aa:89:52:8d:0f:ba:91:9a:fa:3e:a3:e5:d0:
                  5a:d5:d9:1e:34:57:73:c7:f1:7d:6c:e7:3b:9d:60:
                  b7:99:97:33:1c:3e:fc:37:9c:24:f9:17:c3:60:a8:
                  84:d7:79:1c:fd:23:c8:bc:b5:b5:91:33:d8:74:74:
                  6e:da:86:67:d6:38:ec:03:fb:a6:0b:96:02:2c:0a:
                  7f:2f:2d:4e:c8:e1:3c:4c:dc:5e:16:a6:d9:c3:c0:
                  2f:58:20:71:ee:79:5d:ed:ac:ca:54:8d:46:b3:31:
                  c3:18:d6:01:61:11:77:13:29:aa:28:c0:28:7d:8e:
                  6f:68:4b
                  )
            ],
        },
    ],
);

sub get_param ( $min, $n, $max ) {
    if ( exists( $DHPARAM{$n} ) ) {
        return pick_next($n);
    }

    foreach my $sz ( reverse sort { $a <=> $b } keys %DHPARAM ) {
        if ( $sz <= $max ) {
            return pick_next($sz);
        }
    }

    return undef;
}

sub pick_next($n) {
    my $row = $DHPARAM{$n};

    if ( scalar( $row->@* ) ) {
        return update_param( $row->[0], $n );
    } else {
        my $first = $row->[0];
        push $row->@*, $first;

        return update_param($first);
    }
}

sub update_param ( $param, $size ) {
    if ( !exists( $param->{size} ) ) {
        $param->{size} = $size;
    }
    if ( !exists( $param->{p} ) ) {
        $param->{p} =
          join '', map { chr(hex($_)) }
          split /:/,
          join '', $param->{txt}->@*;
    }

    return $param;
}

1;

