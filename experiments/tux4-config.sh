#!/bin/bash

ip route del 172.16.10.0/24
ip route del 172.16.11.0/24
ip a flush eth0
#172.16.10.X

ip a add 172.16.10.254/24 dev eth0
ip route add 172.16.10.0/24 dev eth0 src 172.16.10.254

#172.16.11.X
ip a add 172.16.11.253/24 dev eth1
ip route add 172.16.11.0/24 dev eth1 src 172.16.11.253

#default route
ip route add default dev eth1 via 172.16.11.254

ip neigh flush all #flush arp table just in case

sysctl net.ipv4.ip_forward=1
sysctl net.ipv4.icmp_echo_ignore_broadcasts=0
