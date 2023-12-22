#!/bin/bash
ip route del default
ip route del 172.16.10.0/24
ip a flush eth0
ip a add 172.16.10.1/24 dev eth0
ip route add 172.16.10.0/24 dev eth0 src 172.16.10.1
ip route add default dev eth0 via 172.16.10.254
ip neigh flush all #flush arp table just in case

echo 'nameserver 193.136.28.10' > /etc/resolv.conf
