#!/bin/bash
ip route del 172.16.10.0/24
ip route del 172.16.11.0/24
ip a flush eth0

ip a add 172.16.11.1/24 dev eth0
ip route add 172.16.11.0/24 dev eth0 src 172.16.11.1
ip route add 172.16.10.0/24 dev eth0 via 172.16.11.253
ip neigh flush all #flush arp table just in case