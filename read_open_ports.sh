#!/bin/bash

echo "usage: $0 <NMAP XML> <NMAP switches>";
echo "example: $0 ./host_port_scan.xml '-Pn -T3 -oX port_details.xml -sC'";

echo "nmap switches: $2"