#!/bin/bash

iptables-save > /tmp/initial_rules

while true; do
    iptables-save > /tmp/current_rules
    
    if ! diff -q /tmp/initial_rules /tmp/current_rules >/dev/null 2>&1; then
        /usr/local/bin/network_restrictions.sh
        
        logger -p auth.warning "Reseting network restrictions."
    fi
    
    if wget -q --spider https://google.com >/dev/null 2>&1 || curl -s https://google.com >/dev/null 2>&1; then

        /usr/local/bin/block_network.sh
        
        logger -p auth.alert "Reseting network restrictions."
    fi
    
    sleep 10
done