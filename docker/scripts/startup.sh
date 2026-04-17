#!/bin/bash


echo "srv-web-03" > /etc/hostname
hostname srv-web-03

/usr/local/bin/hide_container.sh

/usr/local/bin/network_restrictions.sh

iptables -L

/usr/local/bin/monitor_iptables.sh &

(sleep 5 && /usr/local/bin/network_restrictions.sh) &

service cron start

/usr/sbin/sshd -D