#!/bin/bash

source /home/stack/stackrc
nova list | awk ' /overcloud/ { print $12" "$4}' | cut -f2 -d= >> /etc/hosts
awk ' /overcloud/ { print $2 } '  /etc/hosts > /etc/pdsh/machines
for i in $(nova list | awk ' /overcloud/ { print $4 } ' | cut -f4 -d.); do scp -oStrictHostKeyChecking=no ~/overcloudrc heat-admin@$i:~; done
pdsh -a -l heat-admin uptime
