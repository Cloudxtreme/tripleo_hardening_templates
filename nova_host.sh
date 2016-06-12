#!/bin/bash

source /home/stack/stackrc
nova list | awk ' /overcloud/ { print $12" "$4}' | cut -f2 -d= >> /etc/hosts
