#!/bin/bash

# copy overcloudrc to overcloud
source ~/stackrc
nova list
for i in $(nova list | awk ' /overcloud/ { print $12 } ' | cut -f4 -d.); do scp -oStrictHostKeyChecking=no ~/overcloudrc heat-admin@172.16.0.$i:~; done
for i in $(nova list | awk ' /overcloud/ { print $12 } ' | cut -f4 -d.); do ssh -l heat-admin 172.16.0.$i uptime; done

# create an image
source ~/overcloudrc
curl -o /tmp/cirros.qcow2     http://download.cirros-cloud.net/0.3.4/cirros-0.3.4-x86_64-disk.img
glance image-create --name cirros --disk-format qcow2     --container-format bare --is-public true --file /tmp/cirros.qcow2 --progress
glance image-create --name rhel7 --disk-format qcow2 --container-format bare --is-public true --file ~/rhel7-guest-official.qcow2  --progress

# add security groups
nova secgroup-add-rule default icmp -1 -1 0.0.0.0/0
nova secgroup-add-rule default tcp 22 22 0.0.0.0/0

# network
neutron net-create public --router:external
neutron subnet-create public 192.168.122.0/24 \
    --name public_subnet --enable-dhcp=False --allocation-pool \
    start=192.168.122.130,end=192.168.122.199 --dns-nameserver 192.168.122.1
neutron net-create internal
neutron subnet-create internal 192.168.0.0/24 --name internal_subnet
neutron router-create internal_router
neutron router-gateway-set internal_router public
neutron router-interface-add internal_router internal_subnet

# create a keypair
nova keypair-add demokp > ~/demokp.pem
chmod 600 ~/demokp.pem

# launch an instance
internal_net=$(neutron net-list | awk ' /internal/ {print $2;}')
nova boot --flavor m1.tiny --nic net-id=$internal_net --image cirros cirros-01
nova boot --flavor m1.small --image rhel7 --key-name demokp --nic net-id=$internal_net rhel7-01
sleep 60
neutron floatingip-create public
nova add-floating-ip cirros-01 192.168.122.131
sleep 60
ping -c 4 192.168.122.131
ssh -l cirros 192.168.122.131 uptime

# test cinder and glance
neutron floatingip-create public
nova add-floating-ip rhel7-01 192.168.122.132
sleep 30
ssh -l cloud-user -i ~/demokp.pem 192.168.122.132 uptime

# attach a cinder volume
cinder create --display-name rhel7-test 1
volid=$(cinder list | awk ' /rhel7-test/ { print $2 } ')
nova volume-attach rhel7-01 $volid auto
cinder list
ssh -l cloud-user -i ~/demokp.pem 192.168.122.132 grep vdb /proc/partitions
