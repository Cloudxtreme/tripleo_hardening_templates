#!/bin/bash
COPYEXT=$(date +%Y%m%d-%H%M%S)
#
echo "Saving current configuration"
service iptables save
#
echo "Efetua copia de seguranca"
if [ -f /etc/sysconfig/iptables ] ; then
cp -a /etc/sysconfig/iptables{,.$COPYEXT}
ls -la /etc/sysconfig/iptables*
fi
#
echo "Saving current configuration"
service iptables save
echo "Stop iptables"
systemctl stop iptables
systemctl status iptables
#
cat <<EOF > /etc/sysconfig/iptables
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:neutron-filter-top - [0:0]
:neutron-openvswi-FORWARD - [0:0]
:neutron-openvswi-INPUT - [0:0]
:neutron-openvswi-OUTPUT - [0:0]
:neutron-openvswi-local - [0:0]
:neutron-openvswi-sg-chain - [0:0]
:neutron-openvswi-sg-fallback - [0:0]
:nova-api-FORWARD - [0:0]
:nova-api-INPUT - [0:0]
:nova-api-OUTPUT - [0:0]
:nova-api-local - [0:0]
:nova-filter-top - [0:0]
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 4098 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 11211 -j ACCEPT
-A INPUT -p udp -m udp --dport 11211 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 4567 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 4444 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 3306 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 6379 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 4369,35672,5672 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 27017 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 3121 -j ACCEPT
-A INPUT -p udp -m udp --dport 5404:5406 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 2224 -j ACCEPT
-A INPUT -p udp -m udp --dport 123 -j ACCEPT
-A INPUT -p udp -m udp --dport 199 -j ACCEPT
-A INPUT -p udp -m udp --dport 161 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 1993 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 873,9200 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 25 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 2049 -j ACCEPT
-A INPUT -p udp -m udp --dport 2049 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 111 -j ACCEPT
-A INPUT -p udp -m udp --dport 111 -j ACCEPT
-A INPUT -p udp -m udp --dport 4952 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 8777,13777 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 8776,13776 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 9191,9292,13292 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 13773,13774,13080,6080,8773,8774,8775 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 13800,13003,13004,8000,8003,8004 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 9696,13696 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 8080,13808,6001,6002 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 5000,13000,13357,35357 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 13782,15304 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 1556 -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -m addrtype --dst-type MULTICAST -j ACCEPT
-A INPUT -j neutron-openvswi-INPUT
-A INPUT -j nova-api-INPUT
-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -j neutron-filter-top
-A FORWARD -j neutron-openvswi-FORWARD
-A FORWARD -j nova-filter-top
-A FORWARD -j nova-api-FORWARD
-A OUTPUT -j neutron-filter-top
-A OUTPUT -j neutron-openvswi-OUTPUT
-A OUTPUT -j nova-filter-top
-A OUTPUT -j nova-api-OUTPUT
-A neutron-filter-top -j neutron-openvswi-local
-A neutron-openvswi-sg-fallback -m comment --comment "Default drop rule for unmatched traffic." -j DROP
-A nova-api-INPUT -d $(grep "^IPADDR" /etc/sysconfig/network-scripts/ifcfg-vlan2901 | sed -e 's/IPADDR=//')/32 -p tcp -m tcp --dport 8775 -j ACCEPT
-A nova-filter-top -j nova-api-local
COMMIT
*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:neutron-openvswi-OUTPUT - [0:0]
:neutron-openvswi-PREROUTING - [0:0]
-A PREROUTING -j neutron-openvswi-PREROUTING
-A OUTPUT -j neutron-openvswi-OUTPUT
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:neutron-openvswi-OUTPUT - [0:0]
:neutron-openvswi-POSTROUTING - [0:0]
:neutron-openvswi-PREROUTING - [0:0]
:neutron-openvswi-float-snat - [0:0]
:neutron-openvswi-snat - [0:0]
:neutron-postrouting-bottom - [0:0]
:nova-api-OUTPUT - [0:0]
:nova-api-POSTROUTING - [0:0]
:nova-api-PREROUTING - [0:0]
:nova-api-float-snat - [0:0]
:nova-api-snat - [0:0]
:nova-postrouting-bottom - [0:0]
-A PREROUTING -j neutron-openvswi-PREROUTING
-A PREROUTING -j nova-api-PREROUTING
-A OUTPUT -j neutron-openvswi-OUTPUT
-A OUTPUT -j nova-api-OUTPUT
-A POSTROUTING -j neutron-openvswi-POSTROUTING
-A POSTROUTING -j neutron-postrouting-bottom
-A POSTROUTING -j nova-api-POSTROUTING
-A POSTROUTING -j nova-postrouting-bottom
-A neutron-openvswi-snat -j neutron-openvswi-float-snat
-A neutron-postrouting-bottom -m comment --comment "Perform source NAT on outgoing traffic." -j neutron-openvswi-snat
-A nova-api-snat -j nova-api-float-snat
-A nova-postrouting-bottom -j nova-api-snat
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:neutron-openvswi-FORWARD - [0:0]
:neutron-openvswi-INPUT - [0:0]
:neutron-openvswi-OUTPUT - [0:0]
:neutron-openvswi-POSTROUTING - [0:0]
:neutron-openvswi-PREROUTING - [0:0]
:neutron-openvswi-mark - [0:0]
:nova-api-POSTROUTING - [0:0]
-A PREROUTING -j neutron-openvswi-PREROUTING
-A INPUT -j neutron-openvswi-INPUT
-A FORWARD -j neutron-openvswi-FORWARD
-A OUTPUT -j neutron-openvswi-OUTPUT
-A POSTROUTING -j neutron-openvswi-POSTROUTING
-A POSTROUTING -j nova-api-POSTROUTING
-A neutron-openvswi-PREROUTING -j neutron-openvswi-mark
COMMIT
EOF
#
echo "Start iptables"
systemctl start iptables
systemctl status iptables
echo "Saving final configuration"
service iptables save
systemctl enable iptables
systemctl mask firewalld
