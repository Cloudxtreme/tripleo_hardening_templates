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
systemctl stop iptables
cat <<EOF > /etc/sysconfig/iptables
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:compute - [0:0]
:neutron-filter-top - [0:0]
:neutron-openvswi-FORWARD - [0:0]
:neutron-openvswi-INPUT - [0:0]
:neutron-openvswi-OUTPUT - [0:0]
:neutron-openvswi-local - [0:0]
:neutron-openvswi-sg-chain - [0:0]
:neutron-openvswi-sg-fallback - [0:0]
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 4098 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 16509 -j ACCEPT
-A INPUT -p udp -m udp --dport 123 -j ACCEPT
-A INPUT -p udp -m udp --dport 67 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 199 -j ACCEPT
-A INPUT -p udp -m udp --dport 161 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 25 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 5672 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 9697 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 5900:5999 -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -m addrtype --dst-type MULTICAST -j ACCEPT
-A INPUT -j LOG
-A INPUT -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix " INPUT packet died: " --log-level 5
-A INPUT -j compute
-A INPUT -j neutron-openvswi-INPUT
-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -j neutron-filter-top
-A FORWARD -j neutron-openvswi-FORWARD
-A OUTPUT -j neutron-filter-top
-A OUTPUT -j neutron-openvswi-OUTPUT
-A compute -p tcp -m tcp --dport 16509 -m comment --comment libvirt -j ACCEPT
-A neutron-filter-top -j neutron-openvswi-local
-A neutron-openvswi-sg-fallback -m comment --comment "Default drop rule for unmatched traffic." -j DROP
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
-A PREROUTING -j neutron-openvswi-PREROUTING
-A OUTPUT -j neutron-openvswi-OUTPUT
-A POSTROUTING -j neutron-openvswi-POSTROUTING
-A POSTROUTING -j neutron-postrouting-bottom
-A neutron-openvswi-snat -j neutron-openvswi-float-snat
-A neutron-postrouting-bottom -m comment --comment "Perform source NAT on outgoing traffic." -j neutron-openvswi-snat
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
-A PREROUTING -j neutron-openvswi-PREROUTING
-A INPUT -j neutron-openvswi-INPUT
-A FORWARD -j neutron-openvswi-FORWARD
-A OUTPUT -j neutron-openvswi-OUTPUT
-A POSTROUTING -j neutron-openvswi-POSTROUTING
-A neutron-openvswi-PREROUTING -j neutron-openvswi-mark
COMMIT
EOF
systemctl start iptables
echo "Saving final configuration"
service iptables save
systemctl enable iptables
systemctl mask firewalld
iptables -nvL
