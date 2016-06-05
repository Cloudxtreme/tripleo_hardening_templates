#!/bin/bash
COPYEXT=$(date +%Y%m%d-%H%M%S)
#
echo "Salva configuracao atual"
service iptables save
#
echo "Efetua copia de seguranca"
if [ -f /etc/sysconfig/iptables ] ; then
cp -a /etc/sysconfig/iptables{,.$COPYEXT}
ls -la /etc/sysconfig/iptables*
fi
#
echo "Adiciona regras para o iptables no Director"
iptables -A INPUT -p udp -m udp --dport 67 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 161 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 13776 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 3306 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 6200,6201,6202,873 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 3260,8776 -j ACCEPT
iptables -A INPUT -m state --state NEW -m tcp -p tcp --dport 6081 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 27017 -j ACCEPT
iptables -N LOGGING
iptables -A INPUT -j LOGGING
iptables -A OUTPUT -j LOGGING
iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
iptables -P INPUT DROP
iptables -P FORWARD DROP
echo "Salva Configuracao atual"
service iptables save
echo "Habilita Iptables na inicializacao e desativa Firewalld"
systemctl enable iptables
systemctl mask firewalld
iptables -nvL
