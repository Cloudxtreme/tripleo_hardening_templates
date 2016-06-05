#!/bin/bash

LOG="/tmp/hardening-$(date +%Y%m%d.log)"

HOSTTYPE=$(hostname | cut -d- -f2)
if [ "$HOSTTYPE" = "controller" -o "$HOSTTYPE" = "compute" ] ; then

   echo "This script is intended to run on Director only"
   exit 12

fi

COPYEXT=$(date +%Y%m%d-%H%M%S)

PROVIP=$(grep "^IPADDR" /etc/sysconfig/network-scripts/ifcfg-br-ctlplane | sed -e 's/IPADDR=//')
LOCALNET=$( echo $PROVIP | cut -d\. -f2 )

PUBLICIP=$(grep "^IPADDR" /etc/sysconfig/network-scripts/ifcfg-eth1 | sed -e 's/IPADDR=//')

#-----------------------------------------------------------------------

backup()
{
   BACKUPFILE="/root/backup-${COPYEXT}.tar.gz"
   echo "Backing up all configurations to ${BACKUPFILE}" | tee -a $LOG

   tar cpzf ${BACKUPFILE} /etc

   echo -e "\n/etc backed up to ${BACKUPFILE}\n" | tee -a $LOG
}

#-----------------------------------------------------------------------

keystone-ssl-certs()
{
   echo "Fixing permissions on certificates private keys" | tee -a $LOG

   echo -e "\n- Original permissions on /etc/keystone/ssl pem files" >> $LOG
   ls -l /etc/keystone/ssl/* 2>&1 >> $LOG

   echo -e "\nNot changing permissions on public cert pem files" | tee -a $LOG
   echo "Changing permissions on /etc/keystone/ssl/private pem files" | tee -a $LOG

   chmod 640 /etc/keystone/ssl/private/*pem

   echo -e "\nFinal permissions on /etc/keystone/ssl pem files" >> $LOG
   ls -l /etc/keystone/ssl/* 2>&1 >> $LOG
}

#-----------------------------------------------------------------------

cinder()
{
   echo "Cinder - configuring max request body size" | tee -a $LOG

   if [ -f /etc/cinder/cinder.conf ]; then
      cp -a /etc/cinder/cinder.conf{,.$COPYEXT}

      echo -e "\n- Original configuration: " >> $LOG
      grep "osapi_max_request_body_size" /etc/cinder/cinder.conf >> $LOG

      openstack-config --set /etc/cinder/cinder.conf DEFAULT osapi_max_request_body_size 114688
      openstack-config --set /etc/cinder/cinder.conf DEFAULT nas_secure_file_permissions auto

      echo -e "\n- New configuration:" >> $LOG
      grep "osapi_max_request_body_size" /etc/cinder/cinder.conf >> $LOG

   else

      echo "There is no cinder configuration on this host" >> $LOG

   fi
}

#-----------------------------------------------------------------------

horizon()
{
   echo "Configuring ALLOWED HOSTS on dashboard" | tee -a $LOG

   cp -a /etc/openstack-dashboard/local_settings{,.$COPYEXT}

   echo -e "\n- Original configuration: " >> $LOG
   grep "^ALLOWED_HOSTS" /etc/openstack-dashboard/local_settings >> $LOG

   perl -pi -e "s/^ALLOWED_HOSTS.*/ALLOWED_HOSTS = \[\'$(hostname)\'\, \]/" /etc/openstack-dashboard/local_settings

   echo -e "\n- New configuration:" >> $LOG
   grep "^ALLOWED_HOSTS" /etc/openstack-dashboard/local_settings >> $LOG

   echo -e "\n- Disabling image upload on dashboard" | tee -a $LOG
   echo "HORIZON_IMAGES_ALLOW_UPLOAD = False" >>  /etc/openstack-dashboard/local_settings

   echo -e "\n- Setting SESSION COOKIES HTTPONLY on dashboard" | tee -a $LOG
   echo "SESSION_COOKIE_HTTPONLY = True" >> /etc/openstack-dashboard/local_settings
   
   # Only aplicable on SSL connections
   #echo "Setting SESSION COOKIES SECURE on dashboard" | tee -a $LOG
   #perl -pi -e 's/^#SESSION_COOKIE_SECURE = True/SESSION_COOKIE_SECURE = True/' /etc/openstack-dashboard/local_settings
   
   echo -e "\n- Setting CSRF COOKIES SECURE on dashboard" | tee -a $LOG
   perl -pi -e 's/^#CSRF_COOKIE_SECURE = True/CSRF_COOKIE_SECURE = True/' /etc/openstack-dashboard/local_settings

   echo -e "\n- Disabling password autocomplete" | tee -a $LOG
   perl -pi -e 's/^# HORIZON_CONFIG\[\"password_autocomplete\"\] = \"off\"/HORIZON_CONFIG\[\"password_autocomplete\"\] = \"off\"\n\nHORIZON_CONFIG\[\"disable_password_reveal\"\] = True/' /etc/openstack-dashboard/local_settings

   echo -e "\n- Changing SECRET_KEY on dashboard" | tee -a $LOG

   echo -e "\n- Original configuration: " >> $LOG
   grep "^SECRET_KEY" /etc/openstack-dashboard/local_settings >> $LOG

   NEWKEY=$(openssl rand -base64 48)
   ACTUAL_KEY=$(grep "^SECRET_KEY" /etc/openstack-dashboard/local_settings | cut -d\' -f2)
   perl -pi -e "s|$ACTUAL_KEY|$NEWKEY|" /etc/openstack-dashboard/local_settings

   echo -e "\n- New configuration: " >> $LOG
   grep "^SECRET_KEY" /etc/openstack-dashboard/local_settings >> $LOG
}

#-----------------------------------------------------------------------

neutron()
{
   echo "Settings on neutron.conf " | tee -a $LOG

   echo "- Original configuration:" >> $LOG
   grep "quota_driver" /etc/neutron/neutron.conf >> $LOG

   cp -a /etc/neutron/neutron.conf{,.$COPYEXT}

   openstack-config --set /etc/neutron/neutron.conf quotas quota_driver neutron.db.quota_db.DbQuotaDriver

   echo "- New configuration:" >> $LOG
   grep "quota_driver" /etc/neutron/neutron.conf >> $LOG
}

#-----------------------------------------------------------------------

selinux()
{
   echo "Setting SELinux Enforcing mode" | tee -a $LOG

   cp -a /etc/selinux/config{,.$COPYEXT}

   perl -pi -e 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

   echo "Setting SELinux targeted type"

   perl -pi -e 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config
}

#-----------------------------------------------------------------------

ffirewall()
{

   echo "Configuring firewall rules" | tee -a $LOG

   if [ -f /etc/sysconfig/iptables ] ; then

      cp -a /etc/sysconfig/iptables{,.$COPYEXT}

   fi

   echo "Permitting ssh connections"
   iptables -I INPUT -p tcp --dport 4098 -j ACCEPT 
   iptables -I INPUT -p tcp --dport 22 -j ACCEPT 
   #iptables -A INPUT -p udp --dport 161 -m comment --comment "snmp" -j ACCEPT 

   echo "Saving current configuration"
   service iptables save

   if [ "$HOSTTYPE" = "controller" ]; then

      # Pacemaker ports
      iptables -N PaceMaker
      iptables -A PaceMaker -p tcp --dport 2225 -j ACCEPT
      iptables -A PaceMaker -p tcp --dport 3121 -j ACCEPT
      iptables -A PaceMaker -s 10.31.28.0/22 -p udp --dport 5404 -j ACCEPT
      iptables -A PaceMaker -s 10.31.28.0/22 -p udp --dport 5405 -j ACCEPT
      iptables -A PaceMaker -p tcp --dport 21064 -j ACCEPT
      iptables -I INPUT 3 -j Pacemaker

      # OpenStack
      iptables -N OpenStack
      iptables -I INPUT 3 -j OpenStack

   elif [ "$HOSTTYPE" = "compute" ]; then

      echo "" >> /etc/sysctl.conf
      echo "net.bridge.bridge-nf-call-arptables = 0" >> /etc/sysctl.conf
      echo "net.bridge.bridge-nf-call-ip6tables = 0" >> /etc/sysctl.conf
      echo "net.bridge.bridge-nf-call-iptables = 0" >> /etc/sysctl.conf

      /sbin/sysctl -p

      iptables -N compute
      iptables -A compute -p tcp --dport 16509 -m comment --comment "libvirt" -j ACCEPT 
      iptables -I INPUT -j compute

   fi

   echo "Changing default policy to DROP on INPUT and OUTPUT chains"
   #iptables -P INPUT DROP
   #iptables -P FORWARD DROP

   echo "Saving final configuration" >> $LOG
   service iptables save

   systemctl restart iptables
   systemctl enable iptables
   systemctl mask firewalld

   #at now +1min < systemctl restart sshd


}

#-----------------------------------------------------------------------

fsshd()
{
   echo "Configuring sshd hardening" | tee -a $LOG

   echo -e "\n- Original configuration" >> $LOG
   grep -v -e "^#" -e "^$" /etc/ssh/sshd_config >> $LOG

   cp -a /etc/ssh/sshd_config{,.$COPYEXT}

   cat << EOF > /etc/ssh/sshd_config
Port 22
ListenAddress ${PROVIP}
ListenAddress ${PUBLICIP}
PermitEmptyPasswords no
PermitRootLogin no
IgnoreRhosts yes
RhostsRSAAuthentication no
Protocol 2
StrictModes yes
PermitUserEnvironment no
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
ServerKeyBits 2048
SyslogFacility AUTHPRIV
LoginGraceTime 60
MaxAuthTries 3
AuthorizedKeysFile      .ssh/authorized_keys
PasswordAuthentication yes
ChallengeResponseAuthentication no
GSSAPIAuthentication no
LogLevel INFO
TCPKeepAlive yes
KerberosAuthentication no
GSSAPICleanupCredentials yes
PrintLastLog yes
UsePAM yes
AllowTcpForwarding no
X11Forwarding no
UsePrivilegeSeparation sandbox          # Default for new installations.
UseDNS no
MaxStartups 10:30:100
PermitTunnel yes
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS
Subsystem       sftp    /usr/libexec/openssh/sftp-server
EOF

   chmod 0640 /etc/ssh/sshd_config

   echo -e "\n- New configuration" >> $LOG
   grep -v -e "^#" -e "^$" /etc/ssh/sshd_config >> $LOG

   echo -e "\n- Restarting sshd service"
   systemctl restart sshd.service

   echo -e "\n- Removing root ssh authorized_keys if any" >> $LOG
   echo -e "\n- Files remaining in /root/.ssh" >> $LOG
   rm -f /root/.ssh/authorized_keys
   ls -la /root/.ssh/ >> $LOG

   echo -e "\n- Removing stack ssh authorized_keys if any" >> $LOG
   echo -e "\n- Files remaining in /home/stack/.ssh" >> $LOG
   rm -f /home/stack/.ssh/authorized_keys
   ls -la /home/stack/.ssh/ >> $LOG
}

#-----------------------------------------------------------------------

logindefs()
{
   echo "Changing /etc/login.defs" | tee -a $LOG

   echo -e "\n- Original values" >> $LOG
   grep "^PASS" /etc/login.defs >> $LOG

   cp -a /etc/login.defs{,.$COPYEXT}

   perl -pi -e 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 0/; s/^PASS_MIN_LEN.*/PASS_MIN_LEN 8/; s/^PASS_WARN_AGE.*/PASS_WARN_AGE 89/' /etc/login.defs

   echo -e "\n- New values" >> $LOG
   grep "^PASS" /etc/login.defs >> $LOG
}

#-----------------------------------------------------------------------

sha512-passwords()
{
   echo "Changing password algorithm" | tee -a $LOG

   cp -a /etc/sysconfig/authconfig{,.$COPYEXT}

   echo -e "\n- Original value" >> $LOG
   grep "^PASS" /etc/sysconfig/authconfig >> $LOG

   perl -pi -e 's/^PASSWDALGORITHM.*/PASSWDALGORITHM=sha512/' /etc/sysconfig/authconfig

   echo -e "\n- New value" >> $LOG
   grep "^PASS" /etc/sysconfig/authconfig >> $LOG
}

#-----------------------------------------------------------------------

pam-passwords()
{
   echo "Changing pam password rules" | tee -a $LOG

   cp -a /etc/pam.d/system-auth-ac{,.$COPYEXT}

   echo -e "\n- Original values:" >> $LOG
   grep "^password" /etc/pam.d/system-auth-ac >> $LOG

   perl -pi -e 's/password    requisite     pam_pwquality.so.*/password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type= difok=3 minlen=8 dcredit=1 lcredit=1 ucredit=1 ocredit=1/' /etc/pam.d/system-auth-ac

   perl -pi -e 's/password    sufficient    pam_unix.so.*/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authok remember=6/' /etc/pam.d/system-auth-ac

   echo -e "\n- New values: " >> $LOG
   grep "^password" /etc/pam.d/system-auth-ac >> $LOG
}

#-----------------------------------------------------------------------

logrotate-crontab()
{
   echo "Changing /etc/logrotate.conf" | tee -a $LOG

   cp -a /etc/logrotate.conf{,.$COPYEXT}

   echo -e "\n- Original values:" >> $LOG
   grep "create" /etc/logrotate.conf >> $LOG

   perl -pi -e "s/^create$/create 0600/" /etc/logrotate.conf

   perl -pi -e 's/create 0664 root utmp/create 0640 root utmp/' /etc/logrotate.conf

   echo -e "\n- New values:" >> $LOG
   grep "create" /etc/logrotate.conf >> $LOG

   chmod 0600 /etc/crontab

}

#-----------------------------------------------------------------------

cron-users()
{
   echo "Creating /etc/cron.allow file" | tee -a $LOG

   echo root >> /etc/cron.allow
   echo ceilometer >> /etc/cron.allow
   echo keystone >> /etc/cron.allow

   chmod 0600 /etc/cron.allow

   echo -e "\n- New configuration:" >> $LOG
   cat /etc/cron.allow >> $LOG

   echo >> $LOG
   ls -la /etc/cron.allow >> $LOG
}

#-----------------------------------------------------------------------

default_umask()
{
   echo "Creating /etc/profile.d/umask.sh" | tee -a $LOG

   cat << EOF > /etc/profile.d/umask.sh
if [ $UID -gt 199 ] && [ "`id -gn`" = "`id -un`" ]; then
    umask 022
else
    umask 077
fi
EOF

   echo -e "\n- New values:" >> $LOG
   cat /etc/profile.d/umask.sh >> $LOG
}

#-----------------------------------------------------------------------

immutable-services-file()
{
   echo "Activating immutable bit on /etc/services file" | tee -a $LOG

   echo -e "\n- Original values:" >> $LOG
   lsattr /etc/services >> $LOG

   chattr +i /etc/services

   echo -e "\n- New values:" >> $LOG
   lsattr /etc/services >> $LOG
}

#-----------------------------------------------------------------------

disabling-coredumps()
{
   echo "Disabling core files" | tee -a $LOG

   echo -e "\n- Original values on /etc/security/limits.conf" >> $LOG
   grep -v -e "^#" -e "^$" /etc/security/limits.conf >> $LOG

   sed -i.$COPYEXT -e '/^# End/i*\t\thard\tcore\t\t0\n' /etc/security/limits.conf

   echo -e "- New values" >> $LOG
   grep -v -e "^#" -e "^$" /etc/security/limits.conf >> $LOG
}

#-----------------------------------------------------------------------

su-pam-wheel()
{
echo "Changing pam.d su configuration" | tee -a $LOG

echo -e "\n- Original values" >> $LOG
grep "^auth" /etc/pam.d/su >> $LOG

perl -pi -e 's/#auth		required	pam_wheel.so use_uid/auth		required	pam_wheel.so use_uid/' /etc/pam.d/su

echo -e "\n- New values" >> $LOG
grep "^auth" /etc/pam.d/su >> $LOG
}

#-----------------------------------------------------------------------

securetty()
{
echo "Changing /etc/securetty" | tee -a $LOG

cp -a /etc/securetty{,.$COPYEXT}

echo -e "\n- Orginal values" >> $LOG
cat /etc/securetty >> $LOG

cat << EOF > /etc/securetty
console
tty1
tty2
tty3
tty4
tty5
tty6
tty7
tty8
tty9
tty10
tty11
ttyS0
ttysclp0
EOF

echo -e "\n- New values: " >> $LOG
cat /etc/securetty >> $LOG
}

#-----------------------------------------------------------------------

fsysctl()
{
   echo "Changing sysctl conf" | tee -a $LOG

   cp -a /etc/sysctl.conf{,.$COPYEXT}

   echo -e "\n- Original values:" >> $LOG
   grep -v -e "^#" -e "^$" /etc/sysctl.conf >> $LOG

   cat << EOF >> /etc/sysctl.conf

fs.suid_dumpable = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF

   if [ "$HOSTTYPE" = "controller" ] ; then

      cat /usr/lib/sysctl.d/openstack-keystone.conf >> /etc/sysctl.conf

   fi

   /sbin/sysctl -p

   echo -e "\n- New value:" >> $LOG
   grep -v -e "^#" -e "^$" /etc/sysctl.conf >> $LOG

}

#-----------------------------------------------------------------------

motd()
{
   echo "Creating a new /etc/motd file" | tee -a $LOG

   cat << EOF > /etc/motd
--------------------------------------------------------------------------------
                        ATENCAO: Aviso Importante
 
Se voce nao possui autorizacao para acessar este recurso, desconecte
imediatamente ou podera sofrer sancoes legais e/ou acao disciplinar.
 
--------------------------------------------------------------------------------
EOF

   echo "Copying /etc/motd to /etc/issue.net file" | tee -a $LOG
   cp /etc/motd /etc/issue.net

}

#-----------------------------------------------------------------------

home-permissions()
{
   # This is the default behaviour on RHEL.
   echo "Setting default permissions for HOME directories" | tee -a $LOG

   echo -e "\n- Original values" >> $LOG
   grep -A4 "CREATE_HOME" /etc/login.defs | grep -v -e "^#" -e "^$" >> $LOG
   ls -l /home >> $LOG

   perl -pi -e 's/UMASK.*/UMASK            077/' /etc/login.defs
   chmod 0700 /home/*

   echo -e "\n- New values" >> $LOG
   grep -A4 "CREATE_HOME" /etc/login.defs | grep -v -e "^#" -e "^$" >> $LOG
   ls -l /home >> $LOG
}

#-----------------------------------------------------------------------

netrc()
{
   echo "Removing .netrc files from home directories if any" | tee -a $LOG

   find /home -type f -name ".netrc" -exec rm -fv {} \; >> $LOG
}

#-----------------------------------------------------------------------

disabling-suid()
{
echo "Disabling suid on following files" | tee -a $LOG

echo -e "\n- Original values:" >> $LOG
ls -l /bin/mount &>> $LOG
ls -l /bin/umount &>> $LOG
ls -l /sbin/netreport &>> $LOG
ls -l /usr/bin/at &>> $LOG
ls -l /usr/bin/chage &>> $LOG
ls -l /usr/bin/chfn &>> $LOG
ls -l /usr/bin/chsh &>> $LOG
ls -l /usr/bin/gpasswd &>> $LOG
ls -l /usr/bin/locate &>> $LOG
ls -l /usr/bin/newgrp &>> $LOG
ls -l /usr/bin/ssh-agent &>> $LOG
ls -l /usr/bin/wall &>> $LOG
ls -l /usr/bin/write &>> $LOG
ls -l /usr/libexec/openssh/ssh-keysign &>> $LOG
ls -l /usr/libexec/utempter/utempter &>> $LOG
ls -l /usr/sbin/sendmail.postfix &>> $LOG
ls -l /usr/sbin/usernetctl &>> $LOG

for FILE in /bin/mount \
   /bin/umount \
   /sbin/netreport \
   /usr/bin/at \
   /usr/bin/chage \
   /usr/bin/chfn \
   /usr/bin/chsh \
   /usr/bin/gpasswd \
   /usr/bin/locate \
   /usr/bin/newgrp \
   /usr/bin/ssh-agent \
   /usr/bin/wall \
   /usr/bin/write \
   /usr/libexec/openssh/ssh-keysign \
   /usr/libexec/utempter/utempter \
   /usr/sbin/sendmail.postfix \
   /usr/sbin/usernetctl; do

   chmod -s $FILE &>> $LOG

done

echo -e "\n- New values:" >> $LOG
ls -l /bin/mount &>> $LOG
ls -l /bin/umount &>> $LOG
ls -l /sbin/netreport &>> $LOG
ls -l /usr/bin/at &>> $LOG
ls -l /usr/bin/chage &>> $LOG
ls -l /usr/bin/chfn &>> $LOG
ls -l /usr/bin/chsh &>> $LOG
ls -l /usr/bin/gpasswd &>> $LOG
ls -l /usr/bin/locate &>> $LOG
ls -l /usr/bin/newgrp &>> $LOG
ls -l /usr/bin/ssh-agent &>> $LOG
ls -l /usr/bin/wall &>> $LOG
ls -l /usr/bin/write &>> $LOG
ls -l /usr/libexec/openssh/ssh-keysign &>> $LOG
ls -l /usr/libexec/utempter/utempter &>> $LOG
ls -l /usr/sbin/sendmail.postfix &>> $LOG
ls -l /usr/sbin/usernetctl &>> $LOG
}

#-----------------------------------------------------------------------

logfile-permissions()
{
   echo "Disable permissions for others on /var/log files" | tee -a $LOG

   find /var/log -type f -exec chmod o-rwx {} \;

   chmod 0600 /var/log/dmesg
   chmod 0640 /var/log/wtmp
}

#-----------------------------------------------------------------------

unwanted-services()
{
echo "Disabling unwanted services" | tee -a $LOG

echo -e "\n- Original configuration" >> $LOG 

# Não localizei no RHEL7
#   haldaemon \
#   hidd \
#   hplip \
#   kudzu \
#   microcode_ctl \ <- renomeado para microcode

for SERVICE in \
   abrtd \
   acpid \
   anacron \
   apmd \
   atd \
   avahi-daemon \
   bluetooth \
   cgconfig \
   cgred \
   cups \
   systemd-firstboot \
   gpm \
   isdn \
   kdump \
   messagebus \
   microcode \
   netconsole \
   psacct \
   pcscd \
   rdisc \
   systemd-readahead-collect \
   systemd-readahead-replay \
   systemd-readahead-done \
   rhnsd \
   saslauthd \
   smartd ; do

   echo "- Disabling $SERVICE" | tee -a $LOG
   systemctl is-enabled ${SERVICE}.service &>> $LOG && systemctl disable $SERVICE &>> $LOG

done
}

#-----------------------------------------------------------------------

resolv-conf()
{
   echo "Setting new resolv.conf" | tee -a $LOG

   echo -e "\n- Current configuration:" >> $LOG
   cat /etc/resolv.conf >> $LOG

   case $LOCALNET in

     16) cat << EOF >> /etc/resolv.conf
search redhat.local
nameserver 192.168.122.1

options timeout:1
options attempts:2
EOF
     ;;

   esac

   echo -e "\n- New configuration:" >> $LOG
   cat /etc/resolv.conf >> $LOG
}

#-----------------------------------------------------------------------

locking-users()
{
echo "Locking password for specific users" | tee -a $LOG

echo -e "\n- Original configuration" >> $LOG 

for BLOCKUSER in \
   bin \
   daemon \
   adm \
   lp \
   sync \
   shutdown \
   halt \
   mail \
   uucp \
   operator \
   games \
   gopher \
   ftp \
   nobody \
   vcsa \
   saslauth \
   postfix \
   sshd ; do
   
   echo "- Locking password for $BLOCKUSER" &>> $LOG
   passwd -l $BLOCKUSER &>> $LOG
   
done
}

#-----------------------------------------------------------------------

keystone()
{
   echo "Changing settings on keystone.conf" | tee -a $LOG

   echo -e "\n- Original value" >> $LOG
   grep "max_request_body_size" /etc/keystone/keystone.conf >> $LOG

   cp -a /etc/keystone/keystone.conf{,.$COPYEXT}

   openstack-config --set /etc/keystone/keystone.conf oslo_middleware max_request_body_size 114688

   openstack-config --set /etc/keystone/keystone.conf token hash_algorithm sha512

   echo -e "\n- New value" >> $LOG
   grep "max_request_body_size" /etc/keystone/keystone.conf >> $LOG
}

#-----------------------------------------------------------------------

flibvirtd()
{

   if [ "$HOSTTYPE" = "compute" ]; then

      echo "Change bind addres for libvirtd" | tee -a $LOG

      echo -e "\n- Original value:" >> $LOG
      grep "listen_addr" /etc/libvirt/libvirtd.conf >> $LOG

      perl -pi -e "s/#listen_addr.*/listen_addr = $INTERNALIP/" /etc/libvirt/libvirtd.conf

      echo -e "\n- New value:" >> $LOG
      grep "listen_addr" /etc/libvirt/libvirtd.conf >> $LOG

   fi

}

#-----------------------------------------------------------------------

fstab()
{

   if [ "$HOSTTYPE" = "compute" ]; then

      echo "Changing mount options on /etc/fstab for ephemeral disk" | tee -a $LOG

      echo -e "\n- Original value:" >> $LOG
      grep "/dev/mapper/instancesvg-ephemeral" /etc/fstab >> $LOG

      perl -pi -e 's|/dev/mapper/instancesvg-ephemeral.*|/dev/mapper/instancesvg-ephemeral /var/lib/nova/instances xfs defaults,nosuid,noexec,nodev 0 0|' /etc/fstab

      echo -e "\n- New value:" >> $LOG
      grep "/dev/mapper/instancesvg-ephemeral" /etc/fstab >> $LOG

      mount -o remount /var/lib/nova/instances

   fi

}

#-----------------------------------------------------------------------

apache()
{

   echo "Setting horizon apache headers on /etc/httpd/conf.d/10-horizon_vhost.conf file" | tee -a $LOG

   cp -a /etc/httpd/conf.d/10-horizon_vhost.conf{,.$COPYEXT}

   DOMAIN=$(hostname)
   VHOST_FILE=/etc/httpd/conf.d/10-horizon_vhost.conf
   HEADERS_MOD="LoadModule headers_module modules/mod_headers.so"
   HEADERS_MOD_FILE=/etc/httpd/conf.d/headers.load
   HEADER_CORS="Header add Access-Control-Allow-Origin \"${DOMAIN}\""
   HEADER_HSTS="Header add Strict-Transport-Security \"max-age=15768000\; includeSubdomains"

   if [ -f $VHOST_FILE ]; then
       grep -q "${HEADER_CORS}" $VHOST_FILE || sed -i "s/<\/Directory>/&\n\n  $HEADER_CORS/g" $VHOST_FILE
       grep -q "${HEADER_HSTS}" $VHOST_FILE || sed -i "s/<\/Directory>/&\n\n  $HEADER_HSTS/g" $VHOST_FILE
   fi

   if [ ! -f $HEADERS_MOD_FILE ]; then
       echo "${HEADERS_MOD}" > $HEADERS_MOD_FILE
   fi
}

#-----------------------------------------------------------------------

# Modules available but not activated

      for MODULE in \
         #selinux
         #home-permissions
         #netrc
         #ffirewall
         backup \
         keystone-ssl-certs \
         cinder \
         horizon \
         neutron \
         fsshd \
         logindefs \
         sha512-passwords \
         pam-passwords \
         logrotate-crontab \
         cron-users \
         default_umask \
         immutable-services-file \
         disabling-coredumps \
         su-pam-wheel \
         securetty \
         fsysctl \
         motd \
         disabling-suid \
         logfile-permissions \
         unwanted-services \
         resolv-conf \
         locking-users \
         keystone \
         flibvirtd \
         apache \
         fstab ; do

                 echo -e "\n##########" >> $LOG
                 $MODULE
		 sleep 10
      done

echo -e "\n### End of hardening " >> $LOG

