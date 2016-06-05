#!/bin/bash

if [ $( whoami ) != "root" ] ; then

   echo
   echo "This script must be run as root"
   echo "Change user and run it again"
   echo
   exit 11

fi

LOG="/tmp/hardening-$(date +%Y%m%d.log)"
echo $LOG

HOSTTYPE=$(hostname | cut -d- -f2)
echo $HOSTTYPE

COPYEXT=$(date +%Y%m%d-%H%M%S)
echo $COPYEXT

LOCALIP=$(grep "^IPADDR" /etc/sysconfig/network-scripts/ifcfg-br-ex | sed -e 's/IPADDR=//')
echo $LOCALIP

INTERNALIP=$(grep "^IPADDR" /etc/sysconfig/network-scripts/ifcfg-vlan101 | sed -e 's/IPADDR=//')
echo $INTERNALIP

if [ "$HOSTTYPE" = "control" ] ; then

   if [ ! -f /etc/openstack-dashboard/.dsk ]; then

      echo "I did not find /etc/openstack-dashboard/.dsk file"
      echo 
      echo "Press ENTER if this is the first controller where you are running this script" 
      echo "and I will generate this file for you"
      echo
      echo "or copy /etc/openstack-dashboard/.dsk from first controller manually "
      echo "and put it into /etc/openstack-dashboard directory"
      echo
      read -p "Press ENTER to continue or CTRL+C to cancel" 

   fi

fi


#-----------------------------------------------------------------------

fheader()
{
   echo -e "\n##########" >> $LOG
}

#-----------------------------------------------------------------------

backup()
{
   fheader
   ls /root/backup-*.tar.gz | tee -a $LOG
}

#-----------------------------------------------------------------------

keystone-ssl-certs()
{
   
   fheader
   echo "Checking permissions on certificates private keys" | tee -a $LOG
   
   if [ "$HOSTTYPE" = "control" ]; then

      ls -l /etc/keystone/ssl/* 2>&1 | grep -e '-rw-r--r--'

   else

      echo "Not necessary on a compute node."

   fi
}

#-----------------------------------------------------------------------

cinder()
{

   if [ "$HOSTTYPE" = "control" ]; then

      fheader

      echo "Cinder - checking max request body size" | tee -a $LOG

      openstack-config --get /etc/cinder/cinder.conf DEFAULT osapi_max_request_body_size | grep 114688
      openstack-config --get /etc/cinder/cinder.conf DEFAULT nas_secure_file_permissions | grep auto

   fi

}

#-----------------------------------------------------------------------

horizon()
{
   if [ "$HOSTTYPE" = "control" ]; then

      fheader

      echo "Configuring ALLOWED HOSTS on dashboard" | tee -a $LOG
   
      cp -a /etc/openstack-dashboard/local_settings{,.$COPYEXT}
   
      echo -e "\n- Original configuration: " >> $LOG
      grep "^ALLOWED_HOSTS" /etc/openstack-dashboard/local_settings >> $LOG

      perl -pi -e "s/^ALLOWED_HOSTS.*/ALLOWED_HOSTS = \[\'$(hostname)\'\, \]/" /etc/openstack-dashboard/local_settings

      echo -e "\n- New configuration:" >> $LOG
      grep "^ALLOWED_HOSTS" /etc/openstack-dashboard/local_settings >> $LOG

      if ! grep "HORIZON_IMAGES_ALLOW_UPLOAD = False" /etc/openstack-dashboard/local_settings &> /dev/null ; then

         echo -e "\n- Disabling image upload on dashboard" | tee -a $LOG
         echo "HORIZON_IMAGES_ALLOW_UPLOAD = False" >>  /etc/openstack-dashboard/local_settings

      fi

      if ! grep "SESSION_COOKIE_HTTPONLY = True" /etc/openstack-dashboard/local_settings ; then

         echo "Setting SESSION COOKIES HTTPONLY on dashboard" | tee -a $LOG
         echo "SESSION_COOKIE_HTTPONLY = True" >> /etc/openstack-dashboard/local_settings

      fi

      # Only aplicable on SSL connections
      #echo "Setting SESSION COOKIES SECURE on dashboard" | tee -a $LOG
      #perl -pi -e 's/^#SESSION_COOKIE_SECURE = True/SESSION_COOKIE_SECURE = True/' /etc/openstack-dashboard/local_settings
      
      echo "Setting CSRF COOKIES SECURE on dashboard" | tee -a $LOG
      perl -pi -e 's/^#CSRF_COOKIE_SECURE = True/CSRF_COOKIE_SECURE = True/' /etc/openstack-dashboard/local_settings

      echo -e "\n- Disabling password autocomplete" | tee -a $LOG
      perl -pi -e 's/^# HORIZON_CONFIG\[\"password_autocomplete\"\] = \"off\"/HORIZON_CONFIG\[\"password_autocomplete\"\] = \"off\"\n\nHORIZON_CONFIG\[\"disable_password_reveal\"\] = True/' /etc/openstack-dashboard/local_settings

      echo -e "\n- Changing SECRET_KEY on dashboard" | tee -a $LOG

      echo -e "\n- Original configuration: " >> $LOG
      grep "^SECRET_KEY" /etc/openstack-dashboard/local_settings >> $LOG

      if [ ! -f /etc/openstack-dashboard/.dsk ]; then

         NEWKEY=$(openssl rand -base64 48)
         echo $NEWKEY > /etc/openstack-dashboard/.dsk
         chmod 0440 /etc/openstack-dashboard/.dsk

      else

         NEWKEY=$(cat /etc/openstack-dashboard/.dsk)

      fi

      ACTUAL_KEY=$(grep "^SECRET_KEY" /etc/openstack-dashboard/local_settings | cut -d\' -f2)

      perl -pi -e "s|$ACTUAL_KEY|$NEWKEY|" /etc/openstack-dashboard/local_settings

      echo -e "\n- New configuration: " >> $LOG
      grep "^SECRET_KEY" /etc/openstack-dashboard/local_settings >> $LOG

   fi
}

#-----------------------------------------------------------------------

neutron()
{
   fheader

   openstack-config --get /etc/neutron/neutron.conf quotas quota_driver | grep neutron.db.quota_db.DbQuotaDriver

}

#-----------------------------------------------------------------------

selinux()
{
   fheader


   grep 'SELINUX=enforcing' /etc/selinux/config
   grep 'SELINUXTYPE=targeted' /etc/selinux/config
}

#-----------------------------------------------------------------------

ffirewall()
{
   fheader

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

   if [ "$HOSTTYPE" = "control" ]; then

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
   fheader
   echo "Configuring sshd hardening" | tee -a $LOG

   echo -e "\n- Original configuration" >> $LOG
   grep -v -e "^#" -e "^$" /etc/ssh/sshd_config >> $LOG

   cp -a /etc/ssh/sshd_config{,.$COPYEXT}

   cat << EOF > /etc/ssh/sshd_config
Port 22
ListenAddress ${LOCALIP}
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

   echo -e "\n- Removing root ssh authorized_keys, if any" >> $LOG
   rm -f /root/.ssh/authorized_keys &> /dev/null

   echo -e "\n- Listing /root/.ssh directory" >> $LOG
   ls -la /root/.ssh/ >> $LOG

   if [ -f /home/heat-admin/.ssh/authorized_keys ] ; then
      echo -e "\n- Limiting heat-admin connection from Director only" >> $LOG
      perl -pi -e "s/^ssh-rsa/from=\"10.${LOCALNET}.12.21\" ssh-rsa/" /home/heat-admin/.ssh/authorized_keys
   fi
}

#-----------------------------------------------------------------------

logindefs()
{
   fheader

   CONF="/etc/login.defs"
   echo "Changing $CONF" | tee -a $LOG

   echo -e "\n- Original values" >> $LOG
   grep "^PASS" $CONF >> $LOG

   cp -a $CONF{,.$COPYEXT}

   perl -pi -e 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 0/; s/^PASS_MIN_LEN.*/PASS_MIN_LEN 8/; s/^PASS_WARN_AGE.*/PASS_WARN_AGE 89/' $CONF

   echo -e "\n- New values" >> $LOG
   grep "^PASS" $CONF >> $LOG

   unset CONF
}

#-----------------------------------------------------------------------

sha512-passwords()
{
   fheader

   echo "Changing password algorithm" | tee -a $LOG

   CONF="/etc/sysconfig/authconfig"
   cp -a $CONF{,.$COPYEXT}

   echo -e "\n- Original value in $CONF" >> $LOG
   grep "^PASS" $CONF >> $LOG

   perl -pi -e 's/^PASSWDALGORITHM.*/PASSWDALGORITHM=sha512/' $CONF

   echo -e "\n- New value in $CONF" >> $LOG
   grep "^PASS" $CONF >> $LOG

   unset CONF
}

#-----------------------------------------------------------------------

pam-passwords()
{
   fheader

   echo "Changing pam password rules" | tee -a $LOG

   CONF="/etc/pam.d/system-auth-ac"
   cp -a $CONF{,.$COPYEXT}

   echo -e "\n- Original values:" >> $LOG
   grep "^password" $CONF >> $LOG

   perl -pi -e 's/password    requisite     pam_pwquality.so.*/password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type= difok=3 minlen=8 dcredit=1 lcredit=1 ucredit=1 ocredit=1/' $CONF

   perl -pi -e 's/password    sufficient    pam_unix.so.*/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authok remember=6/' $CONF

   echo -e "\n- New values: " >> $LOG
   grep "^password" $CONF >> $LOG

   unset CONF
}

#-----------------------------------------------------------------------

logrotate-crontab()
{
   fheader

   CONF="/etc/logrotate.conf"
   echo "Changing $CONF" | tee -a $LOG

   cp -a $CONF{,.$COPYEXT}

   echo -e "\n- Original values:" >> $LOG
   grep "create" $CONF >> $LOG

   perl -pi -e "s/^create$/create 0600/" $CONF

   perl -pi -e 's/create 0664 root utmp/create 0640 root utmp/' $CONF

   echo -e "\n- New values:" >> $LOG
   grep "create" $CONF >> $LOG

   chmod 0600 /etc/crontab

   unset CONF
}

#-----------------------------------------------------------------------

cron-users()
{
   fheader

   CONF="/etc/cron.allow"
   echo "Creating $CONF file" | tee -a $LOG

   echo root >> $CONF
   echo ceilometer >> $CONF
   echo keystone >> $CONF

   chmod 0600 $CONF

   echo -e "\n- New configuration:" >> $LOG
   cat $CONF >> $LOG

   echo >> $LOG
   ls -la $CONF >> $LOG

   unset CONF
}

#-----------------------------------------------------------------------

default_umask()
{
   fheader

   echo "Changing default umask" | tee -a $LOG

   cat << EOF > /etc/profile.d/umask.sh
if [ \$UID -gt 199 ] && [ "\`id -gn\`" = "\`id -un\`" ]; then
    umask 022
else
    umask 077
fi
EOF
}

#-----------------------------------------------------------------------

immutable-services-file()
{
   fheader

   CONF="/etc/services"
   echo "Activating immutable bit on /etc/services file" | tee -a $LOG

   echo -e "\n- Original values:" >> $LOG
   lsattr $CONF >> $LOG

   chattr +i $CONF

   echo -e "\n- New values:" >> $LOG
   lsattr $CONF >> $LOG

   unset CONF
}

#-----------------------------------------------------------------------

disabling-coredumps()
{
   fheader

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
   fheader

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
   fheader

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
   fheader

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

   if [ "$HOSTTYPE" = "control" ] ; then

      cat /usr/lib/sysctl.d/openstack-keystone.conf >> /etc/sysctl.conf

   fi

   /sbin/sysctl -p

   echo -e "\n- New value:" >> $LOG
   grep -v -e "^#" -e "^$" /etc/sysctl.conf >> $LOG

}

#-----------------------------------------------------------------------

motd()
{
   fheader

   echo "Creating a new /etc/motd file" | tee -a $LOG

   cat << EOF > /etc/motd
--------------------------------------------------------------------------------
                        ATENCAO: Aviso Importante
 
E proibido o acesso nao autorizado. Esse e um recurso de acesso restrito
devidamente controlado, monitorado e de responsabilidade do Itau Unibanco
 
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
   fheader

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
   fheader

   echo "Removing .netrc files from home directories, if any" | tee -a $LOG

   find /home -type f -name ".netrc" -exec rm -fv {} \; >> $LOG
}

#-----------------------------------------------------------------------

disabling-suid()
{
   fheader

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
   fheader

   echo "Disable permissions for others on /var/log files" | tee -a $LOG

   find /var/log -type f -exec chmod o-rwx {} \;

   chmod 0600 /var/log/dmesg
   chmod 0640 /var/log/wtmp
}

#-----------------------------------------------------------------------

unwanted-services()
{
   fheader

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
   fheader

   echo "Setting new resolv.conf" | tee -a $LOG

   echo -e "\n- Current configuration:" >> $LOG
   cat /etc/resolv.conf >> $LOG

   case $LOCALNET in

     28) cat << EOF > /etc/resolv.conf
search prod.cloud.ihf ctmm1.prod.cloud.ihf
nameserver 10.28.18.15
nameserver 10.29.18.15
nameserver 10.30.18.15

options timeout:1
options attempts:2
EOF
     ;;

     29) cat << EOF > /etc/resolv.conf
search prod.cloud.ihf ctmm2.prod.cloud.ihf
nameserver 10.29.18.15
nameserver 10.28.18.15
nameserver 10.30.18.15

options timeout:1
options attempts:2
EOF
     ;;

     30|31) cat << EOF > /etc/resolv.conf
search prod.cloud.ihf ctsp.prod.cloud.ihf des.cloud.ihf ctsp.des.cloud.ihf
nameserver 10.30.18.15
nameserver 10.28.18.15
nameserver 10.29.18.15

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
   fheader

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
   fheader

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

      fheader

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

      fheader

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
   if [ "$HOSTTYPE" = "control" ]; then

      fheader

      DOMAIN="controller.ctsp.prod.cloud.ihf"
      VHOST_FILE=/etc/httpd/conf.d/10-horizon_vhost.conf
      HEADERS_MOD="LoadModule headers_module modules/mod_headers.so"
      HEADERS_MOD_FILE=/etc/httpd/conf.d/headers.load
      HEADER_CORS="Header add Access-Control-Allow-Origin \"${DOMAIN}\""
      HEADER_HSTS="Header add Strict-Transport-Security \"max-age=15768000\; includeSubdomains"

      echo "Configuring httpd for new headers"
      if [ -f $VHOST_FILE ]; then
          echo -e "\n- Adding Access-Control-Allow-Origin" | tee -a $LOG
          grep -q "${HEADER_CORS}" $VHOST_FILE || sed -i "s/<\/Directory>/&\n\n  $HEADER_CORS/g" $VHOST_FILE
          echo -e "\n- Adding Strict-Transport-Security" | tee -a $LOG
          grep -q "${HEADER_HSTS}" $VHOST_FILE || sed -i "s/<\/Directory>/&\n\n  $HEADER_HSTS/g" $VHOST_FILE
      fi

      if [ ! -f $HEADERS_MOD_FILE ]; then
         echo -e "\n- Creating $HEADERS_MOD_FILE" | tee -a $LOG
         echo "${HEADERS_MOD}" > $HEADERS_MOD_FILE
      fi

   fi

}

#-----------------------------------------------------------------------

frabbitmq()
{
   if [ "$HOSTTYPE" = "control" ]; then

      fheader

      echo "RabbitMQ" | tee -a $LOG

      echo -e "\n- Checking open files limit" | tee -a $LOG

      if [ -f /etc/security/limits.d/rabbitmq-server.conf ] ; then

         echo -e "\n- Original values:" | tee -a $LOG
         cat /etc/security/limits.d/rabbitmq-server.conf >> $LOG

         if ! grep -q 65535 /etc/security/limits.d/rabbitmq-server.conf ; then

            echo -e "\n- Changing open files limit to 65535" | tee -a $LOG
            cat << EOF > /etc/security/limits.d/rabbitmq-server.conf
rabbitmq soft nofile 65535
rabbitmq hard nofile 65535
EOF

            echo -e "\n- New values:" | tee -a $LOG
            cat /etc/security/limits.d/rabbitmq-server.conf >> $LOG

         fi

      fi

      echo -e "\n- Checking rabbitmq compute user" | tee -a $LOG
      if ! rabbitmqctl list_users | grep -q compute &> /dev/null ; then

         echo -e "\n- Adding compute user" | tee -a $LOG
         PASSCP=$(openssl rand -hex 24)
         rabbitmqctl add_user compute $PASSCP
         rabbitmqctl set_permissions compute ".*" ".*" ".*"
         echo -e "\n- Creating pass file" | tee -a $LOG
         echo $PASSCP > /etc/rabbitmq/.cmpt

      else

         if [ ! -f /home/heat-admin/.cmpt ] ; then

            echo "Copying .cmpt file from Director, enter stack user password when asked"
            scp 10.$LOCALNET.12.21:.cmpt ~heat-admin/

            cp /home/heat-admin/.cmpt /etc/rabbitmq/

         else

            cp /home/heat-admin/.cmpt /etc/rabbitmq/

         fi

         if [ ! -f /etc/rabbitmq/.cmpt ]; then

            echo "You need to copy /etc/rabbitmq/.cmpt from the first controller"
            echo "and save it to /etc/rabbitmq directory on this server"

         else

            echo -e "\n- Loading pass from /etc/rabbitmq/.cmpt file" | tee -a $LOG
            PASSCP=$(cat /etc/rabbitmq/.cmpt)

         fi

      fi

      echo -e "\n- Checking rabbitmq ospd-service user" | tee -a $LOG
      if ! rabbitmqctl list_users | grep -q ospd-service &> /dev/null ; then

         echo -e "\n- Adding controller user" | tee -a $LOG
         PASSCTRL=$(openssl rand -hex 24)
         rabbitmqctl add_user ospd-service $PASSCTRL
         rabbitmqctl set_permissions ospd-service ".*" ".*" ".*"
         echo -e "\n- Creating pass file" | tee -a $LOG
         echo $PASSCTRL > /etc/rabbitmq/.ctrl

      else

         if [ -f /home/heat-admin/.ctrl ] ; then

            cp /home/heat-admin/.ctrl /etc/rabbitmq/

         fi

         if [ ! -f /etc/rabbitmq/.ctrl ]; then

            echo "You need to copy /etc/rabbitmq/.ctrl from the first controller"
            echo "and save it to /etc/rabbitmq directory"

         else

            echo -e "\n- Loading pass from /etc/rabbitmq/.ctrl file" | tee -a $LOG
            PASSCTRL=$(cat /etc/rabbitmq/.ctrl)

         fi

      fi

      # Locating files:
      #grep -ri "^rabbit_userid" /etc | grep -vi -e "puppet" -e "2016" -e "bkp" -e "hds" -e "orig"

      for CONF in /etc/cinder/cinder.conf \
                  /etc/ceilometer/ceilometer.conf \
                  /etc/keystone/keystone.conf \
                  /etc/nova/nova.conf \
                  /etc/heat/heat.conf \
                  /etc/neutron/neutron.conf ; do

         echo -e "\n- Backing up $CONF" | tee -a $LOG
         cp -a $CONF{,.$COPYEXT}

         echo -e "\n- Original value:" | tee -a $LOG
         grep "^rabbit_userid" $CONF >> $LOG

         echo -e "\n- Changing rabbit use in $CONF" | tee -a $LOG
         sed -i -e "/^rabbit_userid/s/guest/ospd-service/; /^rabbit_password/s/guest/$PASSCTRL/" $CONF

         echo -e "\n- New value:" | tee -a $LOG
         grep "^rabbit_userid" $CONF >> $LOG

      done

      read -p "Is this the last controller where this script is running? [s/N] " LASTCTRL

      case $LASTCTRL in

         s|S|y|Y) pcs resource restart openstack-keystone-clone
                  ;;
         *)       ;;

      esac

   elif [ "$HOSTTYPE" = "compute" ]; then

      if [ -f /home/heat-admin/.cmpt ] ; then

         cp /home/heat-admin/.cmpt /etc/rabbitmq/

      fi

      if [ ! -f /etc/rabbitmq/.cmpt ]; then

         echo "You need to copy /etc/rabbitmq/.cmpt from the first controller"
         echo "and save it to /etc/rabbitmq directory"

      else

         echo -e "\n- Loading pass from /etc/rabbitmq/.cmpt file" | tee -a $LOG
         PASSCP=$(cat /etc/rabbitmq/.cmpt)

         for CONF in /etc/ceilometer/ceilometer.conf \
                     /etc/nova/nova.conf \
                     /etc/neutron/neutron.conf ; do

            echo -e "\n- Backing up $CONF" | tee -a $LOG
            cp -a $CONF{,.$COPYEXT}

            echo -e "\n- Original value:" >> $LOG
            grep "^rabbit_userid" $CONF >> $LOG

            echo -e "\n- Changing rabbit use in $CONF" | tee -a $LOG
            sed -i -e "/^rabbit_userid/s/guest/compute/; /^rabbit_password/s/guest/$PASSCP/" $CONF

            echo -e "\n- New value:" >> $LOG
            grep "^rabbit_userid" $CONF >> $LOG

         done

         echo -e "\n- Restarting openstack-nova-compute openstack-ceilometer-compute neutron-openvswitch-agent" | tee -a $LOG
         systemctl restart openstack-nova-compute openstack-ceilometer-compute neutron-openvswitch-agent

      fi

   fi
}

#-----------------------------------------------------------------------

# Modules available but not activated
#selinux \
#netrc \
#ffirewall \

#if $1 ; then
#
#   $1
#
#else


      for MODULE in \
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
         home-permissions \
         disabling-suid \
         logfile-permissions \
         unwanted-services \
         resolv-conf \
         locking-users \
         keystone \
         flibvirtd \
         fstab \
         apache \
         frabbitmq ; do

         #read -p "Run $MODULE ? [s/N] " ANSWER

         #case $ANSWER in

         #   s|S) #echo -e "\n##########" >> $LOG
                 $MODULE
         #        read -p "Press ENTER to continue..."

         #esac

      done

#fi

echo -e "\n### End of hardening " >> $LOG
