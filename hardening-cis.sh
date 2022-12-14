#!/bin/bash

#Ensure that SSH has been turned on. Via gui or command line using command <sudo raspi-config>
#1.1.9
cmmd=$(apt purge autofs 2> /dev/null)

#1.1.10
#cmmd1=$

#AIDE NOT COMPATIBLE ON RASPBERRY PI

#1.3.1 Installing AIDE 
#cmmd=$(apt install aide aide-common -y)
#cmmd2=$(aideinit)
#cmmd3=$(mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db)

#1.3.2 Ensure filesystem integrity is regularly checked
#cmmd4=$(echo "Description=Aide Check" >> /etc/systemd/system/aidecheck.service)
#cmmd5=$(echo "Type=simple" >> /etc/systemd/system/aidecheck.service)
#cmmd6=$(echo "ExecStart=/usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" >> /etc/systemd/system/aidecheck.service)
#cmmd7=$(echo "WantedBy=multi-user.target" >> /etc/systemd/system/aidecheck.service)

#cmmd8=$(Description=Aide check every day at 5AM >> /etc/systemd/system/aidecheck.timer)
#cmmd9=$(OnCalendar=*-*-* 05:00:00 >> /etc/systemd/system/aidecheck.timer)
#cmmd10=$(Unit=aidecheck.service >> /etc/systemd/system/aidecheck.timer)
#cmmd11=$(WantedBy=multi-user.target >> /etc/systemd/system/aidecheck.timer)

#cmmd12=$(chown root:root /etc/systemd/system/aidecheck.*)
#cmmd13=$(chmod 0644 /etc/systemd/system/aidecheck.*)
#cmmd14=$(systemctl daemon-reload)
#cmmd15=$(systemctl enable aidecheck.service)
#cmmd16=$(systemctl --now enable aidecheck.timer)

#grub eventhough installed does not install files such as grub.cfg which is needed to set superuser in bootloader login
#1.4.1 Ensure bootloader password is set 
#cmmd=$(apt install grub2 -y)
#cmmd1=$(echo "cat <<EOF" >> /etc/grub/grub.cfg)
#cmmd2=$(echo "set superusers="root"" >> /etc/grub.d/grub.cfg)
#cmmd3=$(echo "password_pbkdf2 root grub.pbkdf2.sha512.10000.6FEDBC29DD27E666EA3FD37DD132AD1DAC4CE5FA5F86DCEADC63F0C76A0C2702B710CF4A3154ABC181DBEC8A412F4EC18A2D9952FC3987A106B1578334D37DE7.8EAE3EAD75520944BA1C587EDDBA533A951A09175CD32645FD91B4974F58A714216D4DD564915734CD7AFC36AA3E609066C289C881932FEE58FB22615C0958A8 >> /etc/grub.d)
#cmmd1=$(echo "password_pbkdf2 root grub.pbkdf2.sha512.10000.6FEDBC29DD27E666EA3FD37DD132AD1DAC4CE5FA5F86DCEADC63F0C76A0C2702B710CF4A3154ABC181DBEC8A412F4EC18A2D9952FC3987A106B1578334D37DE7.8EAE3EAD75520944BA1C587EDDBA533A951A09175CD32645FD91B4974F58A714216D4DD564915734CD7AFC36AA3E609066C289C881932FEE58FB22615C0958A8" >> /boot/grub/grub.cfg)
#cmmd4=$(echo "EOF" >> /etc/grub.d/grub.cfg)
#cmmd5=$(sudo update-grub)


#1.4.2 Ensure bootloader config are configured
#grub.cfg does not exist even when rasp pi downloaded grub

#cmd=$(chown root:root /boot/grub/grub.cfg)
#cmd1=$(chmod u-wx,go-rwx /boot/grub/grub.cfg)

#1.4.3 Ensure authentication required for single user mode

cmd2=$(echo "root:AMCtp@2022#" | chpasswd)

#1.5.1 Ensure address space layout randomization is enabled

cmd3=$(printf "kernel.randomize_va_space = 2" >> /etc/sysctl.d/60-kernel_sysctl.conf)
cmd4=$(sysctl -w kernel.randomize_va_space=2)

#1.5.2 Ensure prelink is not installed
cmd5=$(prelink -ua 2> /dev/null)
cmd6=$(apt purge prelink 2> /dev/null)

#1.5.3 apport cannot be installed on rasp pi

#1.5.4 Ensure core dumps are restricted
cmd7=$(printf "* hard core 0" >> /etc/security/limits.conf)
cmd8=$(printf "fs.suid_dumpable = 0" >> /etc/sysctl.conf)
cmd9=$(sysctl -w fs.suid_dumpable=0)


#NEED TO CHECK IF ACTUAL RASP PI SYSTEMD-COREDUMP CAN BE INSTALLED

#1.6.1.1 Ensure AppArmor is installed

cmd10=$(apt install apparmor apparmor-utils -y)



#1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration
#grub again does not work
#cmd11=$(sed -i -e 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"/g' /etc/default/grub)
#cmd12=$(update-grub)

#1.6.1.4 Ensure all AppArmor Profiles are enforcing
cmd13=$(aa-enforce /etc/apparmor.d/*)

#1.7.1 Ensure message of the day is configured properly
cmd14=$(rm /etc/motd 2> /dev/null)


#1.7.2 Ensure local login warning banner is configured properly
cmd15=$(echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue)

#1.7.3 Ensure remote login warning banner is configured properly

cmd16=$(echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net)


#1.7.4 Ensure permissions on /etc/motd are configured (Not done as /etc/motd is already removed)


#1.7.5 Ensure permissions on /etc/issue are configured
cmd17=$(chown root:root $(readlink -e /etc/issue))
cmd18=$(chmod u-x,go-wx $(readlink -e /etc/issue))


#1.7.6
comd=$(chown root:root $(readlink -e /etc/issue.net))
comd1=$(chmod u-x,go-wx $(readlink -e /etc/issue.net))

#gdm3 cannot be installed on rasp pi not sure

#1.8.2 GDM login banner need not be configured while having a warning banner is good to avoid users from illegally entering the system, it does not harden the system infrastructure

#1.8.3
#gdm eventhough has been preinstalled these files does not exist and when user tries to download gdm he would be greeted w an error. Thus the user is not able to update gdm files
#cmmd6=$(echo "user-db:user" >> /etc/dconf/profile/gdm)
#cmmd7=$(echo "system-db:gdm" >> /etc/dconf/profile/gdm)
#cmmd8=$(echo "file-db:/usr/share/gdm/greeter-dconf-defaults" >> /etc/dconf/profile/gdm)
#cmmd9=$(echo "[org/gnome/login-screen]" >> /etc/dconf/db/gdm.d/00-loginscreen)
#cmmd10=$(echo "# Do not show the user list:" >> /etc/dconf/db/gdm.d/00-loginscreen)
#cmmd11=$(echo "disable-user-list=true" >> /etc/dconf/db/gdm.d/00-loginscreen)
#cmmd12=$(dconf update)

#1.8.4 While good to have does not harden the infrastructure

#1.8.5 While good to have does not harden the infrastructure

#1.8.6
#cmmd13=$(echo "[org/gnome/desktop/media-handling]" >> /etc/dconf/db/local.d/00-media-automount)
#cmmd14=$(echo "automount=false" >> /etc/dconf/db/local.d/00-media-automount)
#cmmd15=$(echo "automount-open=false" >> /etc/dconf/db/local.d/00-media-automount)
#cmmd16=$(echo "EOF" >> /etc/dconf/db/local.d/00-media-automount)
#cmmd17=$(dconf update)

# 1.8.7 -.9 cannot be executed on raspberry pi

#1.8.10 not running gdm3
#cmmd 18=$(sed -i -e 's/Enable=true//g' /etc/gdm3/custom.conf)





#chrony=$(systemctl status chrony | grep "active (running)")
#ntp=$(systemctl status ntp | grep "active (running)")
#systemd-timesyncd=$(systemctl status systemd-timesyncd | grep "active (running)"


#if [ ! -z "$chrony" ]
#then
#	systemctl stop systemd-timesyncd.service
#	systemctl --now mask systemd-timesyncd.service
#	apt purge ntp
#elif [ ! -z "$ntp" ]
#then
#	apt purge chrony
#	apt purge ntp
#elif [ ! -z "$systemd-timesyncd" ]
#then
#	apt install ntp
#	systemctl stop systemd-timesyncd.service
#	systemctl --now mask systemd-timesyncd.service
#	apt purge chrony
#else
#	apt install ntp
#fi


#2.1.4.1
command=$(apt purge ntp -y)
command1=$(apt install ntp -y)
command2=$(sed -i -e 's/restrict -4 default kod notrap nomodify nopeer noquery limited/restrict -4 default kod notrap nomodify nopeer noquery/g'  /etc/ntp.conf)
command3=$(sed -i -e 's/restrict -6 default kod nomodify notrap nopeer noquery/restrict -6 default kod notrap nomodify nopeer noquery/g'  /etc/ntp.conf)
command3=$(sed -i -e 's/restrict -6 default kod nomodify notrap nopeer noquery limited/restrict -6 default kod notrap nomodify nopeer noquery/g'  /etc/ntp.conf)

command4=$(systemctl unmask ntp.service)
command5=$(systemctl --now enable ntp.service)



#2.2 & 2.3 need to check which services are used by ACTUAL raspberry pi

#while user need to login on raspberry pi, this authentication can already be done by the OS no need for additional service
#if need gui remove this
cmdd=$(apt purge xserver-xorg* -y)

cmdd21=$(systemctl stop avahi-daaemon.service)
cmdd22=$(systemctl stop avahi-daemon.socket)
cmdd23=$(apt purge avahi-daemon -y)

#as the purpose of the raspberry pi is used for camera streaming and not printing this service can be removed
cmdd1=$(apt purge cups -y)

#not a dhcp server which allocates ip addresses to end devices
cmdd2=$(apt purge isc-dhcp-server -y)

#not a LDAP server
cmdd3=$(apt purge slapd -y)

#raspberry pi is not configured to export NFS shares
cmdd4=$(apt purge nfs-kernel-server -y)

#not a DNS server
cmdd5=$(apt purge bind9 -y)

#not a FTP server
cmdd6=$(apt purge vsftpd -y)

#HTTP server is hosted by client VM not raspberry pi
cmdd7=$(apt purge apache2 -y)

#not a POP3 or IMAP server
cmdd8=$(apt purge dovecot-imapd dovecot-pop3d -y)

#No need the use of SAMBA as there is no mounting on Windows systems happening on the raspberry pi
cmdd9=$(apt purge samba -y)

#no need for a HTTP proxy server
cmdd10=$(apt purge squid -y)

#no need for SNMP server
cmdd11=$(apt purge snmp -y)

#not a NIS server
cmdd12=$(apt purge nis -y)

#2.2.15 NOT sure if need to be done

#2.2.16
cmdd13=$(systemctl stop rsync)
cmdd14=$(systemctl mask rsync)

#not using nis client
cmdd15=$(apt purge nis -y)

#not using rsh rather using a more secure ssh to remote into raspberry pi
cmdd16=$(apt purge rsh-client -y)


#not using talk client
cmdd17=$(apt purge talk -y)

#not using telnet using ssh instead
cmdd18=$(apt purge telnet -y)

#not using LDAP client
cmdd19=$(apt purge ldap-utils -y)

#not using RPC
cmdd20=$(apt purge rpcbind -y)



#3.1 & 3.2 need to check which network interface/ network features used


#3.1.2 cannot be disabled

#3.1.4
comp=$(bash 3-1-4.sh)

#3.1.5
comp1=$(bash 3-1-5.sh)

#3.1.6
comp2=$(bash 3-1-6.sh)




#3.2.1 Disabled as raspberry pi is not suppose to provide information for routing information as it is not a counter 
#just configured as an end device
#Not sure if this method is correct
comp3=$(bash 3-2-1.sh)

#cmd20=$(echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf)
#cmd21=$(echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf)


comp4=$(bash 3-2-2.sh 2> /dev/null)

#3.2.2 As it is an end device it is not supposed to tell a system if it can forward packets to it or not
#cmd22=$(echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf)
#cmd23=$(echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.conf)
#cmd24=$(sysctl -p)



#STOPPED HERE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!




#3.3.1 Not sure if these commands work

#cmd25=$(sysctl -w net.ipv4.conf.all.accept_source_route=0)
#cmd26=$(sysctl -w net.ipv4.conf.default.accept_source_route=0)

#cmd27=$(sysctl -w net.ipv6.conf.all.accept_source_route=0)
#cmd28=$(sysctl -w net.ipv6.conf.default.accept_source_route=0)
#cmd29=$(sysctl -w net.ipv4.route.flush=1)
#cmd30=$(sysctl -w net.ipv6.route.flush=1)
cmd25=$(bash 3-3-1.sh)
cmd26=$(bash 3-3-2.sh)
cmd27=$(bash 3-3-3.sh)
cmd28=$(bash 3-3-4.sh)
cmd29=$(bash 3-3-5.sh)
cmd30=$(bash 3-3-6.sh)
comp5=$(bash 3-3-7.sh)
comp6=$(bash 3-3-8.sh)
comp7=$(bash 3-3-9.sh)






#Skipped till now 3.5.1.1 UFW 
cmd31=$(apt install ufw -y)
cmd32=$(apt purge iptables-persistent -y)
cmd33=$(systemctl unmask ufw.service)
cmd34=$(systemctl --now enable ufw.service)
cmd35=$(ufw enable)
cmd36=$(ufw allow in on lo)
cmd37=$(ufw allow out on lo)
cmd38=$(ufw deny in from 127.0.0.0/8)
cmd39=$(ufw deny in from ::1)
cmd40=$(ufw allow out on all)
cmdssh=$(sudo ufw allow OpenSSH)
cmdvnc=$(ufw allow from 192.168.215.0/24 to any port 5900)


#3.5.1.6 creating ufw for open ports (5900,8081,22) 631 not inside as it used for CUPS service which has been removed

cmd41=$(ufw default deny incoming)
cmd42=$(ufw default allow outgoing)
cmd43=$(ufw default deny routed)

#3.5.2.1 As UFW has already been configured nftables is not configured as it could cause errors due to both of the services running simultaneously
#comp8=(apt install nftables -y)




#3.5.3.1.1 As UFW has already been configured nftables is not configured as it could cause errors due to both of the services running simultaneously
#comp8=$(




#done in run_after_hardening.sh

#4.1.4.1 is in 2nd script
