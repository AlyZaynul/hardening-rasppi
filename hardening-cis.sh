#Ensure that SSH has been turned on. Via gui or command line using command <sudo raspi-config>


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
cmd7=$(echo "* hard core 0" >> /etc/security/limits.conf)
cmd8=$(echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf)
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
command4=$(systemctl unmask ntp.service)
command5=$(systemctl --now enable ntp.service)



#2.2 & 2.3 need to check which services are used by ACTUAL raspberry pi

#while user need to login on raspberry pi, this authentication can already be done by the OS no need for additional service
cmdd=$(apt purge xserver-xorg* -y)

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





#SKipped all the way till 4.1.1.1 
cmd44=$(apt install auditd audispd-plugins -y)
cmd45=$(systemctl --now enable auditd)

#cmd46=$(echo 'GRUB_CMDLINE_LINUX="audit=1"' /etc/default/grub)
#cmd47=$(echo 'GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"' /etc/default/grub)
#cmd48=$(update-grub)


#DO not want to increase the log storage size as it may take up too much space which could in tern aversely affect the camera feed
cmd48=$(sed -i -e 's/max_log_file_action/#max_log_file_action/g'  /etc/audit/auditd.conf)
cmd49=$(echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf)

#While security is important the purpose of the camera is meant to be kept running no matter whaat so that emergency stops can still be executed if the employee deem the machine unsafe through the camera feed

#4.1.3.1
cmd50=$(bash 4-1-3-1.sh)
cmd53=$(printf " -a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation" >> /etc/audit/rules.d/50-user_emulation.rules)
cmd54=$(augenrules --load)
#cmd55=({SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,?.*//' -e 's/"//g') [ -n "${SUDO_LOG_FILE}" ] && printf " -w ${SUDO_LOG_FILE} -p wa -k sudo_log_file" >> /etc/audit/rules.d/50-sudo.rules || printf "ERROR: Variable 'SUDO_LOG_FILE_ESCAPED' is unset.\n"})
cmd55=$(bash 4133.sh)
cmd56=$(augenrules --load)
cmd57=$(printf " -a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime,stime -k time-change " >> /etc/audit/rules.d/50-time-change.rules)
cmd58=$(augenrules --load)
cmd59=$(printf " -a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale\n-w /etc/issue -p wa -k system-locale\n -w /etc/issue.net -p wa -k system-locale\n -w /etc/hosts -p wa -k system-locale\n -w /etc/networks -p wa -k system-locale\n -w /etc/networks -p wa -k system-locale\n -w /etc/network/ -p wa -k system-locale" >> /etc/audit/rules.d/50-system_local.rules)
cmd60=$(augenrules --load)
cmd61=$(bash 4-1-3-6.sh)
cmd62=$(augenrules --load)
cmd63=$(bash 4-1-3-7.sh)
#{UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs) [ -n "${UID_MIN}" ] && printf " -a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access\n -a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access" >> /etc/audit/rules.d/50-access.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"})
cmd64=$(augenrules --load)
cmd65=$(bash 4-1-3-8.sh)
#4-1-3-9 & -10 has error
#cmd67=$({UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs) [ -n "${UID_MIN}" ] && printf " -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod\n -a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod " >> /etc/audit/rules.d/50-perm_mod.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"})
#cmd68=$(augenrules --load)
#cmd69=$({UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs) [ -n "${UID_MIN}" ] && printf " -a always,exit -F arch=b32 -S mount -F auid>=$UID_MIN -F auid!=unset -k mounts" >> /etc/audit/rules.d/50-mounts.rules || printf "ERROR: Variable 'UID_MIN'is unset.\n"})
#cmd70=$(augenrules --load)

#4-1-3-11
cmd71=$(printf " -w /var/run/utmp -p wa -k session\n -w /var/log/wtmp -p wa -k session\n -w /var/log/btmp -p wa -k session" >> /etc/audit/rules.d/50-session.rules)
cmd72=$(augenrules --load)

#4-1-3-12
cmd73=$(printf " -w /var/log/lastlog -p wa -k logins\n -w /var/run/faillock -p wa -k logins" >> /etc/audit/rules.d/50-login.rules)
cmd74=$(augenrules --load)

#4-1-3-13 has errors
#cmd75=$({UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs) [ -n "${UID_MIN}" ] && printf " -a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete" >> /etc/audit/rules.d/50-delete.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"})
#cmd76=$(augenrules --load)

#4-1-3-14
#cmd77=$(printf " -w /etc/apparmor/ -p wa -k MAC-policy\n -w /etc/apparmor.d/ -p wa -k MAC-policy" >> /etc/audit/rules.d/50-MAC-policy.rules )
#cmd78=$(augenrules --load)

#4-1-3-15 has errors
#cmd79=({UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs) [ -n "${UID_MIN}" ] && printf " -a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng" >> /etc/audit/rules.d/50-perm_chng.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"})
#cmd80=$(augenrules --load)

#4-1-3-16 has errors
#cmd81=$({UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs) [ -n "${UID_MIN}" ] && printf " -a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng" >> /etc/audit/rules.d/50-perm_chng.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"})
#cmd82=$(augenrules --load)

#4-1-3-17 has errors
#cmd83=$({UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs) [ -n "${UID_MIN}" ] && printf " -a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng" >> /etc/audit/rules.d/50-perm_chng.rules || printf "ERROR: Variable'UID_MIN' is unset.\n"})
#cmd84=$(augenrules --load)











#4.1.3.19 only for 64 bit system
#cmd85=$({UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs) [ -n "${UID_MIN}" ] && printf " -a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k usermod" >> /etc/audit/rules.d/50-usermod.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"}
#cmd86=$(augenrules --load)
cmdY=$(bash try.sh)
cmd85=$(printf -- "-e 2" >> /etc/audit/rules.d/99-finalize.rules)
cmd86=$(augenrules --load)
cmd87=$(chmod 640 /etc/audit/auditd.conf)
cmd88=$(chown root /etc/audit/auditd.conf)
cmd89=$(chgrp adm /var/log/audit/)
cmd90=$(sed -ri 's/^\s*#?\s*log_group\s*=\s*\S+(\s*#.*)?.*$/log_group = adm\1/' /etc/audit/auditd.conf)
cmd91=$(systemctl restart auditd)
#4.1.4.4
cmd92=(chmod g-w,o-rwx "$(dirname $(awk -F"=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf))")

#cmd92=$(chmod 0750 /var/log/audit)

#4.1.4.5
cmd93=$(find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec chmod u-x,g-wx,o-rwx {} +)


#4.1.4.6
cmd94=$(find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec chown root {} +)

#4.1.4.7
cmd95=$(find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} +)

#4.1.4.8
cmd96=$(chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules)

#4.1.4.9 
cmd97=$(chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules)

#4.1.4.10
cmd98=$(chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules)
cmd99=$(chown root:root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules)

#4.1.4.11 As aide is not supported by rasp pi this step is skipped

#4.2.1.1.1
#apt install systemd-journal-remote NOT installed as there is not dedicated remote log host








#5.1.1
cmd100=$(systemctl --now enable cron)
cmd101=$(chown root:root /etc/crontab)
cmd102=$(chmod og-rwx /etc/crontab)
cmd103=$(chown root:root /etc/cron.hourly/)
cmd104=$(chmod og-rwx /etc/cron.hourly/)
cmd105=$(chown root:root /etc/cron.daily/)
cmd106=$(chmod og-rwx /etc/cron.daily/)
cmd107=$(chown root:root /etc/cron.weekly/)
cmd108=$(chmod og-rwx /etc/cron.weekly/)
cmd109=$(chown root:root /etc/cron.monthly/)
cmd110=$(chmod og-rwx /etc/cron.monthly/)
cmd111=$(chown root:root /etc/cron.d/)
cmd112=$(chmod og-rwx /etc/cron.d/)
cmd113=$(rm /etc/cron.deny 2>/dev/null)
cmd114=$(touch /etc/cron.allow)
cmd115=$(chmod g-wx,o-rwx /etc/cron.allow)
cmd116=$(chown root:root /etc/cron.allow)
cmd117=$(rm /etc/at.deny 2>/dev/null)
cmd118=$(touch /etc/at.allow)
cmd119=$(chmod g-wx,o-rwx /etc/at.allow)
cmd120=$(chown root:root /etc/at.allow)

#5.2.1
cmd121=$(chown root:root /etc/ssh/sshd_config)
cmd122=$(chmod og-rwx /etc/ssh/sshd_config)

#5.2.2 Currently change owner but not perms
bash 5-2-2.sh

#5.2.3 
#cmd123=$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,gowx {} \;)
cmd123=$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 0644 {} \;)
cmd124=$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;)

#5.2.4
cmd125=$(echo "AllowUsers pi" >> /etc/ssh/sshd_config)
cmd126=$(echo "DenyUsers root" >> /etc/ssh/sshd_config)

#5.2.5
cmd127=$(sed -i -e 's/LogLevel INFO/LogLevel VERBOSE/g'  /etc/ssh/sshd_config)

#5.2.6
cmd128=$(sed -i -e 's/UsePAM no/UsePAM yes/g'  /etc/ssh/sshd_config)
cmd129=$(sed -i -e 's/#UsePAM yes/UsePAM yes/g'  /etc/ssh/sshd_config)

#5.2.7
cmd130=$(sed -i -e 's/PermitRootLogin prohibit-password/PermitRootLogin no/g'  /etc/ssh/sshd_config)
cmd131=$(sed -i -e 's/PermitRootLogin yes/PermitRootLogin no/g'  /etc/ssh/sshd_config)
cmd131add=$(sed -i -e 's/#PermitRootLogin no/PermitRootLogin no/g'  /etc/ssh/sshd_config)

#5.2.8
cmd132=$(sed -i -e 's/HostbasedAuthentication yes/HostbasedAuthentication no/g'  /etc/ssh/sshd_config)
cmd133=$(sed -i -e 's/#UHostbasedAuthentication no/HostbasedAuthentication no/g'  /etc/ssh/sshd_config)

#5.2.9
cmd134=$(sed -i -e 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/g'  /etc/ssh/sshd_config)
cmd135=$(sed -i -e 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g'  /etc/ssh/sshd_config)

#5.2.10
cmd136=$(sed -i -e 's/PermitUserEnvironment yes/PermitUserEnvironment no/g'  /etc/ssh/sshd_config)
cmd137=$(sed -i -e 's/#PermitUserEnvironment no/PermitUserEnvironment no/g'  /etc/ssh/sshd_config)

#5.2.11
cmd138=$(sed -i -e 's/IgnoreRhosts no/IgnoreRhosts yes/g'  /etc/ssh/sshd_config)
cmd139=$(sed -i -e 's/#IgnoreRhosts yes/IgnoreRhosts yes/g'  /etc/ssh/sshd_config)

#5.2.12
cmd140=$(sed -i -e 's/X11Forwarding yes/X11Forwarding no/g'  /etc/ssh/sshd_config)
cmd141=$(sed -i -e 's/#X11Forwarding no/X11Forwarding no/g'  /etc/ssh/sshd_config)
cmd142=$(sed -i -e 's/#X11Forwarding yes/X11Forwarding no/g'  /etc/ssh/sshd_config)


cmd143=$(sed -i -e 's/3des-cbc/aes128-gcm@openssh.com/g'  /etc/ssh/sshd_config)
cmd144=$(sed -i -e 's/aes128-cbc/aes128-ctr/g'  /etc/ssh/sshd_config)
cmd145=$(sed -i -e 's/aes192-cbc/aes192-ctr/g'  /etc/ssh/sshd_config)
cmd146=$(sed -i -e 's/aes256-cbc/aes256-ctr/g'  /etc/ssh/sshd_config)

cmd147=$(echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config)
#cmd148=$(echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellmangroup14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffiehellman-group-exchange-sha256" >> /etc/ssh/sshd_config)
cmd148=$(echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256" >> /etc/ssh/sshd_config)

#15
cmd149=$(sed -i -e 's/AllowTcpForwarding yes/AllowTcpForwarding no/g'  /etc/ssh/sshd_config)
cmd149A=$(sed -i -e 's/#AllowTcpForwarding yes/AllowTcpForwarding no/g'  /etc/ssh/sshd_config)


cmd150=$(echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config)

cmd151=$(sed -i -e 's/MaxAuthTries 6/MaxAuthTries 4/g'  /etc/ssh/sshd_config)
cmd152=$(sed -i -e 's/#MaxAuthTries 4/MaxAuthTries 4/g'  /etc/ssh/sshd_config)

cmd153A=$(sed -i -e 's/#MaxStartups 10:30:100/MaxStartups 10:30:60/g'  /etc/ssh/sshd_config)
cmd153B=$(sed -i -e 's/MaxStartups 10:30:100/MaxStartups 10:30:60/g'  /etc/ssh/sshd_config)

cmd153=$(sed -i -e 's/#MaxSessions 10/MaxSessions 10/g'  /etc/ssh/sshd_config)

cmd154=$(sed -i -e 's/#LoginGraceTime 2m/LoginGraceTime 60/g'  /etc/ssh/sshd_config)
cmd155=$(sed -i -e 's/LoginGraceTime 120/LoginGraceTime 60/g'  /etc/ssh/sshd_config)
cmd156=$(sed -i -e 's/#LoginGraceTime 120/LoginGraceTime 60/g'  /etc/ssh/sshd_config)


cmd157=$(sed -i -e 's/#ClientAliveInterval 0/ClientAliveInterval 15/g'  /etc/ssh/sshd_config)
cmd158=$(sed -i -e 's/#ClientAliveCountMax 3/ClientAliveCountMax 3/g'  /etc/ssh/sshd_config)

cmdX=$(systemctl reload sshd)

cmd159=$(apt install sudo -y)
cmd160=$(echo "Defaults use_pty" >> /etc/sudoers)
cmd161=$(echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers)

cmd162=$(sed -i -e 's/NOPASSWD/PASSWD/g'   /etc/sudoers)
cmd163=$(sed -i -e 's/NOPASSWD/PASSWD/g'   /etc/sudoers* 2>/dev/null) 
cmd163A=$(sed -i -e 's/NOPASSWD/PASSWD/g'  /etc/sudoers.d/010_pi-nopasswd)

cmd164=$(sed -i -e 's/!authenticate/PASSWD/g'   /etc/sudoers)
cmd165=$(sed -i -e 's/!authenticate/PASSWD/g'   /etc/sudoers* 2>/dev/null)

cmd166=$(echo "Defaults env_reset, timestamp_timeout=15" >> /etc/sudoers)

cmd167=$(groupadd sugroup 2>/dev/null)
cmd168=$(echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su)

cmd169=$(apt install libpam-pwquality -y)
cmd170=$(sed -i -e 's/# minlen = 8/minlen = 14/g'  /etc/security/pwquality.conf)
cmd171=$(sed -i -e 's/# minclass = 0/minclass = 4/g'  /etc/security/pwquality.conf)

#5.4.2 stopped NOT DONE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#5.4.3
cmd172=$(echo "password required pam_pwhistory.so use_authtok remember=5" >> /etc/pam.d/common-password)

#cmd173=$(sed -i -e 's/password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass yescrypt/password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass remember=5/g'  /etc/pam.d/common-password)
cmd173=$(sed -i -e 's/pam_unix.so obscure use_authtok try_first_pass yescrypt/pam_unix.so obscure use_authtok try_first_pass remember=5/g'  /etc/pam.d/common-password)
#cmd174=$(sed -i -e 's/ENCRYPT_METHOD SHA512/ENCRYPT_METHOD yescrypt/g' /etc/login.defs)


cmd175=$(chage --mindays 1 root)
cmd176=$(chage --mindays 1 pi)

cmd177=$(sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/g' /etc/login.defs)

cmd178=$(sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/g' /etc/login.defs)
cmd179=$(chage --maxdays 365 root)
cmd180=$(chage --maxdays 365 pi)

cmd180=$(sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/g' /etc/login.defs)

cmd181=$(useradd -D -f 30)

cmd182=$(awk -F: '$1!~/(root|sync|shutdown|halt|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!~/((\/usr)?\/sbin\/nologin)/ && $7!~/(\/bin)?\/false/ {print $1}' /etc/passwd | while read -r user; do usermod -s "$(which nologin)" "$user"; done)

cmd183=$(usermod -g 0 root)

cmd184=$(sed -i 's/^UMASK.*/UMASK 027/g' /etc/login.defs)
cmd185=$(sed -i 's/USERGROUPS_ENAB yes/USERGROUPS_ENAB no/g' /etc/login.defs)
cmd186=$(echo "session optional pam_umask.so" >> /etc/pam.d/common-session)

cmd187=$(echo "readonly TMOUT=900 ; export TMOUT" >> /etc/profile)




#6.1.1
cmd188=$(chmod u-x,go-wx /etc/passwd)
cmd189=$(chown root:root /etc/passwd)

#6.1.2
cmd190=$(chmod u-x,go-wx /etc/passwd-)
cmd191=$(chown root:root /etc/passwd-)

#6.1.3
cmd192=$(chmod u-x,go-wx /etc/group)
cmd193=$(chown root:root /etc/group)

#6.1.4
cmd194=$(chmod u-x,go-wx /etc/group-)
cmd195=$(chown root:root /etc/group-)

#6.1.5
cmd196=$(chown root:root /etc/shadow)
cmd197=$(chmod u-x,g-wx,o-rwx /etc/shadow)

#6.1.6
cmd198=$(chown root:root /etc/shadow-)
cmd199=$(chmod u-x,g-wx,o-rwx /etc/shadow-)

#6.1.7
cmd200=$(chown root:root /etc/gshadow)
cmd201=$(chmod u-x,g-wx,o-rwx /etc/gshadow)

#6.1.8
cmd202=$(chown root:root /etc/gshadow-)
cmd203=$(chmod u-x,g-wx,o-rwx /etc/gshadow-)

#6.1.9 & 6.1.10 & 6.1.11 (Did not harden as the rasp pi should only have motion(usb camera) OR uv4l(rolling shutter camera)


#6.2.1
cmd204=$(sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd)

#6.2.2 & 6.2.3. as there should not be any other users other than pi and root this hardening need not be done

cmd205=$(sed -ri 's/(^shadow:[^:]*:[^:]*:)([^:]+$)/\1/' /etc/group)

#6.2.5 & 6.2.6 & 6.2.7 & 6.2.8 As raspi pi is configured for user pi and root these steps can be skipped

#6.2.9 As PATH was not changed to allow the camera to livestream this part can be skipped
cmd206=$(bash 6-2-11.sh)

cmd207=$(bash 6-2-12.sh)

cmd208=$(bash 6-2-13.sh)

cmd209=$(bash 6-2-14.sh)

cmd210=$(bash 6-2-15.sh)

cmd211=$(bash 6-2-16.sh)

cmd212=$(bash 6-2-17.sh)
