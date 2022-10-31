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
