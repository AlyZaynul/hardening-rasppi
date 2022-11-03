#!/bin/bash







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
