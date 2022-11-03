#!/bin/bash
comd1=$(apt install auditd audispd-plugins)
comd2=$(systemctl --now enable auditd)

comd3=$(sed -i -e 's/max_log_file_action = ROTATE/max_log_file_action = keep_logs/g' /etc/audit/auditd.conf)


cmd1=$(bash 4131.sh)
cmd2=$(bash 4132.sh)
#.3 has errors
cmd3=$(bash 4134.sh)
cmd4=$(bash 4135.sh)
cmd5=$(bash 4136.sh)
#.7 has errors
cmd6=$(bash 4138.sh)
cmd7=$(bash 4139.sh)
cmd8=$(bash 41310.sh)
cmd9=$(bash 41311.sh)
cmd10=$(bash 41312.sh)
cmd11=$(bash 41313.sh)
cmd12=$(bash 41314.sh)
cmd13=$(bash 41315.sh)
cmd14=$(bash 41316.sh)
cmd15=$(bash 41317.sh)
cmd16=$(bash 41318.sh)
#.19 not for 32bit system
cmd17=$(bash 41320.sh)


#4.1.4.1
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


