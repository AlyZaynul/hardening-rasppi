
cmd67=$({ UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs) 
[ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod 
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod 
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
" >> /etc/audit/rules.d/50-perm_mod.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n" 
})
cmd68=$(augenrules --load)

cmd69=$({
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b32 -S mount -F auid>=$UID_MIN -F auid!=unset -k mounts
" >> /etc/audit/rules.d/50-mounts.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
})
cmd70=$(augenrules --load)

cmd75=$({
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
" >> /etc/audit/rules.d/50-delete.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
})
cmd76=$(augenrules --load)

cmd77=$(printf "
-w /etc/apparmor/ -p wa -k MAC-policy\n
-w /etc/apparmor.d/ -p wa -k MAC-policy
" >> /etc/audit/rules.d/50-MAC-policy.rules )
cmd78=$(augenrules --load)
 
#4-1-3-15 has errors


cmd79=$({
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> /etc/audit/rules.d/50-perm_chng.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
})
cmd80=$(augenrules --load)

cmd81=$({
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> /etc/audit/rules.d/50-perm_chng.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
})
cmd82=$(augenrules --load)
 
#4-1-3-17 has errors


cmd83=$({  
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
[ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> /etc/audit/rules.d/50-perm_chng.rules || printf "ERROR: Variable 'UID_MIN' is unset.\n"
})
cmd84=$(augenrules --load)

