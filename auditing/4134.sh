cmd9=$(
printf "
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k timechange
-w /etc/localtime -p wa -k time-change
" >> /etc/audit/rules.d/50-time-change.rules)


cmd10=$(augenrules --load)
