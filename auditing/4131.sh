                                                                              

cmd1=$(apt install auditd audispd-plugins -y)
cmd2=$(systemctl --now enable auditd)


cmd3=$(printf "
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
" >> /etc/audit/rules.d/50-scope.rules)

cmd4=$(augenrules --load)
