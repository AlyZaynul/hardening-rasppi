printf -- "-e 2
" >> /etc/audit/rules.d/99-finalize.rules

augenrules --load
