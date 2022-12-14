#!/usr/bin/env bash
{
 perm_mask='0177'
 valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
 awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd | while read -r user home; do
 if [ -f "$home/.rhosts" ]; then
 echo -e "\n- User \"$user\" file: \"$home/.rhosts\" exists\n -removing file: \"$home/.rhosts\"\n"
 rm -f "$home/.rhosts"
 fi
 done
}
