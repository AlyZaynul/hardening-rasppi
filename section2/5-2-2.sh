#!/usr/bin/env bash
{
 l_skgn="ssh_keys" # Group designated to own openSSH keys
 l_skgid="$(awk -F: '($1 == "'"$l_skgn"'"){print $3}' /etc/group)"
 awk '{print}' <<< "$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat -L -c "%n %#a %U %G %g" {} +)" | (while read -r l_file l_mode l_owner l_group l_gid; do
 [ -n "$l_skgid" ] && l_cga="$l_skgn" || l_cga="root"
 [ "$l_g#!/usr/bin/env bash
{
 l_skgn="ssh_keys" # Group designated to own openSSH keys
 l_skgid="$(awk -F: '($1 == "'"$l_skgn"'"){print $3}' /etc/group)"
 awk '{print}' <<< "$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat -L -c "%n %#a %U %G %g" {} +)" | (while read -r l_file l_mode l_owner l_group l_gid; do
 [ -n "$l_skgid" ] && l_cga="$l_skgn" || l_cga="root"
 [ "$l_gid" = "$l_skgid" ] && l_pmask="0137" || l_pmask="0177"
 l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"
 if [ $(( $l_mode & $l_pmask )) -gt 0 ]; then
 echo -e " - File: \"$l_file\" is mode \"$l_mode\" changing to mode: \"$l_maxperm\""
 if [ -n "$l_skgid" ]; then
 chmod u-x,g-wx,o-rwx "$l_file"
 else
 chmod u-x,go-rwx "$l_file"
 fi
 fi
 if [ "$l_owner" != "root" ]; then
 echo -e " - File: \"$l_file\" is owned by: \"$l_owner\" changing owner to \"root\""
 chown root "$l_file"
 fi
 if [ "$l_group" != "root" ] && [ "$l_gid" != "$l_skgid" ]; then
 echo -e " - File: \"$l_file\" is owned by group \"$l_group\" should belong to group \"$l_cga\""
 chgrp "$l_cga" "$l_file"
 fi
 done
 )
}
id" = "$l_skgid" ] && l_pmask="0137" || l_pmask="0177"
 l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"
 if [ $(( $l_mode & $l_pmask )) -gt 0 ]; then
 echo -e " - File: \"$l_file\" is mode \"$l_mode\" changing to mode: \"$l_maxperm\""
 if [ -n "$l_skgid" ]; then
 chmod u-x,g-wx,o-rwx "$l_file"
 else
 chmod u-x,go-rwx "$l_file"
 fi
 fi
 if [ "$l_owner" != "root" ]; then
 echo -e " - File: \"$l_file\" is owned by: \"$l_owner\" changing owner to \"root\""
 chown root "$l_file"
 fi
 if [ "$l_group" != "root" ] && [ "$l_gid" != "$l_skgid" ]; then
 echo -e " - File: \"$l_file\" is owned by group \"$l_group\" should belong to group \"$l_cga\""
 chgrp "$l_cga" "$l_file"
 fi
 done
 )
}
