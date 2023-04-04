#!/bin/sh
############################################################################
#                               _                                          #
#                    _      __ (_)_____ ___   ____   _____                 #
#                   | | /| / // // ___// _ \ / __ \ / ___/                 #
#                   | |/ |/ // // /__ /  __// / / /(__  )                  #
#                   |__/|__//_/ \___/ \___//_/ /_//____/                   #
#                                                                          #
#                 WAN IP Change Email Notification Script                  #
#                                                                          #
############################################################################
# Thanks to all who contribute(d) at SNBforums, pieces of your code are here ;)
# shellcheck disable=SC2039,SC3045,SC2034,SC3003,SC3046,SC1090,SC2154,SC2005,SC2104
# disable notices about posix compliant -s   reads unused vars   hex/backspace in pswd check
# source   unfoundvars    echo with command   continue in function
# written by maverickcdn
# github.com/maverickcdn/wicens
# SNBforums thread https://www.snbforums.com/threads/wicens-wan-ip-change-email-notification-script.69294/

[ "$1" = 'debug' ] && shift && set -x

# START ###############################################################################################################
script_version='3.11'
script_ver_date='Apr 4 2023'
current_core_config='3.0'   # version of core(update) config (F_default_update_create)
current_user_config='3.1'   # version of user config (F_default_create)

script_name="$(basename "$0")"
script_name_full="/jffs/scripts/$script_name"
script_dir='/jffs/addons/wicens'
[ ! -d "$script_dir" ] && mkdir "$script_dir"
script_git_src='https://raw.githubusercontent.com/maverickcdn/wicens/master/wicens.sh'
git_get="/usr/sbin/curl -fsL --retry 3 --connect-timeout 5 $script_git_src"

config_src="${script_dir}/wicens_user_config.wic"   # user settings
update_src="${script_dir}/wicens_update_conf.wic"   # core config file
script_backup_file="${script_dir}/wicens_user_config.backup"   # user settings backup
history_src="${script_dir}/wicens_wan_history.wic"   # historical wan ip change file
history_src_backup="${script_dir}/wicens_history_src.bak"   # historical wan ip change file backup

mail_file='/tmp/wicens_email.txt'   # temp file for mail text
mail_log="${script_dir}/wicens_email.log"   # log file for sendmail/curl
wicens_send_retry='/tmp/wicens_send.retry'   # retry count file for send option
wicens_send_copy='/tmp/wicens_user_email.txt'   # backup of email for send option in retries
wicens_update_retry='/tmp/wicens_update.retry'   # retry count file for script update notifications
wicens_fw_retry='/tmp/wicens_fw.retry'   # retry count file for fw update notifications
wicens_wanip_retry='/tmp/wicens_wanip.retry'   # retry count file for wan ip change notifications
script_lock='/tmp/wicens.lock'   # script temp lock file
script_mail_lock='/tmp/wicenssendmail.lock'   # script temp lock file2 (email)
cred_loc="${script_dir}/.wicens_cred.enc"
cred_loc_bak="${cred_loc}bak"
amtm_email_conf='/jffs/addons/amtm/mail/email.conf'
amtm_cred_loc='/jffs/addons/amtm/mail/emailpw.enc'
amtm_d='L3Vzci9zYmluL29wZW5zc2wgMj4vZGV2L251bGwgYWVzLTI1Ni1jYmMgLXBia2RmMiAtZCAtaW4gL2pmZnMvYWRkb25zL2FtdG0vbWFpbC9lbWFpbHB3LmVuYyAtcGFzcyBwYXNzOmRpdGJhYm90LGlzb2kK'
user_e='L3Vzci9zYmluL29wZW5zc2wgZW5jIC1tZCBzaGE1MTIgLXBia2RmMiAtYWVzLTI1Ni1jYmMgLWEgLXNhbHQgLXBhc3MgcGFzczoiJChGX252cmFtX2dldCBib2FyZG51bSB8IC9iaW4vc2VkIHMvOi8vZykiIHwgdHIgLWQgIlxuIgo='
user_d='L3Vzci9zYmluL29wZW5zc2wgZW5jIC1tZCBzaGE1MTIgLXBia2RmMiAtYWVzLTI1Ni1jYmMgLWQgLWEgLXBhc3MgcGFzczoiJChGX252cmFtX2dldCBib2FyZG51bSB8IC9iaW4vc2VkIHMvOi8vZykiCg=='

# script misc #########################################################################################################
F_ctrlc_clean() { printf '\n\n%b Script interrupted...\n' "$tTERMHASH" ; F_clean_exit ;}   # CTRL+C catch with trap
trap F_ctrlc_clean INT   # trap ctrl+c exit clean
ip_regex='([0-9]{1,3}[\.]){3}[0-9]{1,3}'
current_wan_ip=''
passed_options="$1"
[ "$1" = '' ] && passed_options='manual'   # used to show manual vs cron/test/wancall/fwupdate/send run

F_replace_var() { sed -i "1,/${1}=.*/{s/${1}=.*/${1}=\'${2}\'/;}" "$3" ;}   # 1=var to change 2=new var string 3=file
F_chmod() { chmod a+rx "$1" ;}
F_crlf() { if grep -q $'\x0D' "$1" 2>/dev/null ; then dos2unix "$1" ; fi ;}   # crlf
F_nvram_get() { nvram get "$1" ;}
F_date() {
	if [ "$1" = 'sec' ] ; then
		/bin/date +'%s'
	elif [ "$1" = 'full' ] ; then
		/bin/date +'%a %b %d %Y @ %T'
	fi
}

# terminal/logging functions ##########################################################################################
F_terminal_show() { printf -- '%b %s\n' "$tTERMHASH" "$1" ;}
F_terminal_padding() { printf '\n' ;}
F_terminal_separator() { printf '---------------------------------------------------------------------------- \n' ;}
F_terminal_entry() { printf '%b %s' "$tTERMHASH" "$1" ;}
F_terminal_check() { printf '%b %s' "$tCHECK" "$1" ;}
F_terminal_check_ok() { printf '\r%b %s\n' "$tERASE$tCHECKOK" "$1" ;}
F_terminal_check_fail() { printf '\r%b %s\n' "$tERASE$tCHECKFAIL" "$1" ;}
F_terminal_header_print() { printf '%b %s %b%s%b\n' "$tTERMHASH" "$1" "$tGRN" "$2" "$tCLR" ;}
F_terminal_header_print_d() { printf '%b %s %b%s%b\n' "$tTERMHASH" "$1" "$tRED" "$2" "$tCLR" ;}
F_terminal_warning() { printf '%b%45s\n%45s\n%45s%b\n\n' "$tRED" "#################" "#    WARNING    #" "#################" "$tCLR" ;}
F_fail_entry() { F_terminal_check_fail "Invalid entry, any key to retry" && read -rsn1 "invalidwait" && printf '%b' "$tBACK$tERASE" && continue ;}
F_log() { printf '%s: %s' "$passed_options" "$1" | /usr/bin/logger -t "wicens[$$]" ;}
F_log_show() { F_log "$1" ; F_terminal_show "$1" ;}
F_log_terminal_ok() { F_terminal_check_ok "$1" ; F_log "$1" ;}
F_log_terminal_fail() { F_terminal_check_fail "$1" ; F_log "$1" ;}
F_sleep() {	 F_terminal_check "Importing..." ; usleep 150000 ;}

F_terminal_color() {
	tGRN="\033[1;32m" ; tRED="\033[1;31m" ; tPUR="\033[1;95m" ; tYEL="\033[1;93m" ; tCLR="\033[0m" ; tERASE="\033[2K" ; tBACK="\033[1A"
	# user no color
	[ "$opt_color" = 'no' ] && tGRN='' && tRED='' && tPUR='' && tYEL='' && tCLR=''
	tCHECK="[${tYEL}WAIT${tCLR}]" ; tCHECKOK="[${tGRN} OK${tCLR} ]" ; tCHECKFAIL="[${tRED}FAIL${tCLR}]" ; tTERMHASH="[${tPUR}-##-${tCLR}]"
}

F_confirm() {
	while true ; do
		if [ "$1" = 'correct' ] ; then
			printf '%bIs %b correct? | Y||y or N||n' "$(F_terminal_check)" "${tGRN}${2}${tCLR}"
		else
			printf '%b%s | Y||y or N||n' "$(F_terminal_check)" "$1"
		fi

		read -rsn1 ynentry
		case $ynentry in
			Y|y) return 0 ;;
			N|n) return 1 ;;
			E|e) F_menu_exit ;;
			*) F_fail_entry ;;
		esac
		break
	done
} ### confirm

F_menu_wait() {
			wait_time="$1"
			while [ "$wait_time" != '0' ] ; do
				printf "%b Loading menu in %s secs... any key to skip " "$tCHECK" "$wait_time"
				wait_time=$((wait_time - 1))
				waiting=zzz
				read -rsn1 -t1 waiting
				if [ ${#waiting} -le 1 ] ; then
					break
				fi
				printf '\r%b' "$tERASE"
			done
} ### menu_wait

# vars from user config below #########################################################################################
F_user_settings() {
	[ ! -f "$update_src" ] && F_default_update_create && F_chmod "$update_src"   # first run create core
	[ ! -f "$config_src" ] && F_default_create && F_chmod "$config_src"   # first run create user default

	source "$config_src"
	source "$update_src"

	F_terminal_color   # load user terminal settings
	F_integrity_check   # confirm configs are up to date re-source if updated
	F_settings_test   # sets var if valid configured config_src exists or not (used by Menu and F_ready_check for autorun)

	user_custom_subject_decoded="$(echo "$user_custom_subject" | /usr/sbin/openssl base64 -d)"
	user_custom_text_decoded="$(echo "$user_custom_text" | /usr/sbin/openssl base64 -d)"
	user_custom_script_decoded="$(echo "$user_custom_script" | /usr/sbin/openssl base64 -d)"

	if [ "$user_custom_script_time" = 'i' ] || [ "$user_custom_script_time" = 'I' ] ; then
		user_script_call_time='immediate'
	elif [ "$user_custom_script_time" = 'w' ] || [ "$user_custom_script_time" = 'W' ] ; then
		user_script_call_time='wait'
	fi

	original_wan_ip="$(grep 'saved_wan_ip' 2>/dev/null < "$config_src" | grep -Eo "$ip_regex")"
	original_wan_date="$(grep 'saved_wan_date' 2>/dev/null < "$config_src" | cut -d'=' -f2 | tr -d "'")"
	original_wan_epoch="$(grep 'saved_wan_epoch' 2>/dev/null < "$config_src" | cut -d'=' -f2 | tr -d "'")"

	if [ "$update_cron_epoch" -gt 0 ] ; then update_diff=$((run_epoch - update_cron_epoch)) ; else update_diff="$update_period" ; fi   # update_cron_epoch comes from core config (default=0)

}   # function to be reloadable on restore

# firmware check ######################################################################################################
F_firmware_check() {
	if [ "$build_no" = '374' ] ; then john_sub=${build_extend:0:2} ; fi

	if [ "$build_no" != '386' ] || [ "$build_no" = '384' ] && [ "$build_sub" -lt 15 ] || [ "$build_no" = '374' ] && [ "$john_sub" -lt 48 ] ; then
		F_terminal_header
		F_terminal_check_fail "Sorry this version of firmware is not compatible, please update to 384.15 or newer, or 374 LTS release 48 or newer to utilize this script"
		F_terminal_padding
		rm -d "$script_dir"
		F_clean_exit
	else
		pulled_device_name="$(F_nvram_get lan_hostname)"
		pulled_lan_name="$(F_nvram_get lan_domain)"
		if [ -z "$(F_nvram_get odmpid)" ] ; then device_model="$(F_nvram_get productid)" ; else device_model="$(F_nvram_get odmpid)" ; fi

		F_replace_var fw_pulled_device_name "$pulled_device_name" "$update_src"
		F_replace_var fw_pulled_lan_name "$pulled_lan_name" "$update_src"
		F_replace_var fw_device_model "$device_model" "$update_src"
		F_replace_var fw_build_no "$build_no" "$update_src"
		if [ "$build_no" = '374' ] ; then F_replace_var fw_build_sub "$john_sub" "$update_src" ; else F_replace_var fw_build_sub "$build_sub" "$update_src" ; fi
		F_replace_var fw_build_extend "$build_extend" "$update_src"

		source "$update_src"

		if [ "$1" = 'fwupdate' ] ; then
			F_terminal_header ; F_terminal_padding
			F_log_show "core config v${update_settings_version} updated for new router firmware version"
			sleep 3
		else
			F_log "core config v${update_settings_version} updated with router config"
		fi
	fi
}

# alias ###############################################################################################################
F_alias() {
	if [ ! -f '/jffs/configs/profile.add' ] ; then
		echo "alias wicens=\"/bin/sh ${script_name_full}\"   # added by wicens $(F_date full)" > /jffs/configs/profile.add
	elif ! grep -q "alias wicens=" '/jffs/configs/profile.add' ; then
		echo "alias wicens=\"/bin/sh ${script_name_full}\"   # added by wicens $(F_date full)" >> /jffs/configs/profile.add
	fi
}   # alias   only checked on manual runs

# MENU OPTIONS ########################################################################################################
#######################################################################################################################

F_opt_about() {
	clear
	{   # start of | more
	printf "	WICENS - WAN IP Change Email Notification Script                     \n\n"

	printf "This script when configured will send an Email (1-4) at variable intervals \n"
	printf "X(second/minute/hour/day) to your Email(s) notifying you when your WAN IP  \n"
	printf "has changed.                                                             \n\n"

	printf "Supports GMail, Hotmail, Outlook, ISP based Email                        \n\n"

	printf "Supports AMTM Email config import                                        \n\n"

	printf "SMTP Email send formats available: \n"
	printf "sendmail - StartTLS v1.1 higher (eg. GMail port 587) \n"
	printf "sendmail - StartTLS v1 only \n"
	printf "curl     - SSL (eg GMail port 465) \n"
	printf "sendmail - SMTP plain auth (no encryption) \n"
	printf "sendmail - ISP based (no password reqd, generally port 25) \n\n"

	printf "IMPORTANT - If using GMail, you must use 2 factor authentication and setup \n"
	printf "an assigned App password in GMail for this script to use.                \n\n"

	printf "IMPORTANT - Your Email address(es) are stored as plain text within this    \n"
	printf "script.  Your Email password is encrypted and saved to router storage.     \n"
	printf "If you dont practice good security habits around your router ssh access,   \n"
	printf "this script might not be for you.                                        \n\n"

	printf "Script compares IP in NVRAM to saved IP with wancall connected events and  \n"
	printf "cron, cron is also a watchdog and monitors for failed Email attempts.      \n"
	printf "Should NVRAM IP be unavailable for whatever reason script will use         \n"
	printf "firmware built in getrealip.sh to retrieve your WAN IP using Google STUN   \n"
	printf "server.                                                                  \n\n"

	printf "Script will display a notification if an update is available.            \n\n"

	printf "All cron/wan-event entries are automatically created with this script    \n\n"

	printf "NTP sync must occur to update router date/time for proper script function\n\n"

	printf "### Technical ###\n\n"

	printf "Supports being used as an Email forwarder for other scripts, in your       \n"
	printf "script call /jffs/scripts/wicens.sh send {your email.txt path here}        \n"
	printf "ie. /jffs/scripts/wicens.sh send /tmp/email.txt                            \n"
	printf "Your email.txt should contain a Subject: Date: From: fields as headers     \n"
	printf "In your script when generating email.txt use                               \n"
	printf "echo \"Subject: My Email notification\" >> /tmp/email.txt                  \n"
	printf "echo \"Date: \$(/bin/date -R)\" >> /tmp/email.txt                          \n"
	printf "echo \"From: Myscript\" >> /tmp/email.txt                                  \n"
	printf "echo \"\"                                                                \n\n"
	printf "Ensure there is 1 line space between header info and text body.          \n\n"

	printf "Should Email sending fail with either WAN IP change or forwarder the       \n"
	printf "script will retry 4 more times with cron (1/10min) in 6 hour intervals.    \n"
	printf "If FW update or script update Emails fail 5 times it will give up trying.  \n"

	printf "Script generates a lock file in /tmp called wicens.lock to prevent         \n"
	printf "duplicate runs as well as another file in /tmp called wicenssendmail.lock  \n"
	printf "when sending Email notifications. Script will automatically remove (with   \n"
	printf "cron) stale lock files if original starting process no longer exists or    \n"
	printf "lock files are over age limit. \n\n"

	printf "Sendmail/Curl output for Emails is saved to /tmp/wicenssendmail.log for    \n"
	printf "debugging if needed.  This file can be viewed by running this script and   \n"
	printf "select option L||l \n\n"

	printf "Sendmail doesnt always return an error code on a misconfiguration so false \n"
	printf "send success can occur.  If script says Email has sent but no Email received\n"
	printf "use option L||l from the Main Menu to read sendmail output for errors\n\n"

	printf "The script does not update its saved WAN IP until the script has completed \n"
	printf "sending all notifications and adds to the Email message of success or      \n"
	printf "failure	in updating it, so in the event of message failure it should run   \n"
	printf "again with next cron run and attempt to send again.\n\n"

	printf "Using option 4 you can call your own script either immediately upon WAN IP \n"
	printf "change detection, or wait until all Email messages have been sent and      \n"
	printf "script has successfully updated. Script will be put in background as to not\n"
	printf "block this script \n\n"

	printf "Every Sunday the script will log the number of calls from wan-event.     \n\n"

	printf "Thank you for using this script. \n\n"
	
	printf "SNBforums thread https://www.snbforums.com/threads/wicens-wan-ip-change-email-notification-script.69294/ \n\n"
	} | more
	F_menu_exit
} ### about

F_opt_amtm() {
	if [ "$1" = 'check' ] ; then
		if [ -f "$amtm_email_conf" ] ; then   # check vars without sourcing file
			for var_set_check in FROM_ADDRESS TO_NAME TO_ADDRESS FRIENDLY_ROUTER_NAME USERNAME SMTP PORT PROTOCOL ; do
				pull_var="$(grep "$var_set_check" $amtm_email_conf | cut -d"=" -f2 | tr -d '"')"
				[ -z "$pull_var" ] && return 1
			done

			# ensure pswd file exists
			if [ -f "$amtm_cred_loc" ] ; then
				return 0
			else
				return 1
			fi
		else
			return 1
		fi

	elif [ "$1" = 'import' ] ; then
		building_settings='yes'
		F_terminal_header ; F_terminal_padding
		if [ "$2" = 'update' ] ; then
			F_terminal_header
			F_log_show "Detected updated AMTM config, updating wicens"
		fi

		source "$amtm_email_conf"

		# write AMTM config to wicens
		F_replace_var user_from_addr "$USERNAME" "$config_src"
		F_terminal_check_ok "Imported send from/login address - $USERNAME"
		F_sleep
		F_replace_var user_send_to_addr "$TO_ADDRESS" "$config_src"
		F_terminal_check_ok "Imported send to address - $TO_ADDRESS"
		F_sleep
		F_replace_var user_from_name "$FRIENDLY_ROUTER_NAME" "$config_src"
		F_terminal_check_ok "Imported from name - $FRIENDLY_ROUTER_NAME"
		F_sleep
		F_replace_var user_smtp_server "${SMTP}:${PORT}" "$config_src"
		F_terminal_check_ok "Imported server address/port - ${SMTP}:${PORT}"
		F_sleep
		F_replace_var user_message_type "smtp_ssl" "$config_src"
		F_terminal_check_ok "Set server type to SSL req'd"
		F_sleep
		if [ "$2" != 'update' ] ; then   # dont overwrite if updating, user may have changed in wicens menu
			F_replace_var user_message_count "1" "$config_src"
			F_terminal_check_ok "Set Email message count to 1 notification"
			F_sleep
		fi
		F_replace_var protocol "$PROTOCOL" "$config_src"
		F_terminal_check_ok "Imported server protocol - $PROTOCOL"
		F_sleep
		if [ -n "$SSL_FLAG" ] ; then
			F_replace_var ssl_flag "$SSL_FLAG" "$config_src"
			F_terminal_check_ok "Imported SSL flag $SSL_FLAG"
		fi

		# pswd not found warning, should never hit this
		if [ ! -f "$amtm_cred_loc" ] ; then
			F_terminal_check_fail "Error, missing Email password from AMTM"
			F_terminal_show "Configure Email login password from wicens menu"
		else
			amtm_pswd="$(eval "$(echo "$amtm_d" | openssl base64 -d)" )"
			user_pswd_encrypt="$(echo "$amtm_pswd" | eval "$(echo "$user_e" | openssl base64 -d)" )"

			if [ -n "$user_pswd_encrypt" ] ; then
				echo "$user_pswd_encrypt" > "$cred_loc"
				F_chmod "$cred_loc"
				F_log_terminal_ok "Imported password successfully encrypted and saved"
			else
				F_log_terminal_fail "Failed decrypting/encrypting saved AMTM password"
				F_terminal_show "Configure Email login password from wicens menu"
			fi
			amtm_pswd=
			user_pswd_encrypt=
		fi

		# set imported flag, change script configured date
		F_replace_var amtm_import 0 "$config_src"
		F_replace_var created_date "$(F_date full)" "$config_src"
		F_log_terminal_ok "Import complete"
		echo "# Imported from AMTM config on $run_date" >> "$config_src"

		source "$config_src"

		[ -z "$saved_wan_ip" ] && F_saved_wan_ip_create

		# below only with new import
		if [ "$2" != 'update' ] && [ "$passed_options" = 'manual' ] ; then
			F_terminal_check_ok "Enabling WAN IP notifications..."
			F_auto_run add

			F_terminal_padding ; F_terminal_check "T||t Send Test Email - E||e Exit - Any key to return to the Main Menu"

			read -rsn1 setupwait
			case $setupwait in
				t|T) rm -f "$script_lock" && exec /bin/sh "$script_name_full" test ;;
				E|e) printf "\r%b" "$tERASE" && F_clean_exit ;;
				*) F_clean_exit reload ;;
			esac
		fi

	elif [ "$1" = 'confirm' ] ; then
		source "$amtm_email_conf"

		# sync check
		if [ "$user_from_addr" != "$USERNAME" ] || [ "$user_send_to_addr" != "$TO_ADDRESS" ] || \
		   [ "$user_from_name" != "$FRIENDLY_ROUTER_NAME" ] || [ "$user_smtp_server" != "${SMTP}:${PORT}" ] || \
		   [ "$user_message_type" != "smtp_ssl" ] || [ "$protocol" != "$PROTOCOL" ] || \
		   [ "$ssl_flag" != "$SSL_FLAG" ] ; then
				F_opt_amtm import update
				[ "$passed_options" = 'manual' ] && F_menu_wait 10
		fi

		# sync pswd check
		amtm_pswd="$(eval "$(echo "$amtm_d" | openssl base64 -d)" )"
		user_pswd_enc="$(echo "$amtm_pswd" | eval "$(echo "$user_e" | openssl base64 -d)" )"
		user_pswd="$(eval "$(echo "$user_d" | openssl base64 -d)" < "$cred_loc")"

		if [ "$amtm_pswd" != "$user_pswd" ] ; then
			F_terminal_header
			F_log_terminal_ok "Detected new saved password in AMTM, updated wicens with new password"
			echo "$user_pswd_enc" > "$cred_loc"
			sync_updated='Y'
		fi

		amtm_pswd=
		user_pswd_enc=
		user_pswd=

		[ "$passed_options" != 'cron' ] || [ "$passed_options" != 'wancall' ] && [ "$sync_updated" = 'Y' ] && F_menu_wait 10
	fi
} ### amtm_import

F_opt_backup_restore() {

	F_backup() {
		if [ -f "$script_backup_file" ] ; then
			while true; do
				F_terminal_warning ; F_terminal_padding
				F_terminal_show "Backup file exists, Y||y to overwrite - Any key to return to Main Menu"
				read -rsn1 configremove
				case $configremove in
					y|Y) rm -f "$script_backup_file" ; printf "%b" "$tBACK$tERASE" ;;
					*) F_clean_exit reload;;
				esac
				break
			done
		fi

		F_terminal_check "Starting backup"
		if cp "$config_src" "$script_backup_file" ; then
			F_terminal_check_ok "Backup successful, saved to $script_backup_file"
			echo "# Backup created $(F_date full)" >> "$script_backup_file"
			if [ -f "$history_src" ] ; then
				cp "$history_src" "$history_src_backup"
			fi

			if [ "$user_message_type" != 'smtp_isp_nopswd' ] ; then
				if [ -f "$cred_loc" ] ; then
					if cp "$cred_loc" "$cred_loc_bak" ; then
						F_terminal_check_ok "Password backup successful"
					else
						F_terminal_check_fail"Error backing up password"
					fi
				else
					F_terminal_check_fail "Couldn't find password to backup"
				fi
			else
				# cleanup if smtp_isp_nopswd
				if [ -f "$cred_loc_bak" ] ; then
					rm -f "$cred_loc_bak"
				fi
			fi

		else
			F_terminal_check_fail "Critical error, backup failed, could not output to $script_backup_file"
		fi
		[ "$1" = 'resetbackup' ] && F_terminal_check "Any key to continue..." && read -rsn1 rstbakwait
	} # backup

	F_restore() {
		source "$script_backup_file"
		F_status
		F_terminal_show "File history:"
		sed -n "/# Created/,/&/p" "$script_backup_file"
		F_terminal_padding

		if ! F_confirm "Do you wish to restore this config?" ; then
			F_terminal_check_ok "No received, exiting..."
			F_menu_exit
		fi

		F_terminal_check_ok "Ok received"
		F_terminal_check "Restoring backup"
		if cp -f "$script_backup_file" "$config_src" ; then
			echo "# File restored from backup on $(F_date full)" >> "$config_src"
			F_replace_var created_date "$(F_date full)" "$config_src"
			source "$config_src"

			if [ -f "$history_src_backup" ] ; then
				cp "$history_src_backup" "$history_src"
			fi

			F_user_settings   # reload custom_decoded etc for status

			if [ "$user_fw_update_notification" = '0' ] ; then
				F_fw_updates add
			fi

			F_status
			F_terminal_padding ; F_terminal_check_ok "Done restoring backup settings to script"

			if [ "$user_message_type" != 'smtp_isp_nopswd' ] ; then
				if [ -f "$cred_loc_bak" ] ; then
					if cp "$cred_loc_bak" "$cred_loc" ; then
						F_terminal_check_ok "Successfully restored backed up password"
					else
						F_terminal_check_fail "Error restoring backed up password"
					fi
				else
					F_terminal_check_fail "Error, no backed up password found, use Main Menu option P||p"
				fi
			fi

			F_terminal_check_ok "Enabling WAN IP notifications..."
			F_auto_run add

		else
			F_terminal_check_fail "Critical error copying backup to script"
		fi
	} # restore

	[ "$1" = 'resetbackup' ] && F_backup resetbackup && return 0   # from F_reset valid config incase want to save before reset
	F_terminal_header ; F_terminal_padding
	printf "%bBackup/Restore Settings Menu %b \n" "$tTERMHASH $tYEL" "$tCLR"  ; F_terminal_padding

	if [ "$settings_test" != 'OK' ] && [ ! -f "$script_backup_file" ] ; then
		F_terminal_warning ; F_terminal_padding
		F_terminal_check_fail "Error invalid current settings and no backup found to restore"
		F_terminal_padding ; F_terminal_show "Use Menu option 1 to edit settings" ; F_terminal_padding
		F_menu_exit
	fi

	while true; do
		if [ -f "$script_backup_file" ] ; then
			F_terminal_check_ok "Backup found!        R||r to restore settings   D||d to delete backup" ; F_terminal_padding
		else
			F_terminal_check_fail "No backup found to restore" ; F_terminal_padding
		fi

		if [ "$settings_test" = 'OK' ] ; then
			F_terminal_check_ok "Valid config found!  B||b to backup current config" ; F_terminal_padding
		else
			F_terminal_check_fail "No valid config to backup, Main Menu option 1 to add a config" ; F_terminal_padding
		fi

		F_terminal_show "E|e to return to the Main Menu"
		F_terminal_padding ; F_terminal_check "Selection : "

		read -r bandrwait
		case $bandrwait in
			D|d) printf '%b' "$tBACK$tERASE"
				F_terminal_check_ok "Delete backup selected"
				F_terminal_padding
				F_terminal_warning
				if ! F_confirm "This will delete your backup, are you sure?" ; then
					F_terminal_check_ok "No received, exiting..."
					F_menu_exit
				fi

				if [ -f "$script_backup_file" ] ; then
					rm -f "$script_backup_file"
					F_terminal_check_ok "Saved backup removed"
					[ -f "$cred_loc_bak" ] && rm -f "$cred_loc_bak"
					F_menu_exit
				 else
					F_terminal_check_fail "Error, no saved backup to delete" ; F_terminal_padding
					F_terminal_check "Any key to return to the Main Menu"
					read -rsn1 nobackupwait
					F_clean_exit reload
				 fi
				 ;;
			B|b) if [ "$settings_test" != 'OK' ] ; then
					F_terminal_check_fail "Error, no valid config found to backup"
					F_terminal_padding ; F_terminal_check "Any key to return to the Main Menu"
					read -rsn1 backupwait
					F_clean_exit reload
				else
					printf '%b' "$tBACK$tERASE"
					F_terminal_check_ok "B selected for backup"
					F_backup
					F_menu_exit
				fi
				;;
			R|r) if  [ -f "$script_backup_file" ] ; then
					printf '%b' "$tBACK$tERASE"
					F_terminal_check_ok "R selected for restore"
					F_restore
					F_menu_exit
				else
					printf '%b' "$tBACK$tERASE"
					F_terminal_check_fail "Invalid entry, no valid backup exists"
					read -rsn1 invalwait
					F_opt_backup_restore
					continue
				fi
				;;
			E|e) F_clean_exit reload ;;
			*) F_terminal_check_fail "Invalid entry, B/R/D - any key to retry, E return to Main Menu"
				read -rsn1 brinvalid
				case $brinvalid in
					e|E) F_clean_exit reload ;;
					*) F_opt_backup_restore ;;
				esac
				;;
		esac
		break
	done
} ### backup_restore

F_opt_color() {
	F_terminal_padding

	if [ "$opt_color" = 'yes' ] ; then
		printf '%b' "$tBACK"
		F_terminal_check "Setting script to no color mode"
		F_replace_var opt_color "no" "$config_src"
		F_terminal_check_ok "Done, set to no color mode, return to the Main Menu to view changes"

	elif [ "$opt_color" = 'no' ] ; then
		printf '%b' "$tBACK"
		F_terminal_check "Setting script to color mode"
		F_replace_var opt_color "yes" "$config_src"
		F_terminal_check_ok "Done, set to color mode, return to the Main Menu to view changes"
	fi

	F_menu_exit
} ### color

F_opt_count() {
	F_terminal_header
	printf "%b %bCounts Reset Menu%b\n" "$tTERMHASH" "$tYEL" "$tCLR" ; F_terminal_padding
	F_terminal_header_print "Number of cron checks            : " "$cron_run_count"
	F_terminal_header_print "Number of wan-event checks       : " "$wancall_run_count"
	[ -n "$last_cron_run" ] && F_terminal_header_print "Last monitored with cron         : " "$last_cron_run"
	[ -n "$last_wancall_run" ] && F_terminal_header_print "Last ran with wan-event          : " "$last_wancall_run"
	[ -n "$last_ip_change" ] && F_terminal_header_print "Last IP change                   : " "$last_ip_change"
	F_terminal_header_print "IP changes recorded              : " "$ip_change_count"
	F_terminal_header_print "Script configured on             : " "$created_date"
	F_terminal_show '---------------------------------------------------------------------'
	F_terminal_padding
	F_terminal_warning
	F_terminal_show "This will reset cron/wan-event check counts and configured date"
	F_terminal_padding

	if F_confirm "Are you sure you wish to reset?" ; then
		F_terminal_check_ok "Ok received, resetting counts..."
		F_terminal_check "Resetting script wan-event/cron count and install date"
		F_replace_var cron_run_count 0 "$config_src"
		F_replace_var last_cron_run "''" "$config_src"
		F_replace_var wancall_run_count 0 "$config_src"
		F_replace_var last_wancall_run "''" "$config_src"
		F_replace_var last_wancall_log_count 0 "$config_src"
		F_replace_var created_date "$(F_date full)" "$config_src"
		F_log_terminal_ok "Reset cron count, wan-event count and configured date"

		if [ -n "$last_ip_change" ] ; then
			if F_confirm "Do you want to reset last recorded WAN IP change date and count?" ; then
				F_replace_var last_ip_change "never" "$config_src"
				F_replace_var ip_change_count 0 "$config_src"
				F_log_terminal_ok "Reset last recorded WAN IP change date"
			else
				F_terminal_check_ok "Keeping WAN IP change records"
			fi
		fi

		if [ -f "$history_src" ] ; then
			if F_confirm "Do you want to remove historical WAN IP change file?" ; then
				rm -f "$history_src"
			else
				F_terminal_check_ok "Keeping historical WAN IP change records"
			fi
		fi
	else
		F_terminal_check_ok "No received, exiting..."
	fi

	F_menu_exit
} ### count

F_opt_custom() {
	F_terminal_header
	printf "%b %bCustom Text Entry Menu - E||e to exit%b\n" "$tTERMHASH" "$tYEL" "$tCLR" ; F_terminal_padding

	F_ready_check options

	if [ -z "$user_custom_text" ] ; then
		F_terminal_show "Enter your line of custom plain text to add to the Email message(s)"
		F_terminal_show "eg.  Router hidden in moms closet, 2 vpn clients to update"
		F_terminal_show "Entry must be one line, can use \\n to create new line in Email msg"
		F_terminal_padding ; F_terminal_entry "Text : "

		read -r user_custom_text_entry
		F_terminal_padding
		# ensure we empty any saved vars if brought here by N new entry but left entry blank
		[ -z "$user_custom_text_entry" ] && F_replace_var user_custom_text "" "$config_src" && return 0
		case $user_custom_text_entry in
			e|E) F_menu_exit ;;
		esac

		if F_confirm correct "$user_custom_text_entry" ; then
			custom_text_encoded="$(echo "$user_custom_text_entry" | /usr/sbin/openssl base64 | tr -d '\n')"   # base64 no worries of sed conflicts
			if F_replace_var user_custom_text "$custom_text_encoded" "$config_src" ; then
				F_terminal_check_ok "Done writing custom text to script"
				user_custom_text="$user_custom_text_entry"
			else
				F_terminal_check_fail "Error, sed failed writing custom text to script"
			fi
		else
			return 1
		fi

	else
		F_terminal_show "Custom text already set :" ; F_terminal_padding
		F_terminal_show "$user_custom_text_decoded" ; F_terminal_padding

		while true ; do
			F_terminal_check "Y||y keep - N||n enter new - R||r remove current "

			read -rsn1 yesornowremove
			case $yesornowremove in
				Y|y) F_terminal_check_ok "Keeping currently saved custom text" ;;
				N|n) user_custom_text='' ; return 1 ;;
				R|r) if F_replace_var user_custom_text "" "$config_src" ; then
						F_terminal_check_ok "Done, custom text cleared"
						user_custom_text=''
					else
						F_terminal_check_fail "Error, sed failed to reset custom text"
						F_clean_exit
					fi
					;;
				E|e) F_menu_exit ;;
				*) F_terminal_check_fail "Invalid entry, Y||y N||n R||r - Any to key to retry"
					read -rsn1 invalidwait
					printf "%b" "$tBACK$tERASE"
					continue
					;;
			esac
			break
		done
	fi
} ### custom_text

F_opt_disable() {
	F_terminal_header
	printf "%b %bWAN IP notification disable Menu%b \n\n" "$tTERMHASH" "$tYEL" "$tCLR"
	F_terminal_warning
	F_terminal_show "This will remove all auto start entries in wan-event, cron, and"
	F_terminal_show "services-start. Saved configuration will be kept."
	F_terminal_show "You will not receive an Email notification if your WAN IP changes."
	F_terminal_show "Nor will you receive notification of script updates if enabled."
	F_terminal_show "Firmware update notifications will continue if enabled."
	F_terminal_show "Use Main Menu option M||m to re-enable notifications." ; F_terminal_padding

	if F_confirm "Are you sure you wish to disable?" ; then
		F_terminal_check_ok "Ok received, disabling..."
		F_auto_run remove
	else
		F_terminal_check_ok "No received, exiting..."
	fi

	F_menu_exit
} ### disable

F_opt_error() {
	if [ -f "$mail_log" ] ; then
		F_terminal_show "Contents of last Email send log : "
		more < "$mail_log"
		F_terminal_padding
		F_terminal_check_ok "End of contents."
		F_menu_exit
	else
		F_terminal_show "No log file found"
		F_menu_exit
	fi
} # error

F_opt_forward() {
	[ -n "$fwd_send_addr" ] && user_send_to_addr="$fwd_send_addr"

	cp "$fwd_send_msg" "$wicens_send_copy" 2> /dev/null   # copy incase send fails and user has email removed in their script
	ln -s "$fwd_send_msg" "$mail_file"   # symlink user Email to script Email source
	rm -f "$mail_log" 2> /dev/null

	if [ ! -f "$wicens_send_retry" ] ; then
		{
			echo "#/bin/sh"
			echo "fwd_send_msg='${wicens_send_copy}'"
			echo "fwd_send_addr='${user_send_to_addr}'"
			echo "wicens_send_retry_time='${run_epoch}'"
			echo "# Attempting to send $fwd_send_msg to $user_send_to_addr $(F_date full)"
		} > "$wicens_send_retry"
		F_chmod "$wicens_send_retry"
	else
		echo "# Attempting to send $fwd_send_msg to $user_send_to_addr $(F_date full)" >> "$wicens_send_retry"
	fi

	internet_check_count=0
	until F_internet_check send ; do : ; done

	if ! F_send_message ; then
		F_log "Error, failed to send $fwd_send_msg Email to $user_send_to_addr"
		user_pswd=''
		rm -f "$mail_file"
		return 1
	fi

	user_pswd=''
	rm -f "$mail_file"
	rm -f "$wicens_send_retry"
	rm -f "$wicens_send_copy"
	F_log_terminal_ok "Success, finished sending $fwd_send_msg Email to $user_send_to_addr"
} ### forward

F_opt_fw_notifications() {
	if F_ready_check ; then
		if [ "$user_fw_update_notification" = 1 ] ; then
			if [ "$fw_build_no" = '374' ] ; then
				F_terminal_show "Sorry, this version of firmware is not compatible"
				F_menu_exit
			else
				F_fw_updates add
			fi
		elif [ "$user_fw_update_notification" = 0 ] ; then
			F_fw_updates remove
		fi
	else
		F_terminal_padding
		F_terminal_check_fail "Error, no/invalid Email settings, use Main Menu option 1 to edit settings"
	fi

	F_menu_exit
} # fw_notifications

F_opt_notifications() {
	if F_ready_check ; then
		if [ "$user_update_notification" = 1 ] ; then
			if F_auto_run checkall ; then
				F_log_terminal_ok "Enabling Email notifications for script updates"
				F_replace_var user_update_notification 0 "$config_src"
				F_menu_exit
			else
				F_log_terminal_fail "Error, WAN IP notifications MUST be enabled for script update notifications"
				F_menu_exit
			fi

		elif [ "$user_update_notification" = 0 ] ; then
			F_log_terminal_ok "Disabling Email notifications for script updates"
			F_replace_var user_update_notification 1 "$config_src"
			F_menu_exit
		fi
	else
		F_terminal_check_fail "Error, no/invalid Email settings, use Main Menu option 1 to edit settings"
		F_menu_exit
	fi
} # notifications

F_opt_manual() {
	F_ready_check
	F_status
	F_auto_run add

	if ! F_do_compare ; then
		F_send_mail
	fi
} ### manual run   called by option m in menu

F_opt_pswd() {
	if F_ready_check pswdset ; then
		until F_smtp_pswd ; do : ; done
		F_menu_exit
	fi
} ### pswd

F_opt_remove() {
	F_terminal_padding

	if [ -f "$script_lock" ] ; then
		process_id="$(/bin/sed -n '2p' "$script_lock")"   # pid
		process_created="$(/bin/sed -n '5p' "$script_lock")"   # started on

		if [ -d "/proc/$process_id" ] ; then # process that created exist
			F_terminal_show "Process exists attached to lock file.... killing process"
			/bin/kill -9 "$process_id" 2> /dev/null
			printf "%b Killed process %s and deleting lock file %s" "$tERASE$tCHECKOK" "$process_id" "$process_created"
			F_terminal_padding
			F_log "Killed old process $process_id and deleting lock file $process_created"
		fi

		F_terminal_check "Removing lock file 1 of 2"
		rm -f "$script_lock"
		F_terminal_check_ok "Removed lock file 1 of 2 "

	else
		F_terminal_check_fail "1st lock file not present"
	fi

	F_terminal_check "Removing lock file 2 of 2"

	if [ -f "$script_mail_lock" ] ; then
		rm -f "$script_mail_lock"
		F_terminal_check_ok "Removed lock file 2 of 2 "
	else
		F_terminal_check_fail "2nd lock file not present"
	fi

	F_terminal_check_ok "Exiting."
	F_terminal_padding
	exit 0
} ### remove

F_opt_reset() {
	if [ "$settings_test" = 'OK' ] ; then
		F_terminal_header
		printf "%b %bScript Reset Menu - E||e to Exit%b \n" "$tTERMHASH" "$tYEL" "$tCLR"
		F_terminal_padding
		F_terminal_warning
		F_terminal_check_ok "Found valid config" ; F_terminal_padding
		F_terminal_show "You're about to reset, would you like to make a backup?" ; F_terminal_padding

		while true; do
			F_terminal_check "B||b to create a backup, R||r to reset without backup, E||e to exit"

			read -rsn1 backup_wait
			case $backup_wait in
				B|b) F_terminal_header ; F_terminal_check_ok "Creating backup" ; F_opt_backup_restore resetbackup ;;
				R|r) break ;;
				E|e) F_clean_exit reload ;;
				*) F_fail_entry ;;
			esac
			break
		done
	fi

	F_terminal_header
	printf "%b %bScript Reset Menu%b \n" "$tTERMHASH" "$tYEL" "$tCLR"
	F_terminal_padding
	F_terminal_warning

	F_terminal_show "This will reset wicens to default and remove all"
	F_terminal_show "saved settings and records including entires in"
	F_terminal_show "services-start/wan-event/cron/update-notification" ; F_terminal_padding

	if F_confirm "Are you sure you wish to reset?" ; then
		F_terminal_header
		F_terminal_check_ok "Ok received, resetting..."
	else
		F_terminal_check_ok "No received, exiting..."
		F_menu_exit
	fi

	F_auto_run remove
	F_fw_updates remove

	[ -f "$cred_loc" ] && rm -f "$cred_loc" && F_log_terminal_ok "Removed saved password"
	[ -f "$config_src" ] && rm -f "$config_src" && F_log_terminal_ok "Reset user config to default"
	[ -f "$update_src" ] && rm -f "$update_src" && F_log_terminal_ok "Reset core config to default"
	[ -f "$history_src" ] && rm -f "$history_src" && F_log_terminal_ok "Removed WAN IP change history"
	F_log_terminal_ok "Done, script reset to default"
	[ -f "$mail_log" ] && rm -f "$mail_log"

	F_terminal_padding ; F_terminal_check "Any key to continue"
	read -rsn1 donewait
	F_clean_exit reset
} ### reset

F_opt_sample() {
	F_terminal_header
	F_terminal_show "Sample Email output:" ; F_terminal_padding
	current_wan_ip="x.x.x.x"   # fake for email
	passed_options='sample'   # for setup just fake running sample
	loop_run=1
	user_message_count=1
	test_mode="yes"
	F_email_message
	cat "$mail_file" ; F_terminal_padding
	rm -f "$mail_file"
	F_terminal_show "End of Email output"
	[ "$building_settings" != 'yes' ] && F_menu_exit
} ### sample

F_opt_script() {
	F_terminal_header
	printf "%b %bCustom Script Path Entry Menu - E||e to Exit%b \n" "$tTERMHASH" "$tYEL" "$tCLR" ; F_terminal_padding
	F_ready_check options

	if [ -z "$user_custom_script" ] ; then
		while true ; do
			F_terminal_show "Do you want your custom script to execute immediately on WAN IP"
			F_terminal_show "change detection, or wait till all Email messages configured"
			F_terminal_show "have finished sending" ; F_terminal_padding
			F_terminal_entry "W||w for wait    I||i for immediately : "

			read -r user_script_wait_entry
			case $user_script_wait_entry in
				w|W|I|i) if F_replace_var user_custom_script_time "$user_script_wait_entry" "$config_src" ; then
							F_terminal_check_ok "Done writing custom script execute time $user_script_wait_entry to script"
							user_custom_script_time="$user_script_wait_entry"
							if [ "$user_custom_script_time" = 'i' ] || [ "$user_custom_script_time" = 'I' ] ; then
								user_script_call_time='immediate'
							elif [ "$user_custom_script_time" = 'w' ] || [ "$user_custom_script_time" = 'W' ]; then
								user_script_call_time='wait'
							fi
						else
							F_terminal_check_fail "Error, sed failed writing custom script exec time to script"
							F_clean_exit
						fi ;;
				e|E) F_menu_exit ;;
				*) F_terminal_check_fail "Invalid entry, any key to retry" && read -rsn1 "invalidwait" && printf "%b" "$tBACK$tERASE$tBACK$tERASE$tBACK$tERASE$tBACK$tERASE$tBACK$tERASE" && continue ;;
			esac
			break
		done

		F_terminal_padding ; F_terminal_check "Any key to continue..."
		read -rsn1 waitscript

		F_terminal_header
		F_terminal_show "Custom Script Path Entry Menu" ; F_terminal_padding
		printf "%b Script execution set to : %b \n" "$tTERMHASH" "$user_script_call_time" ; F_terminal_padding
		F_terminal_show "Enter the full path to your script"
		F_terminal_show "eg. /jffs/scripts/customscript.sh" ; F_terminal_padding
		F_terminal_entry "Path : "

		read -r user_custom_script_entry
		F_terminal_padding

		case $user_custom_script_entry in
			E|e) F_replace_var user_custom_script_time "''" "$config_src"
				 user_script_call_time=
				 F_menu_exit
				 ;;
			"") F_terminal_check_fail "Script path cannot be empty - Any key to retry"
				read -rsn1 scriptempty
				F_opt_script
				;;
		esac

		if F_confirm correct "$user_custom_script_entry" ; then
			if [ ! -f "$user_custom_script_entry" ] ; then
				F_terminal_check_fail "Could not locate custom script"
				F_terminal_show "Any key to return to the Main Menu"
				F_replace_var user_custom_script_time "''" "$config_src"
				user_script_call_time=
				read -rsn1 nofind
				F_clean_exit reload
			fi

			custom_script_encoded="$(echo "$user_custom_script_entry" | /usr/sbin/openssl base64 | tr -d '\n')"   # base64 no worries of sed conflicts

			if F_replace_var user_custom_script "$custom_script_encoded" "$config_src" ; then
				F_terminal_check_ok "Done writing custom script path to script"
				user_custom_script="$user_custom_script_entry"
			else
				F_terminal_check_fail "Error, sed failed writing custom script path to wicens script"
				F_clean_exit
			fi
		else
			F_replace_var user_custom_script_time "''" "$config_src"
			return 1
		fi

	else
		F_terminal_show "Custom script path already set" ; F_terminal_padding
		F_terminal_show "$user_custom_script_decoded" ; F_terminal_padding

		while true ; do
			F_terminal_check "Y||y keep - N||n enter new - R||r remove current "

			read -rsn1 yesornowremove
			case $yesornowremove in
				Y|y) F_terminal_check_ok "Keeping currently saved custom script path" ;;
				N|n) user_custom_script='' ; return 1 ;;
				R|r) if F_replace_var user_custom_script "''" "$config_src" ; then
						F_replace_var user_custom_script_time "''" "$config_src"
						F_terminal_check_ok "Done, custom script path cleared"
						user_custom_script=''
					else
						F_terminal_check_fail "Error, sed failed to reset custom script path"
						F_clean_exit
					fi
					;;
				E|e) F_menu_exit ;;
				*) F_terminal_check_fail "Invalid entry, Y||y N||n R||r - Any to key to retry" ; read -rsn1 invalidwait ; printf "%b" "$tBACK$tERASE" ; continue
					;;
			esac
			break
		done
	fi
} ### script

F_opt_subject() {
	F_terminal_header ; printf "%b %bCustom Subject Menu - E||e to Exit%b \n" "$tTERMHASH" "$tYEL" "$tCLR" ; F_terminal_padding
	F_ready_check options

	if [ -z "$user_custom_subject" ] ; then
		F_terminal_show "Enter the text for a custom Email Subject line you wish to use"
		printf "%b Default Subject text is: %bWAN IP has changed on %s%b\n" "$tTERMHASH" "$tGRN" "$fw_device_model" "$tCLR"
		F_terminal_padding ; F_terminal_show "If you wish to use the new or current WAN IP, add the var names"
		F_terminal_show "\$current_wan_ip and \$saved_wan_ip to your text (like shown)"
		F_terminal_show "Model of router var is \$fw_device_model"
		F_terminal_padding ; F_terminal_entry "Subject: "

		read -r user_custom_subject_entry
		F_terminal_padding
		[ -z "$user_custom_subject_entry" ] && return 0
		case $user_custom_subject_entry in
			e|E) F_menu_exit ;;
		esac

		if F_confirm correct "$user_custom_subject_entry" ; then
			custom_subject_encoded="$(echo "$user_custom_subject_entry" | /usr/sbin/openssl base64 | tr -d '\n')"
			if F_replace_var user_custom_subject "$custom_subject_encoded" "$config_src" ; then
				user_custom_subject="$user_custom_subject_entry"
				F_terminal_check_ok "Done. user_custom_subject set to : $user_custom_subject_entry"
			else
				F_terminal_check_fail "Error, sed failed to write custom subject to script"
				F_clean_exit
			fi
		else
			return 1
		fi

	else
		F_terminal_show "Custom subject already set :" ; F_terminal_padding
		F_terminal_show "$user_custom_subject_decoded" ; F_terminal_padding

		while true; do
			F_terminal_check "Y||y keep - N||n enter new - R||r remove current "

			read -rsn1 yesornowremovesub
			case $yesornowremovesub in
				Y|y) F_terminal_check_ok "Keeping currently saved custom Email subject text" ;;
				N|n) user_custom_subject="" ; return 1 ;;
				R|r) if F_replace_var user_custom_subject "" "$config_src" ; then
						F_terminal_check_ok "Custom subject text cleared"
						user_custom_subject=
					else
						F_terminal_check_fail "Error, sed failed to clear custom subject text"
						F_clean_exit
					fi
					;;
				E|e) F_menu_exit ;;
				*) F_terminal_check_fail "Invalid entry, Y||y N||n R||r - Any to key to retry" && read -rsn1 invalidwait && printf "%b" "$tBACK$tERASE" && continue
					;;
			esac
			break
		done
	fi
} ### subject

F_opt_test() {
	test_mode="yes"
	user_message_count="1"
	F_log "Test mode started, sending test Email"
	current_wan_ip="x.x.x.x Test Mode"
	F_status
	printf "[%bFAIL%b] Current WAN IP is                : %b%s%b --- %bNo Match%b\n" "$tRED" "$tCLR" "$tRED" "$current_wan_ip" "$tCLR" "$tRED" "$tCLR"
	F_send_mail   # return to menu or exit in F_send_mail
	test_mode=''   # reset for terminal header
} ### test

F_opt_uninstall() {
	F_uninstall_do() {
		F_auto_run remove

		F_fw_updates remove

		[ -f "$script_lock" ] && rm -f "$script_lock"
		[ -f "$script_mail_lock" ] && rm -f "$script_mail_lock"
		[ -f "$mail_file" ] && rm -f "$mail_file"

		if [ -f "/jffs/configs/profile.add" ] ; then
			if grep -q "alias wicens=" '/jffs/configs/profile.add' ; then
				/bin/sed -i "/alias wicens=/d" '/jffs/configs/profile.add'
				[ ! -s '/jffs/configs/profile.add' ] && rm -f '/jffs/configs/profile.add'
			fi
		fi

		rm -r "$script_dir"
		rm -f "$script_name_full"
		F_terminal_check_ok "Done. Uninstalled" ; F_terminal_padding
		exit 0
	} # uninstall_do

	F_terminal_header ; F_terminal_warning ; F_terminal_show "This will remove the wicens script ENTIRELY from your system"
	F_terminal_show "And any backup configs" ; F_terminal_padding

	while true; do
		F_terminal_show "Are you sure you wish to uninstall? Type DELETE"
		F_terminal_padding ; F_terminal_check "Entry : "

		read -r uninstall_wait
		case $uninstall_wait in
			'DELETE'|'delete') F_terminal_check_ok "Uninstalling"
								F_terminal_padding
								F_uninstall_do
								;;
			*) F_terminal_check_ok "Must type DELETE to uninstall"
				F_menu_exit
				;;
		esac
		break
	done
} ### uninstall

# BUILD USER SETTINGS FUNCTIONS #######################################################################################
#######################################################################################################################

#requires being passed a line # for head to terminate on
F_terminal_entry_header() { F_status | head -n "$1" ; F_terminal_separator ; F_terminal_padding ;}

# all user entry functions called by until loops and return 1 for failed input and restart or return 0 with completed Y in while loop
F_send_to_addr() {
	F_terminal_entry_header 16
	F_terminal_show "Enter the Email address you wish to send a notification Email(s)"
	F_terminal_show "to when your WAN IP changes"
	F_terminal_show "eg.  myrecipient@myemail.com"
	[ -n "$user_send_to_addr" ] && F_terminal_padding && printf "%b Currently set to : %b%s%b \n" "$tTERMHASH" "$tGRN" "$user_send_to_addr" "$tCLR" && F_terminal_show "Leave entry blank to keep current"
	F_terminal_padding ; F_terminal_entry "Send to address : "

	read -r send_to_entry
	[ -z "$user_send_to_addr" ] && [ -z "$send_to_entry" ] && F_terminal_check_fail "Error, Email send to address cannot be empty - Any key to retry" && read -rsn1 waitsendto && return 1
	[ -z "$send_to_entry" ] && [ -n "$user_send_to_addr" ] && return 0
	case $send_to_entry in
		E|e) F_menu_exit ;;
	esac
	F_terminal_padding

	if F_confirm correct "$send_to_entry" ; then
		F_replace_var user_send_to_addr "$send_to_entry" "$config_src"
		user_send_to_addr="$send_to_entry"
	else
		send_to_entry=''
		return 1
	fi
} ### send_to_addr

F_send_to_cc() {
	if [ -n "$user_send_to_cc" ] ; then
		F_terminal_entry_header 17
		printf "%b Second Email recipient already set to : %b%s%b \n\n" "$tTERMHASH" "$tGRN" "$user_send_to_cc" "$tCLR" ; F_terminal_padding

		while true; do
			F_terminal_check "Y||y keep - N||n enter new - R||r remove current & skip to server entry"   # for edits can remove 2nd email if wanted.
			read -rsn 1 ccmailwait2
			case $ccmailwait2 in
				Y|y) return 0 ;;
				N|n) user_send_to_cc= ; return 1 ;;
				R|r) F_replace_var user_send_to_cc "" "$config_src" && user_send_to_cc= && return 0 ;;
				E|e) F_menu_exit ;;
				*) F_terminal_check_fail "Invalid Entry , Y||y N||n R||r - Any key to retry" ; read -rsn1 "invalidwait" ; printf "%b" "$tBACK$tERASE" ; continue ;;
			esac
			break
		done

	else
		F_terminal_entry_header 17
		F_terminal_show "Enter a 2nd Email address you wish to send a notification Email(s)"
		F_terminal_show "to when your WAN IP changes"
		F_terminal_show "eg.  my2ndrecipient@myemail.com"
		F_terminal_padding ; F_terminal_show "Leave entry blank to leave CC option empty and continue"
		F_terminal_padding ; F_terminal_entry "Send to CC address : "

		read -r send_to_cc_entry
		[ -z "$send_to_cc_entry" ] && return 0
		case $send_to_cc_entry in
			E|e) F_menu_exit ;;
		esac
		F_terminal_padding

		if F_confirm correct "$send_to_cc_entry" ; then
			F_replace_var user_send_to_cc "$send_to_cc_entry" "$config_src"
			user_send_to_cc="$send_to_cc_entry"
		else
			user_send_to_cc=''
			return 1
		fi

	fi
} ### send_to_cc

F_smtp_server() {
	F_terminal_entry_header 18
	F_terminal_show "Enter the SMTP server address and port # like as shown for your"
	F_terminal_show "Email provider - eg.  smtp.myemailprovider.com:25"
	[ -n "$user_smtp_server" ] && F_terminal_padding && printf "%b Currently set to : %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_smtp_server" "$tCLR" && F_terminal_show "Leave entry blank to keep current"
	F_terminal_padding ; F_terminal_entry "Server address and port : "

	read -r smtp_server_entry
	[ -z "$user_smtp_server" ] && [ -z "$smtp_server_entry" ] && F_terminal_check_fail "Error, Server address cannot be empty - Any key to retry" && read -rsn1 waitsmtpserv && return 1
	[ -z "$smtp_server_entry" ] && [ -n "$user_smtp_server" ] && return 0
	case $smtp_server_entry in
		E|e) F_menu_exit ;;
	esac
	F_terminal_padding

	if F_confirm correct "$smtp_server_entry" ; then
		F_replace_var user_smtp_server "$smtp_server_entry" "$config_src"
		user_smtp_server="$smtp_server_entry"
	else
		smtp_server_entry=''
		return 1
	fi
} ### smtp_server

F_send_type() {
	F_terminal_entry_header 19
	F_terminal_show "SMTP Email server send configuration type"
	F_terminal_show "for $user_smtp_server                                    Selection"
	F_terminal_padding
	F_terminal_show "WITH password and StartTLS - eg.GMail(587)/Hotmail/Outlook - 1"
	F_terminal_show "WITH password and SSL required - eg.GMail(465)             - 2"
	F_terminal_show "ISP type with NO password and NO StartTLS/SSL-eg.port 25   - 3"
	F_terminal_show "WITH password and NO StartTLS or SSL (plain auth)          - 4"
	F_terminal_show "WITH password and StartTLS v1                              - 5"
	[ -n "$user_message_type" ] && F_terminal_padding && printf "%b Currently set to : %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_message_type" "$tCLR" && F_terminal_show "Leave selection blank to keep current setting"
	F_terminal_padding ; F_terminal_entry "Selection : "

	read -r send_type_entry
	case $send_type_entry in
		1|2|3|4|5) ;;
		"") if [ -n "$user_message_type" ] ; then
				return 0
			else
				F_terminal_check_fail "Invalid entry, 1,2,3,4,5 only - Any key to retry" && read -rsn1 smtpinvalidwait && return 1
			fi
			;;
		e|E) F_menu_exit ;;
		*) F_terminal_check_fail "Invalid Entry, 1,2,3,4,5 only - Any key to retry" && read -rsn1 smtpinvalidwait && return 1 ;;
	esac

	F_terminal_padding

	if ! F_confirm correct "$send_type_entry" ; then
		send_type_entry=''
		return 1
	fi

	[ "$send_type_entry" = "1" ] && F_replace_var user_message_type "smtp_start_tls" "$config_src" && user_message_type="smtp_start_tls"
	[ "$send_type_entry" = "2" ] && F_replace_var user_message_type "smtp_ssl" "$config_src" && user_message_type="smtp_ssl"
	[ "$send_type_entry" = "3" ] && F_replace_var user_message_type "smtp_isp_nopswd" "$config_src" && user_message_type="smtp_isp_nopswd"
	[ "$send_type_entry" = "4" ] && F_replace_var user_message_type "smtp_plain_auth" "$config_src" && user_message_type="smtp_plain_auth"
	[ "$send_type_entry" = "5" ] && F_replace_var user_message_type "smtp_start_tls_v1" "$config_src" && user_message_type="smtp_start_tls_v1"

	if [ "$user_message_type" != 'smtp_isp_nopswd' ] && [ "$user_message_type" != 'smtp_plain_auth' ] ; then
		F_terminal_header ; F_terminal_padding ; F_terminal_warning
		F_terminal_show "If using GMail for your sending service you must have"
		F_terminal_show "2 factor authentication enabled and create a App"
		F_terminal_show "password for this script to use"
		F_terminal_padding ; F_terminal_check "Any key to continue" && read -rsn1 notify_wait
	fi

	return 0
} ### send_type

F_from_email_addr() {
	F_terminal_entry_header 20
	F_terminal_show "Enter the Email send from (login) address for your Email provider"
	F_terminal_show "eg.  myemail@myemailprovider.com  for $user_smtp_server"
	[ -n "$user_from_addr" ] && F_terminal_padding && printf "%b Currently set to : %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_from_addr" "$tCLR" && F_terminal_show "Leave entry blank to keep current"
	F_terminal_padding ; F_terminal_entry "From Email addr : "

	read -r from_email_addr_entry
	[ -z "$user_from_addr" ] && [ -z "$from_email_addr_entry" ] && F_terminal_check_fail "Error, from(login) address cannot be empty - Any key to retry" && read -rsn1 waitfromemail && return 1
	[ -z "$from_email_addr_entry" ] && [ -n "$user_from_addr" ] && return 0
	case $from_email_addr_entry in
		E|e) F_menu_exit ;;
	esac
	F_terminal_padding

	if F_confirm correct "$from_email_addr_entry" ; then
		F_replace_var user_from_addr "$from_email_addr_entry" "$config_src"
		user_from_addr="$from_email_addr_entry"
	else
		from_email_addr_entry=''
		return 1
	fi
} ### from_email_addr

F_from_name() {
	if [ -z "$user_from_name" ] ; then   # tries to auto generate a from name on first run
		if [ -n "$fw_pulled_device_name" ] && [ -n "$fw_pulled_lan_name" ] ; then
			user_from_name="${fw_pulled_device_name}.${fw_pulled_lan_name}"
		else
			user_from_name="$fw_device_model"
		fi
	fi

	F_terminal_entry_header 21
	F_terminal_show "Enter the message 'from name' for the notification Email"
	[ -n "$user_from_name" ] && F_terminal_padding && printf "%b Currently set to : %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_from_name" "$tCLR" && F_terminal_show "Leave entry blank to keep current"
	F_terminal_padding ; F_terminal_entry "Email from name : "

	read -r from_name_entry
	[ -z "$user_from_name" ] && [ -z "$from_name_entry" ] && F_terminal_show "Error, Script could not auto-fill from name, cannot be blank, any key to retry" && read -rsn1 waitfromname && return 1
	case $from_name_entry in
		E|e) F_menu_exit ;;
	esac
	F_terminal_padding

	# first run set if user accepts autofill
	user_set_check="$(grep "user_from_name" $config_src | cut -f2 -d"=" | tr -d "'")"
	[ -z "$user_set_check" ] && F_replace_var user_from_name "$user_from_name" "$config_src" && return 0

	[ -n "$user_set_check" ] && [ -z "$from_name_entry" ] && return 0

	if F_confirm correct "$from_name_entry" ; then
		F_replace_var user_from_name "$from_name_entry" "$config_src"
		user_from_name="$from_name_entry"
	else
		from_name_entry=''
		return 1
	fi
} ### from_name

F_smtp_pswd() {

	F_pswd_entry() {   # replaces typed chars with * sets var through openssl then sed output to script
		old_ifs=$IFS
		charcount=1

		while IFS= read -rsn1 char ; do   # -s or terminal will leave last char, easier this way
			if [ -z "$char" ] ; then   # enter hit
				[ "$charcount" -eq 1 ] && printf '\n' || printf '\b*\n'
				break
			fi

			if [ "$char" = $'\x7f' ] || [ "$char" = $'\x08' ] ; then   # backspace
				if [ "$charcount" != '1' ] ; then
					passwordentry="${passwordentry%?}"
					printf '\b \b'
					charcount=$((charcount - 1))
				fi

			else
				if [ "$charcount" = '1' ] ; then   # first char
					printf "%s" "$char"
					passwordentry="$char"
				else
					printf "\b*%s" "$char"   # terminal output
					passwordentry="${passwordentry}$char"   # create var
				fi
				charcount=$((charcount + 1))
			fi
		done

		IFS=$old_ifs
	} # pswd_entry

	F_terminal_entry_header 22
	F_terminal_show "Enter the password for your Email"
	[ -f "$cred_loc" ] && F_terminal_padding && F_terminal_show "Saved password exists, leave blank to use saved"
	F_terminal_padding ; F_terminal_entry "Password  : "

	F_pswd_entry

	password_entry_1="$passwordentry"
	case $passwordentry in
		E|e) F_menu_exit ;;
	esac

	if [ -f "$cred_loc" ] && [ -z "$passwordentry" ] ; then   # keep saved
		printf "%b" "$tBACK$tERASE"
		F_terminal_check_ok "Keeping saved"
		return 0

	elif [ ! -f "$cred_loc" ] && [ -z "$passwordentry" ] ; then
		F_terminal_show "Error - Password cannot be empty - Any key to retry - E|e to Exit"
		read -rsn1 waitsmtppswd
		case $waitsmtppswd in
			E|e) F_clean_exit reload ;;
		esac
		return 1
	fi

	passwordentry=''
	F_terminal_entry "Reconfirm : "

	F_pswd_entry

	password_entry_2="$passwordentry"

	case $passwordentry in
		E|e) F_menu_exit ;;
	esac

	if [ "$password_entry_1" != "$password_entry_2" ] || [ -z "$password_entry_2" ] ; then
		F_terminal_check_fail "Passwords do NOT match - Any key to retry"
		read -rsn1 nomatchwait
		password_entry_1='' ; password_entry_2='' ; passwordentry=''
		return 1
	fi

	# encrypt remove new lines so no sed errors
	user_pswd_enc="$(echo "$password_entry_1" | eval "$(echo "$user_e" | openssl base64 -d)" )"
	if echo "$user_pswd_enc" > "$cred_loc" ; then
		F_chmod "$cred_loc"
		F_terminal_check_ok "Password successfully encrypted and saved"
		passwordentry='' ; password_entry_1='' ; password_entry_2='' ; user_pswd_encrypt=''
		return 0
	else
		F_terminal_show "Failed updating script with encrypted password"
		passwordentry='' ; password_entry_1='' ; password_entry_2='' ; user_pswd_encrypt=''
		return 0
	fi
} ### smtp_pswd

F_term_show_msgcount() {
	[ "$user_message_type" != 'smtp_isp_nopswd' ] && base_count=23 || base_count=22
	if [ "$user_message_count" = '1' ] || [ -z "$user_message_count" ] || [ "$user_message_count" = '0' ] ; then
		F_terminal_entry_header $base_count
	elif [ "$user_message_count" = '2' ] ; then
		F_terminal_entry_header $((base_count + 1))
	elif [ "$user_message_count" = '3' ] ; then
		F_terminal_entry_header $((base_count + 2))
	elif [ "$user_message_count" = '4' ] ; then
		F_terminal_entry_header $((base_count + 3))
	fi
}

F_message_config() {
	if [ -n "$user_message_count" ] && [ "$user_message_count" != '0' ] ; then
		F_term_show_msgcount
		F_terminal_show "Total notification Email count and intervals"
		F_terminal_padding

		if [ "$user_message_count" -gt '1' ] ; then
			printf "%b Message count already set to %b%s%b \n" "$tTERMHASH" "$tGRN" "$user_message_count" "$tCLR"
			[ -n "$user_message_interval_1" ] && printf "%b Email 1/2 interval) %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_message_interval_1" "$tCLR"
			[ -n "$user_message_interval_2" ] && printf "%b Email 2/3 interval) %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_message_interval_2" "$tCLR"
			[ -n "$user_message_interval_3" ] && printf "%b Email 3/4 interval) %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_message_interval_3" "$tCLR"
			F_terminal_padding

			if F_confirm "Keep this setting?" ; then
				return 0
			fi

		else   # message count only set to 1
			if F_confirm correct "Keep message count set to ${user_message_count}" ; then
				email_send_count_entry=1
				return 0
			fi
		fi
	fi

	user_message_count='0'  # empty var for term_show_msg_count incase overwriting old (ans:no to keep old settings), doesnt show old entry
	F_term_show_msgcount
	F_terminal_show "Enter the number of notification Emails (1-4) you wish to send"
	F_terminal_show "with variable intervals you will set in-between each notification"
	F_terminal_show "in the next step"
	F_terminal_padding ; F_terminal_entry "Number of notification Emails (1-4) : "

	read -r email_send_count_entry
	case $email_send_count_entry in
		[1-4]) ;;
		e|E) F_menu_exit ;;
		*) F_terminal_check_fail "Invalid Entry, must be 1,2,3,4 - Any key to retry" && read -rsn1 invalidwaitcount && return 1 ;;
	esac

	F_terminal_padding

	if F_confirm correct "$email_send_count_entry" ; then
		F_replace_var user_message_count "$email_send_count_entry" "$config_src"
		user_message_count="$email_send_count_entry"
	else
		email_send_count_entry=''
		return 1
	fi

	user_message_interval_1=   #  reset for edits (terminal show)
	user_message_interval_2=
	user_message_interval_3=
	return 0
} # message_config

F_message_intervals_entry() {
	while [ "$user_message_count" -gt "$message_entry_loop" ] ; do
		F_term_show_msgcount
		printf "%b Enter an interval type between Email notifications %b and %b\n" "$tTERMHASH" "$tGRN$message_entry_loop$tCLR" "$tGRN$email2count$tCLR"
		F_terminal_show "eg. s = second, m = minutes, h = hours, d = days"
		F_terminal_padding ; F_terminal_entry "Interval period : "

		read -r message_interval_entry
		case $message_interval_entry in
			s|m|h|d)
				[ "$message_interval_entry" = 's' ] && message_selection='seconds'
				[ "$message_interval_entry" = 'm' ] && message_selection='minute(s)'
				[ "$message_interval_entry" = 'h' ] && message_selection='hour(s)'
				[ "$message_interval_entry" = 'd' ] && message_selection='day(s)'
				printf "%b Enter a time period (%bx %s%b) : " "$tTERMHASH" "$tGRN" "$message_selection" "$tCLR"

				read -r message_period_entry
				F_terminal_padding

				if [ "$message_period_entry" -eq "$message_period_entry" ] 2> /dev/null; then
					if ! F_confirm correct "$message_period_entry $message_selection" ; then
						message_period_entry=''
						message_interval_entry=''
						return 1
					fi

					message_interval_complete="$message_period_entry$message_interval_entry"
					F_replace_var "user_message_interval_$message_entry_loop" "$message_interval_complete" "$config_src"
					eval "user_message_interval_$message_entry_loop=$message_interval_complete"   # set vars for terminal show (setup)

				else
					F_terminal_check_fail "Not a valid number - Any key to retry" && read -rsn 1 nonumwait && return 1
				fi

				message_entry_loop=$((message_entry_loop + 1))
				email2count=$((email2count + 1))
				;;
			e|E) F_menu_exit ;;
			*) F_terminal_check_fail "Invalid entry. s/m/h/d only - Any key to retry" && read -rsn1 timewait && return 1 ;;
		esac
	done
} ### message_intervals_entry

F_default_create() {
	{
		echo "#!/bin/sh"
		echo "# wicens user config file"
		echo "build_settings_version='$current_user_config'"
		echo "###########################################################"
		echo "saved_wan_ip=''"
		echo "saved_wan_date=''"
		echo "saved_wan_epoch=''"
		echo "###########################################################"
		echo "# User config settings ####################################"
		echo "user_from_name=''"
		echo "user_smtp_server=''"
		echo "user_from_addr=''"
		echo "user_send_to_addr=''"
		echo "user_send_to_cc=''"
		echo "user_message_type=''"
		echo "user_message_count='0'"
		echo "user_message_interval_1=''"
		echo "user_message_interval_2=''"
		echo "user_message_interval_3=''"
		echo "user_custom_subject=''"
		echo "user_custom_text=''"
		echo "user_custom_script=''"
		echo "user_custom_script_time=''"
		echo "user_update_notification='1'"
		echo "user_fw_update_notification='1'"
		echo "###########################################################"
		echo "cron_run_count=0"
		echo "last_cron_run=''"
		echo "last_wancall_run=''"
		echo "wancall_run_count=0"
		echo "last_ip_change=''"
		echo "ip_change_count=0"
		echo "install_date=''"
		echo "update_date=''"
		echo "created_date='never'"
		echo "last_wancall_log_count=0"
		echo "opt_color='yes'"
		echo "log_cron_msg=0"
		echo "ssl_flag="
		echo "protocol='smtps'"
		echo "amtm_import=1"
		echo "###########################################################"
		echo "# Created : $(F_date full)"
	} > "$config_src"

	F_log "Created default user config v${current_user_config} for wicens"
} ### default

F_default_update_create() {
	{
		echo "#!/bin/sh"
		echo "# wicens update config file"
		echo "update_settings_version='$current_core_config'"
		echo "###########################################################"
		echo "fw_build_no="
		echo "fw_build_sub="
		echo "fw_build_extend="
		echo "fw_pulled_device_name="
		echo "fw_pulled_lan_name="
		echo "fw_device_model="
		echo "update_avail='none'"
		echo "update_cron_epoch='0'"
		echo "update_notify_state='0'"
		echo "update_fw_notify_state='0'"
		echo "update_period='172800'   # period between update checks default 48hrs"
		echo "wan_history_count='10'   # change if you want more/less than 10 historcal IPs in Email message"
		echo "retry_wait_period='21600'   # period between failed email retries default 6 hrs"
		echo "max_email_retry='5'   # max cron run retries before waiting for retry_period"
		echo "###########################################################"
		echo "# Created : $(F_date full)"
	} > "$update_src"

	F_log "Created default core config v$current_core_config for wicens"
} # current_core

F_build_settings() {
	building_settings='yes'   # for opt_sample no exit, move to test option
	until F_send_to_addr ; do : ; done
	until F_send_to_cc; do : ; done
	until F_smtp_server ; do : ; done
	until F_send_type ; do : ; done
	until F_from_email_addr ; do : ; done
	[ "$user_message_type" != 'smtp_isp_nopswd' ] && until F_smtp_pswd ; do : ; done
	until F_from_name ; do : ; done
	until F_message_config ; do : ; done
	message_entry_loop=1   # 2 vars used in message_intervals_entry but cant be in that function
	email2count=2
	[ "$email_send_count_entry" -ge 2 ] && until F_message_intervals_entry ; do : ; done

	if [ "$created_date" = 'never' ] ; then
		F_replace_var created_date "$(F_date full)" "$config_src"
		created_date="$(F_date full)"
	else
		F_status ; F_terminal_padding
		if F_confirm "Update script w/ new configure date $(F_date full)?" ; then
			F_replace_var created_date "$(F_date full)" "$config_src"
			F_terminal_check_ok "Updated script with current date/time as configured date"
			created_date="$(F_date full)"   # for terminal show in setup
		else
			F_terminal_check_ok "Leaving original configure date"
		fi
	fi

	F_status
	F_terminal_show "Adding entries in cron(cru)/services-start/wan-event for wicens"
	F_auto_run add
	F_terminal_check_ok "Done, entries added in cron(cru)/services-start/wan-event for wicens"

	[ -z "$saved_wan_ip" ] && F_saved_wan_ip_create

	F_terminal_padding ; F_terminal_check "Any key to continue to view sample Email output"
	read -rsn1 continuewanwait

	source "$config_src"
	F_opt_sample
	F_terminal_padding ; F_terminal_check_ok "Congratulations, you've completed the wicens setup."
	F_terminal_padding ; F_terminal_check "Hit T|t to send a test Email - M|m for Main Menu - Any key to exit"

	read -rsn1 setupwait
	case $setupwait in
		T|t) rm -f "$script_lock" && exec /bin/sh "$script_name_full" test ;;
		M|m) F_clean_exit reload ;;
		*) ;;
	esac

	printf "\r%b" "$tERASE"
	F_terminal_check_ok "This script is now configured"
	F_terminal_show "Run wicens on the command line to run script manually with set config"
	F_clean_exit
} ### build_settings

F_edit_settings() {
	edit_settings='yes'
	F_terminal_header
	printf '%b %bWelcome to the WICENS config editor %b \n' "$tTERMHASH" "$tGRN" "$tCLR"
	F_terminal_padding
	F_terminal_header_print "Current Email send to address       1: " "$user_send_to_addr"
	F_terminal_header_print "Current Email send to CC address    2: " "$user_send_to_cc"
	F_terminal_header_print "Current Email server addr:port      3: " "$user_smtp_server"
	F_terminal_header_print "Current Email send format type      4: " "$user_message_type"
	F_terminal_header_print "Current Email send from address     5: " "$user_from_addr"
	F_terminal_header_print "Current Email message from name     6: " "$user_from_name"
	F_terminal_header_print "Total # Email notifications set     7: " "$user_message_count"
	[ "$user_message_type" = "smtp_ssl" ] && F_terminal_header_print "Current curl SSL protocol           8: " "$protocol"
	[ "$user_message_count" -gt 1 ] 2>/dev/null && F_terminal_header_print "Interval between Email 1/2          9: " "$user_message_interval_1"
	[ "$user_message_count" -gt 2 ] 2>/dev/null && F_terminal_header_print "Interval between Email 2/3          9: " "$user_message_interval_2"
	[ "$user_message_count" -gt 3 ] 2>/dev/null && F_terminal_header_print "Interval between Email 3/4          9: " "$user_message_interval_3"
	if [ "$amtm_import" = 0 ] && [ "$amtm_status" = 'OK' ] ; then
		F_terminal_header_print "Sync wicens from AMTM Email config  0: " "Enabled"
	else
		F_terminal_header_print_d "Sync wicens from AMTM Email config  0: " "Disabled"
	fi
	F_terminal_padding ; F_terminal_show "Make a selection or E||e to exit" ; F_terminal_padding

	while true; do
		F_terminal_check "Selection : "
		read -r editselect
		case $editselect in
			1) until F_send_to_addr ; do : ; done ;;
			2) until F_send_to_cc; do : ; done ;;
			3) until F_smtp_server ; do : ; done ;;
			4) until F_send_type ; do : ; done ;;
			5) until F_from_email_addr ; do : ; done ;;
			6) until F_from_name ; do : ; done ;;
			7) until F_message_config ; do : ; done
				if [ "$user_message_count" -gt 1 ] ; then
					message_entry_loop=1   # 2 vars used in message_intervals_entry but cant be in that function
					email2count=2
					until F_message_intervals_entry ; do : ; done
				fi
				;;
			8) if [ "$user_message_type" = "smtp_ssl" ] ; then
					if [ "$protocol" = 'smtps' ] ; then
						F_replace_var protocol 'smtp' "$config_src"
						F_terminal_padding ; F_terminal_check_ok "Set protocol to SMTP"
					else
						F_replace_var protocol 'smtps' "$config_src"
						F_terminal_padding ; F_terminal_check_ok "Set protocol to SMTPS"
					fi
				else
					printf '%b' "$tBACK$tERASE"
					F_fail_entry
				fi
				F_menu_exit
				;;
			9) if [ "$user_message_count" -ge 2 ] ; then
					message_entry_loop=1   # 2 vars used in message_intervals_entry but cant be in that function
					email2count=2
					until F_message_intervals_entry ; do : ; done
				else
					F_fail_entry
				fi
				;;
			0) if [ "$amtm_import" = 0 ] ; then
					F_terminal_warning
					F_terminal_show "This will disable syncing wicens with your Email config in AMTM"
					F_terminal_check "Are you sure? Y||y or any key to exit"
					read -rsn1 disableamtm
					case $disableamtm in
						Y|y) F_replace_var amtm_import 1 "$config_src"
							 amtm_import=1
							 F_terminal_check_ok "Disabled AMTM Email sync"
							 F_terminal_check "Any key to return..."
							 read -rsn1 syncdisablewait
							;;
						*) ;;
					esac
				else
					if [ "$amtm_status" = 'OK' ] ; then
						F_terminal_warning
						F_terminal_show "This will enable syncing wicens with your Email config in AMTM"
						F_terminal_show "and overwrite any currently saved Email settings"
						F_terminal_check "Are you sure? Y||y or any key to exit"
						read -rsn1 enableamtm
						case $enableamtm in
							Y|y) F_replace_var amtm_import 0 "$config_src"
								 amtm_import=0
								 F_terminal_check_ok "Enabled AMTM Email sync"
								 F_terminal_check "Any key to start sync..."
								 read -rsn1 syncenablewait
								 F_opt_amtm confirm
								 ;;
							*) ;;
						esac
					else
						F_terminal_check_fail "AMTM Email config file is invalid, launch AMTM and configure Email"
						F_terminal_check "Any key to return"
						read -rsn1 synccantenable
					fi
				fi
				;;
			e|E) F_clean_exit reload ;;
			*) [ -n "$editselect" ] && printf '%b' "$tBACK$tERASE" && F_fail_entry ;;
		esac
		break
	done

	F_edit_settings
} ### edit_settings

F_saved_wan_ip_create() {
	saved_wan_date="$run_date"
	F_log_terminal_fail "No saved WAN IP found, attempting to write current to this script"
	internet_check_count=0
	until F_internet_check ; do : ; done
	F_nvram_wan_ip_get
	F_script_wan_update
	saved_wan_ip="$current_wan_ip"
	rm -f "$mail_file" 2> /dev/null
} ### saved_wan_ip_check

# MAIL ################################################################################################################
#######################################################################################################################

F_email_message() {
	if [ -n "$user_custom_subject" ] ;then   # needs to be here as current_wan_ip isnt set till right before this runs
		formatted_custom_subject="$(echo "$user_custom_subject_decoded" | /bin/sed "s~\$fw_device_model~$fw_device_model~g" | /bin/sed "s~\$current_wan_ip~$current_wan_ip~g" | /bin/sed "s~\$saved_wan_ip~$saved_wan_ip~g" )"
	fi

	[ -f "$mail_file" ] && rm -f "$mail_file"

	touch "$mail_file"
	{  # start of message output part 1/2
		[ -n "$user_send_to_cc" ] && echo "Cc: $user_send_to_cc"
		[ -z "$user_custom_subject" ] && echo "Subject: WAN IP has changed on $fw_device_model" || echo "Subject: $formatted_custom_subject"
		echo "From: $user_from_name <$user_from_addr>"
		echo "Date: $(F_date full)"
		echo ""
		[ "$test_mode" = 'yes' ] && [ "$passed_options" != 'sample' ] && echo "### This is a TEST message ###" && echo ""
		echo "NOTICE"
		echo ""
		echo "WAN IP for $user_from_name $fw_device_model has changed"
		echo ""
		echo "New WAN IP : $current_wan_ip"
		echo ""
		echo "Old WAN IP : $saved_wan_ip"
		echo ""
		echo "Old WAN IP recorded in script on : $saved_wan_date"
		echo ""
		printf "WAN IP Lease time observed       : "

		if [ -n "$saved_wan_ip" ] ; then F_calc_lease ; else printf '\n' ; fi    # calc and write lease time to email

		echo ""
		[ -n "$user_custom_text" ] && echo -e "$user_custom_text_decoded" && echo ""

		if [ -f "$history_src" ] ; then
			echo "WAN IP saved history (last $wan_history_count) most recent first"
			echo "    Time Found                              IP                     Lease time"
			F_terminal_separator
			tail -n "$wan_history_count" < "$history_src" | /bin/sed 'x;1!H;$!d;x'   # invert list
			echo ""
		fi
		F_terminal_separator
	} >> "$mail_file"   # end of message output part 1/2

	if [ "$user_message_count" -gt 1 ] ; then
		if [ "$loop_run" = 1 ] ; then
			echo "Message 1 of $user_message_count, you will receive another reminder in $user_message_interval_1" >> "$mail_file"
		else
			echo "Message $loop_run of $user_message_count" >> "$mail_file"
			echo "" >> "$mail_file"

			if [ "$loop_run" = "$user_message_count" ] ; then
				echo "No more notifications, update your devices" >> "$mail_file"
				[ "$test_mode" != 'yes' ] && echo "" && F_script_wan_update   # test mode dont update script
			else
				if [ "$loop_run" = '2' ] ; then
					echo "You will receive another reminder in $user_message_interval_2" >> "$mail_file"
				fi

				if [ "$loop_run" = '3' ] ; then
					echo "You will receive another reminder in $user_message_interval_3" >> "$mail_file"
				fi
			fi
		fi

	else
		echo "Message 1 of $user_message_count - No more notifications, update your devices" >> "$mail_file"
		[ "$test_mode" != 'yes' ] && F_script_wan_update   # test mode dont update script, update script outputs to mail message as well
	fi

	{   # start of message output part 2/2
		echo ""
		echo "Message sent : $(F_date full)"
		echo ""
		router_uptime="$(/usr/bin/awk '{print $1}' /proc/uptime | cut -d'.' -f1)"
		uptime_pretty="$(printf '%d day(s) %d hr(s) %d min(s) %d sec(s)\n' $((router_uptime/86400)) $((router_uptime%86400/3600)) $((router_uptime%3600/60)) $((router_uptime%60)))"
		echo "Router uptime: $uptime_pretty"
		echo ""
		echo "A message from wicens script on your $fw_device_model"

		if [ "$passed_options" != 'sample' ] ; then   # padding incase emails contain footer info
			echo ""
			echo ""
		fi
	} >> "$mail_file"  # end of message output part 2/2

	loop_run="$((loop_run + 1))"
} ### email_message

F_send_format_isp() {
	/usr/sbin/sendmail > "$mail_log" 2>&1 < "$mail_file" \
	-S "$user_smtp_server" -f "$user_from_addr" -t "$user_send_to_addr" -v
} ### message_format_isp

F_send_format_start_tls() {
	/usr/sbin/sendmail >> "$mail_log" 2>&1 < "$mail_file" \
	-H "exec /usr/sbin/openssl s_client -quiet \
	-starttls smtp \
	-connect $user_smtp_server  \
	-no_ssl3 -no_tls1" \
	-t \
	-f "$user_from_name" -au"$user_from_addr" -ap"$user_pswd" "$user_send_to_addr" -v
} ### message_format_tls

F_send_format_tls_v1() {
	/usr/sbin/sendmail >> "$mail_log" 2>&1 < "$mail_file" \
	-H "exec /usr/sbin/openssl s_client -quiet \
	-tls1 -starttls smtp \
	-connect $user_smtp_server" \
	-t \
	-f "$user_from_name" -au"$user_from_addr" -ap"$user_pswd" "$user_send_to_addr" -v
} ### message_format_tls1_only

F_send_format_plain_auth() {
	/usr/sbin/sendmail >> "$mail_log" 2>&1 < "$mail_file" \
	-t -S "$user_smtp_server" -f "$user_from_name" "$user_send_to_addr" -au"$user_from_addr" -ap"$user_pswd" -v
} ### message_format_smtp

F_send_format_ssl() {
	if [ -z "$user_send_to_cc" ] ; then
		curl >> "$mail_log" 2>&1 \
		-v \
		--url "$protocol"://"$user_smtp_server" \
		--mail-from "$user_from_addr" --mail-rcpt "$user_send_to_addr" \
		--upload-file "$mail_file" \
		--ssl-reqd \
		--user "$user_from_addr:$user_pswd" $ssl_flag
	else
		curl >> "$mail_log" 2>&1 \
		-v \
		--url "$protocol"://"$user_smtp_server" \
		--mail-from "$user_from_addr" --mail-rcpt "$user_send_to_addr" \
		--mail-rcpt "$user_send_to_cc" \
		--upload-file "$mail_file" \
		--ssl-reqd \
		--user "$user_from_addr:$user_pswd" $ssl_flag
	fi
} ### message_format_ssl

F_send_message() {
	touch "$mail_log"
	echo "Created by PID $$ on $(F_date full), ran by $passed_options" >> "$mail_log"

	[ -f "$cred_loc" ] && user_pswd="$(eval "$(echo "$user_d" | openssl base64 -d)" < "$cred_loc")"

	if [ "$user_message_type" = 'smtp_isp_nopswd' ] ; then
		if F_send_format_isp ; then return 0 ; else return 1 ; fi
	elif [ "$user_message_type" = 'smtp_plain_auth' ] ; then
		if F_send_format_plain_auth ; then return 0 ; else return 1 ; fi
	elif [ "$user_message_type" = 'smtp_start_tls' ] ; then
		if F_send_format_start_tls ; then return 0 ; else return 1 ; fi
	elif [ "$user_message_type" = 'smtp_start_tls_v1' ] ; then
		if F_send_format_tls_v1 ; then return 0 ; else return 1 ; fi
	elif [ "$user_message_type" = 'smtp_ssl' ] ; then
		if F_send_format_ssl ; then return 0 ; else return 1 ; fi
	fi
} ### send_message

F_send_mail() {
	if [ "$passed_options" != 'test' ] ; then
		if [ -f "$wicens_wanip_retry" ] ; then
			echo "# Attempting to send wan ip change notification $(F_date full)" >> "$wicens_wanip_retry"
		else
			{
				echo "#!/bin/sh"
				echo "wicens_wanip_retry_time=${run_epoch}"
				echo "# Attempting to send wan ip change notification $(F_date full)"
			} > "$wicens_wanip_retry"
			F_chmod "$wicens_wanip_retry"
		fi
	fi

	internet_check_count=0
	until F_internet_check wanip ; do : ; done   # monitors/runs F_internet_ping (attempts 5mins/30s interval)

	rm -f "$mail_log" 2> /dev/null
	touch "$script_mail_lock" # temp lockfile#2
	echo "Sending mail for $script_name_full on : $(F_date full)" >> "$script_mail_lock"
	echo "Sending mail from $(cat "$script_lock")" >> "$script_mail_lock"

	loop_run='1'
	while [ "$loop_run" -le "$user_message_count" ] ; do
		printf "%b Sending Email message %s of %s" "$tCHECK" "$loop_run" "$user_message_count"

		F_email_message #  generates Email text and increases loop_run!

		if ! F_send_message; then
			user_pswd=''
			printf "\r%b Error, failed to send Email notification %s of %s\n" "$tERASE$tCHECKFAIL" "$((loop_run - 1))" "$user_message_count"
			F_log "CRITICAL ERROR - wicens failed to send Email notification $((loop_run - 1)) of $user_message_count"
			F_log_show "Are your Email settings in this script correct? and password?"
			F_log_show "Or maybe your Email host server was temporarily down?"
			F_log_show "Main Menu - option L||l for errors - P||p to re-enter password"
			rm -f "$mail_file"
			F_log_show "Resetting WAN IP to old WAN IP to attempt again in 10 minutes"
			F_replace_var saved_wan_date "$original_wan_date" "$config_src"
			F_replace_var saved_wan_epoch "$original_wan_epoch" "$config_src"
			F_replace_var saved_wan_ip "$original_wan_ip" "$config_src"

			if [ "$from_menu" = 'yes' ] ; then
				F_menu_exit
			else
				F_clean_exit
			fi
		fi

		user_pswd=''
		printf "\r%b Done sending Email message %s of %s\n" "$tERASE$tCHECKOK" "$((loop_run - 1))" "$user_message_count"
		rm -f "$mail_file"
		F_log "Done sending Email $((loop_run - 1)) of $user_message_count update your clients to $current_wan_ip"

		if [ "$loop_run" -le "$user_message_count" ] ; then
			if [ "$loop_run" = '2' ] ; then
				printf "%b Sleeping %s before sending next Email" "$tCHECK" "$user_message_interval_1"
				F_log "Sleeping $user_message_interval_1 before sending next Email"
				sleep "$user_message_interval_1"
			fi

			if [ "$loop_run" = '3' ] ; then
				printf "%b Sleeping %s before sending next Email" "$tCHECK" "$user_message_interval_2"
				F_log "Sleeping $user_message_interval_2 before sending next Email"
				sleep "$user_message_interval_2"
			fi

			if [ "$loop_run" = '4' ] ; then
				printf "%b Sleeping %s before sending next email" "$tCHECK" "$user_message_interval_3"
				F_log "Sleeping $user_message_interval_3 before sending next Email"
				sleep "$user_message_interval_3"
			fi
		fi
	done

	# user_custom_script 'wait' call
	if [ -n "$user_custom_script" ] && [ "$user_custom_script_time" = 'w' ] && [ "$passed_options" != 'test' ] ; then
		nohup /bin/sh "$user_custom_script_decoded" > "${script_dir}/user_script.log" & custom_script_pid=$!
		F_log "Executed custom script $user_custom_script_decoded and put in background with PID $custom_script_pid"
		F_terminal_check_ok "Started user custom script and put in background"
	fi

	# clean up custom script 'immediate' call lock
	if [ "$passed_options" != 'test' ] ; then
		[ -f '/tmp/wicens_user_script_i.tmp' ] && rm -f '/tmp/wicens_user_script_i.tmp'   # immediate call lock file remove after success
		ip_change_count=$((ip_change_count + 1))   # update script IP changes after success
		F_replace_var ip_change_count "$ip_change_count" "$config_src"
	fi

	# finished sending clean up
	rm -f "$script_mail_lock"
	rm -f "$wicens_wanip_retry"
	F_terminal_check_ok "Script completed."

	if [ "$from_menu" = 'yes' ] ; then
		F_menu_exit
	else
		F_terminal_check_ok "This script is now configured"
		F_terminal_show "Run wicens on the command line to run script manually with set config"
		F_clean_exit
	fi
} ### send_mail

# AUTO RUN ############################################################################################################
#######################################################################################################################

F_cru() {
	if [ "$1" = 'check' ] ; then
		if /usr/sbin/cru l | grep -q "$script_name_full cron" ; then
			printf "\r%b Cron(cru) wicens entry           :  %bexists%b\n" "$tERASE$tCHECKOK" "$tGRN" "$tCLR"
			return 0
		else
			F_terminal_check_fail "No wicens entry found in cron(cru)"
			return 1
		fi

	elif [ "$1" = 'add' ] ; then
		F_terminal_check "Adding entry for wicens in cron(cru) with 10m interval"

		if /usr/sbin/cru a wicens "*/10 * * * * $script_name_full cron" ; then
			F_log_terminal_ok "Added entry for wicens in cron(cru) with 10m interval"
		else
			F_log_terminal_fail "Failed to add cron(cru) entry for wicens"
		fi

	elif [ "$1" = 'remove' ] ; then
		F_terminal_check "Removing wicens entry in cron(cru)"

		if /usr/sbin/cru l | grep -q "$script_name cron" ; then
			if /usr/sbin/cru d wicens ; then
				F_log_terminal_ok "Removed cron entry for wicens"
			else
				F_terminal_check_fail "Error, failed removing cron entry for wicens"
				F_log "Error, failed removing cron entry for wicens"
			fi

		else
			F_terminal_check_ok "No entry found for wicens in cron(cru) to remove"
		fi
	fi
} # cru_check

F_serv_start() {
	if [ "$1" = 'check' ] ; then
		F_terminal_check "Checking for wicens entry in services-start"

		if grep -q "$script_name_full cron" '/jffs/scripts/services-start' 2>/dev/null ; then
			printf "\r%b services-start wicens entry      :  %bexists%b\n" "$tERASE$tCHECKOK" "$tGRN" "$tCLR"
			return 0
		else
			if [ -f '/jffs/scripts/services-start' ] ; then
				F_terminal_check_fail "No wicens entry found in /jffs/scripts/services-start for cron(cru)"
			else
				F_terminal_check_fail "/jffs/scripts/services-start does not exist"
			fi
			return 1
		fi

	elif [ "$1" = 'add' ] ; then
		if [ -f '/jffs/scripts/services-start' ] ; then
			F_crlf '/jffs/scripts/services-start'
			[ ! -x '/jffs/scripts/services-start' ] && F_chmod "/jffs/scripts/services-start"

			F_terminal_check "Adding cron(cru) to /jffs/scripts/services-start"

			if ! grep -q '#!/bin/sh' '/jffs/scripts/services-start' ; then
				F_log "Your services-start does not contain a '#!/bin/sh', please investigate and run again"
				F_terminal_check_fail "Your services-start does not contain a '#!/bin/sh', please investigate and run again"
				F_clean_exit
			fi

			if echo "/usr/sbin/cru a wicens \"*/10 * * * * $script_name_full cron\"   # added by wicens $(F_date full)" >> '/jffs/scripts/services-start' ; then
				echo "/usr/bin/logger -t \"services-start[\$\$]\" \"Added wicens entry to cron(cru)\"   # added by wicens $(F_date full)" >> '/jffs/scripts/services-start'
				F_log_terminal_ok "Added a cron(cru) entry for wicens to /jffs/scripts/services-start"
			else
				F_log_show "Critical error, failed writing cron command to services-start"
				F_clean_exit
			fi

		else
			F_log "/jffs/scripts/services-start does not exist, attempting to create"
			F_terminal_check "Creating /jffs/scripts/services-start"
			touch '/jffs/scripts/services-start'
			F_log_terminal_ok "Created services-start in /jffs/scripts/"

			if echo '#!/bin/sh' >> /jffs/scripts/services-start ; then
				if echo "/usr/sbin/cru a wicens \"*/10 * * * * $script_name_full cron\"   # added by wicens $(F_date full)" >> /jffs/scripts/services-start ; then
					echo "/usr/bin/logger -t \"services-start[\$\$]\" \"Added wicens entry to cron(cru)\"   # added by wicens $(F_date full)" >> '/jffs/scripts/services-start'
					F_chmod "/jffs/scripts/services-start"
					F_log_terminal_ok "Added cron entry for wicens cron call in /jffs/scripts/services-start"
					F_log "Created services-start in /jffs/scripts/ and added cron entry for wicens"
				else
					F_log_show "Critical error, failed writing to services-start"
					F_clean_exit
				fi

			else
				F_terminal_check_fail "Critical error, failed to add 'shebang' to services-start"
				F_log "Critical error, failed to add 'shebang' to services-start"
				F_clean_exit
			fi
		fi

	elif [ "$1" = 'remove' ] ; then
		F_terminal_check "Removing wicens entry in services-start"
		if [ -f '/jffs/scripts/services-start' ] ; then
			if grep -q "$script_name_full cron" '/jffs/scripts/services-start' 2> /dev/null; then
				if /bin/sed -i "\| $script_name_full |d" '/jffs/scripts/services-start' ; then
					/bin/sed -i '/Added wicens entry/d' '/jffs/scripts/services-start'
					F_log_terminal_ok "Removed services-start entry for wicens"
				else
					F_terminal_check_fail "Error, could not remove wicens entry in /jffs/scripts/services-start"
					F_log "Error, could not remove wicens entry in services-start"
				fi

			else
				F_terminal_check_ok "No entry found for wicens in /jffs/scripts/services-start to remove"
			fi

			if [ "$(wc -l < /jffs/scripts/services-start )" -eq 1 ] ; then
				if grep -q "#!/bin/sh" "/jffs/scripts/services-start"; then
					F_log_terminal_ok "/jffs/scripts/services-start appears empty, removing file"
					rm -f /jffs/scripts/services-start
				fi
			fi

		else
			F_terminal_check_ok "/jffs/scripts/services-start doesn't exist"
		fi
	fi
} # serv_start_check

F_wan_event() {
	if [ "$1" = 'check' ] ; then
		F_terminal_check "Checking for wicens entry in wan-event"
		if grep -q "$script_name_full wancall" '/jffs/scripts/wan-event' 2>/dev/null ; then
			printf "\r%b wan-event wicens entry           :  %bexists%b\n" "$tERASE$tCHECKOK" "$tGRN" "$tCLR"
			return 0
		else
			if [ -f '/jffs/scripts/wan-event' ] ; then
				F_terminal_check_fail "No wicens entry found in /jffs/scripts/wan-event script"
			else
				F_terminal_check_fail "/jffs/scripts/wan-event does not exist"
			fi
			return 1
		fi

	elif [ "$1" = 'add' ] ; then
		if [ -f '/jffs/scripts/wan-event' ] ; then
			F_crlf '/jffs/scripts/wan-event'
			[ ! -x '/jffs/scripts/wan-event' ] && F_chmod '/jffs/scripts/wan-event'

			F_terminal_check "Adding wicens to wan-event script on connected event"

			if ! grep -q '#!/bin/sh' '/jffs/scripts/wan-event' ; then
				F_terminal_check_fail "Your wan-event does not contain a '#!/bin/sh', please investigate and run again"
				F_log "Your wan-event does not contain a '#!/bin/sh', please investigate and run again"
				F_clean_exit
			fi

			if echo "[ \"\$2\" = \"connected\" ] && (/bin/sh $script_name_full wancall) & wicenspid=\$!  # added by wicens $(F_date full)" >> /jffs/scripts/wan-event ; then
				echo "[ \"\$2\" = \"connected\" ] && /usr/bin/logger -t \"wan-event[\$\$]\" \"Started wicens with pid \$wicenspid\"   # added by wicens $(F_date full)" >> '/jffs/scripts/wan-event'
				F_log_terminal_ok "Added wicens to wan-event with connected event trigger"
			else
				F_terminal_check_fail "Error, failed writing wicens wancall entry to wan-event"
				F_clean_exit
			fi
		else
			F_log "/jffs/scripts/wan-event does not exist, attempting to create"
			F_terminal_check "Creating /jffs/scripts/wan-event"
			touch '/jffs/scripts/wan-event'
			F_terminal_check_ok "Created wan-event in /jffs/scripts/"

			if echo '#!/bin/sh' >> /jffs/scripts/wan-event ; then
				if echo "[ \"\$2\" = \"connected\" ] && (/bin/sh $script_name_full wancall) & wicenspid=\$!   # added by wicens $(F_date full)" >> /jffs/scripts/wan-event ; then
					echo "[ \"\$2\" = \"connected\" ] && /usr/bin/logger -t \"wan-event[\$\$]\" \"Started wicens with pid \$wicenspid\"   # added by wicens $(F_date full)" >> '/jffs/scripts/wan-event'
					F_chmod '/jffs/scripts/wan-event'
					F_terminal_check_ok "Added connected event entry for wicens wancall in /jffs/scripts/wan-event"
					F_log "Created wan-event in /jffs/scripts/ and added connected event entry for wicens"
			else
					F_log_show "Critical error, failed writing to wan-event"
					F_clean_exit
				fi
			else
				F_terminal_check_fail "Critical error, failed to add 'shebang' to wan-event"
				F_log "Critical error, failed to add 'shebang' to wan-event"
				F_clean_exit
			fi
		fi

	elif [ "$1" = 'remove' ] ; then
		F_terminal_check "Removing wicens entry in wan-event"
		if [ -f '/jffs/scripts/wan-event' ] ; then
			if grep -q "$script_name_full wancall" '/jffs/scripts/wan-event' 2> /dev/null; then
				/bin/sed -i "\| $script_name_full |d" '/jffs/scripts/wan-event'
				/bin/sed -i '/Started wicens with pid/d' '/jffs/scripts/wan-event'
				F_log_terminal_ok "Removed wan-event entry for wicens"
			else
				F_terminal_check_ok "No entry found for wicens in /jffs/scripts/wan-event to remove"
			fi
			if [ "$(wc -l < /jffs/scripts/wan-event)" -eq 1 ] ; then
				if grep -q "#!/bin/sh" "/jffs/scripts/wan-event"; then
					F_log_terminal_ok "/jffs/scripts/wan-event appears empty, removing file"
					rm -f /jffs/scripts/wan-event
				fi
			fi
		else
			F_terminal_check_ok "/jffs/scripts/wan-event doesn't exist"
		fi
	fi
} # wan_event_check

F_auto_run() {
	if [ "$1" = 'checkall' ] ; then
		if ! F_cru check > /dev/null ; then return 1 ; fi
		if ! F_serv_start check > /dev/null ; then return 1 ; fi
		if ! F_wan_event check > /dev/null ; then return 1 ; fi
		return 0
	elif [ "$1" = 'add' ] ; then
		F_terminal_check "cron(cru) check" && if ! F_cru check ; then F_cru add ;fi
		F_terminal_check "services-start check" && if ! F_serv_start check ; then F_serv_start add ;fi
		F_terminal_check "wan-event check" && if ! F_wan_event check ; then F_wan_event add ; fi
	elif [ "$1" = 'remove' ] ; then
		F_cru remove
		F_serv_start remove
		F_wan_event remove
		return 0
	fi
} ### auto_run

# CORE ################################################################################################################
#######################################################################################################################

F_random_num() {
	[ -z "$random_max" ] && random_max='30'
	/usr/bin/awk -v min=1 -v max="$random_max" 'BEGIN{srand(); print int(min+rand()*(max-min+1))}'   # less than 5 mins to keep lock happy
} ### random_num

F_private_ip() {
	grep -qE "(^127\.)|(^(0)?10\.)|(^172\.(0)?1[6-9]\.)|(^172\.(0)?2[0-9]\.)|(^172\.(0)?3[0-1]\.)|(^169\.254\.)|(^192\.168\.)"
} # private_ip

# WAN IP ##############################################################################################################

F_nvram_wan_ip_get() {
	current_wan_ip="$(F_nvram_get wan0_ipaddr)"

	if [ "$current_wan_ip" = '0.0.0.0' ] || [ -z "$current_wan_ip" ] ; then
		F_log_terminal_fail "No valid IP found in NVRAM, attempting to force update"

		internet_check_count=0
		until F_internet_check ; do : ; done   # monitors/runs F_internet_ping (attempts 5mins/30s interval)

		F_current_wan_ip_get

	elif echo "$current_wan_ip" | F_private_ip ; then
		printf "\r%b WAN IP %s is a private IP, attempting update with getrealip.sh" "$tERASE$tCHECKFAIL" "$current_wan_ip"
		F_current_wan_ip_get
	fi

	# WAN IP is valid
	if [ "$current_wan_ip" = "$saved_wan_ip" ] ; then
		return 0
	else
		return 1
	fi
} ### nvram_wan_ip_get

F_current_wan_ip_get() {
	getrealip_call_count=3   # max tries to get WAN IP
	F_getrealip() {   # watcher for getrealip.sh so if it hangs it doesnt sit around forever
		sleep_wait=5
		(/bin/sh /usr/sbin/getrealip.sh | grep -Eo "$ip_regex" ) & command_pid=$!
		( sleep "$sleep_wait" && /bin/kill -HUP "$command_pid" 2> /dev/null && rm -f /tmp/wicenswanipget.tmp && F_log "NOTICE - Killed hung getrealip.sh process after 5 secs" ) & watcher_pid=$!
		wait "$command_pid" && /bin/kill -HUP "$watcher_pid" 2> /dev/null
		getrealip_call_count=$((getrealip_call_count - 1))
	} # getrealip

	[ "$passed_options" = 'cron' ] && sleep "$(F_random_num)"

	while [ "$getrealip_call_count" != '0' ] ; do   #  check for WAN IP 3 times
		F_terminal_check "Retrieving WAN IP using getrealip.sh"
		F_getrealip > /tmp/wicenswanipget.tmp   # output to file or watcher doesnt function properly when var=
		current_wan_ip="$(grep -Eo "$ip_regex" /tmp/wicenswanipget.tmp 2>/dev/null )"
		[ -f '/tmp/wicenswanipget.tmp' ] && rm -f /tmp/wicenswanipget.tmp

		if [ -z "$current_wan_ip" ] || [ "$current_wan_ip" = '0.0.0.0' ] ; then
			if [ "$getrealip_call_count" -eq 0 ] ; then
				F_terminal_check_fail "Error retrieving WAN IP 3 times... aborting...."
				F_log "Error retrieving WAN IP 3 times... aborting...."
				F_clean_exit
			else
				F_log_terminal_fail "Error retrieving WAN IP with getrealip.sh, attempt again in 60secs"
				sleep 60
				printf "%b" "$tBACK$tERASE"
			fi
		else
			break
		fi
	done

	if echo "$current_wan_ip" | F_private_ip ; then
		printf "\r%b WAN IP %s is a private IP, something is wrong" "$tERASE$tCHECKFAIL" "$current_wan_ip"
		F_log "ERROR - WAN IP $current_wan_ip is a private IP using getrealip.sh, something is wrong"
		F_clean_exit
	fi
} ### current_wan_ip_get

F_calc_lease() {
	wan_lease_years=0 ; wan_lease_days=0 ; wan_lease_hours=0 ; wan_lease_mins=0 ; wan_lease_secs=0   # set for output
	current_epoch="$(F_date sec)"
	epoch_diff=$((current_epoch - saved_wan_epoch))
	if [ "$epoch_diff" -gt 31536000 ] ; then   # year
		wan_lease_years=$((epoch_diff / 31536000))
		epoch_diff=$((epoch_diff - (31536000 * wan_lease_years)))
	fi

	if [ "$epoch_diff" -gt 86400 ] ; then   # days
		wan_lease_days=$((epoch_diff / 86400))
		epoch_diff=$((epoch_diff - (86400 * wan_lease_days)))
	fi

	if [ "$epoch_diff" -gt 3600 ] ; then   # hours
		wan_lease_hours=$((epoch_diff / 3600))
		epoch_diff=$((epoch_diff - (3600 * wan_lease_hours)))
	fi

	if [ "$epoch_diff" -gt 60 ] ; then   # mins
		wan_lease_mins=$((epoch_diff / 60))
		epoch_diff=$((epoch_diff - (60 * wan_lease_mins)))
	fi
	wan_lease_secs="$epoch_diff"   			# secs

	# output for Email in F_email_message
	[ "$wan_lease_years" -gt 0 ] && printf "%sy " "$wan_lease_years"
	[ "$wan_lease_days" -gt 0 ] && printf "%sd " "$wan_lease_days"
	if [ "$wan_lease_hours" -gt 0 ] ; then
		printf "%sh " "$wan_lease_hours"
	else
		printf "0h "
	fi
	if [ "$wan_lease_mins" -gt 0 ] ; then
		printf "%sm " "$wan_lease_mins"
	else
		printf "0m "
	fi
	printf "%ssec \n" "$wan_lease_secs"
} ### calc_lease

F_do_compare() {
	if F_nvram_wan_ip_get ; then
		printf "\r%b WAN IP lookup  - Current WAN IP  :  %b%s%b \n" "$tERASE$tCHECKOK" "$tGRN" "$current_wan_ip" "$tCLR"
		printf "%b WAN IP compare - Saved WAN IP    :  %bmatch%b \n" "$tCHECKOK" "$tGRN" "$tCLR"
		F_terminal_check_ok "Done."
		[ "$passed_options" = 'wancall' ] && F_log "Saved WAN IP matches current IP"
		if [ "$from_menu" = 'yes' ] ; then F_menu_exit ; else F_clean_exit ; fi
	else
		printf "\r%b WAN IP lookup  - Current WAN IP  :  %b%s%b \n" "$tERASE$tCHECKOK" "$tGRN" "$current_wan_ip" "$tCLR"
		printf "\r%b WAN IP compare - Saved WAN IP    :  %bNo Match%b - Saved IP %b%s%b \n" "$tERASE$tCHECKFAIL" "$tRED" "$tCLR" "$tPUR" "$saved_wan_ip" "$tCLR"
		F_log "WAN IP has changed to $current_wan_ip "
		ip_match='no'

		# user_custom_script 'immediate' call
		if [ -n "$user_custom_script" ] ; then
			case $user_custom_script_time in
				I|i) if [ "$passed_options" != 'test' ] && [ ! -f '/tmp/wicens_user_script_i.tmp' ] ; then
						nohup /bin/sh "$user_custom_script_decoded" > "${script_dir}/user_script.log" 2>&1 & custom_script_pid=$!
						F_log "Executed custom script $user_custom_script_decoded and put in background with PID $custom_script_pid"
						F_terminal_check_ok "Started user custom script and put in background"
						touch /tmp/wicens_user_script_i.tmp   # prevent duplicate runs if email fails on first detection as this will run
					 fi
					 ;;
			esac
		fi
		return 1
	fi
} ### do_compare   does wan ip compare and returns

F_script_wan_update() {
	if [ "$ip_match" = 'no' ] ; then
		F_replace_var last_ip_change "$(F_date full)" "$config_src"
		{
		printf '%-28s' "$saved_wan_date"
		printf '%-17s' "$saved_wan_ip"
		printf '%s \n' "$(F_calc_lease)"
		} >> "$history_src"
	fi

	[ "$building_settings" = 'yes' ] && F_terminal_check_ok "IP successfully retrieved"
	printf "%b Updating wicens script with new WAN IP %b%s%b" "$tCHECKOK" "$tYEL" "$current_wan_ip" "$tCLR"

	if F_replace_var saved_wan_ip "$current_wan_ip" "$config_src" ; then
		printf "\r%b Updated wicens script with new WAN IP %b%s%b  \n" "$tERASE$tCHECKOK" "$tYEL" "$current_wan_ip" "$tCLR"
		F_terminal_check "Confirming new WAN IP in wicens"

		if grep -q "$current_wan_ip" "$config_src" ; then
			F_log_terminal_ok "Success updating wicens script w/ new WAN IP"
			echo "Updating wicens script with new WAN IP $current_wan_ip : Success" >> "$mail_file"
		else
			F_terminal_check_fail "Confirming new WAN IP in wicens"
			F_log "FAILED confirmation of updating wicens with new WAN IP : $current_wan_ip"
			echo "Updating wicens script with new WAN IP $current_wan_ip : Confirmation Failed" >> "$mail_file"
		fi

		F_replace_var saved_wan_date "$(F_date full)" "$config_src"
		F_replace_var saved_wan_epoch "$(F_date sec)" "$config_src"

	else
		F_terminal_check_fail "Updating wicens with new WAN IP : sed failed"
		F_log "FAILED (sed) updating wicens with new WAN IP"
		echo "Updating WICENS script with new WAN IP $current_wan_ip : sed Failed" >> "$mail_file"
	fi
} ### update_script

# INTERNET ############################################################################################################

F_internet_ping() {
	F_test_sites() {
		echo "google.com" ; echo "bing.com" ; echo "yahoo.com" ; echo "github.com" ; echo "asus.com"
		echo "sourceforge.net" ; echo "snbforums.com" ; echo "wikipedia.org"
	}

	cycle_ping_count=1   # cycle through 15 good/bad pings if necessary till 6 good
	good_ping=0
	last_random=   # last random site chosen

	while [ "$cycle_ping_count" -le 15 ] ; do
		[ "${#last_random}" -ge 4 ] && last_random=   # refresh random list after 4 unique tests
		random_max="$(F_test_sites | wc -l)"   # set random max for F_random_num
		random_site="$(F_random_num)"   # pick random line

		if echo "$last_random" | grep -q "$random_site" ; then   # if random picks one of last 3 recently tested sites try again
			sleep 1   # awk random needs 1 sec sleep to function properly
			continue
		else
			last_random="${last_random}$random_site"   # create list of tested sites
			tested_site="$(F_test_sites | /bin/sed -n "${random_site}p")"
			ping_try_count=1
			site_ping=0

			while [ "$ping_try_count" != '4' ] ; do   # ping site 3 times if fail then move on/otherwise 2 good move on
				if ping -q -w1 -c1 "$tested_site" > /dev/null 2>&1 ; then
					good_ping=$((good_ping + 1))
					site_ping=$((site_ping + 1))
					[ "$good_ping" -ge 6 ] && random_max= && return 0
					[ "$site_ping" -ge 2 ] && break
				fi
				ping_try_count=$((ping_try_count + 1))
			done

			cycle_ping_count=$((cycle_ping_count + 1))
		fi
	done

	random_max=
	return 1
} ### internet_ping   cycle through 2 pings to each random site till 6 good or 15 cycle attempts

F_internet_check() {
	internet_check_count=$((internet_check_count + 1))

	if [ "$internet_check_count" = '10' ] ; then
		F_log_terminal_fail "Could not ping $(F_test_sites | wc -l) test sites for the last 5 mins, exiting. Run again with next cron"
		if [ -n "$1" ] ; then   # remove entry try from wanip,send,update,fwupdate to retry again after internet up
			case $1 in
				'wanip') file_line_remove="$wicens_wanip_retry" ;;
				'send') file_line_remove="$wicens_send_retry" ;;
				'update') file_line_remove="$wicens_update_retry" ;;
				'fwupdate') file_line_remove="$wicens_fw_retry" ;;
			esac

			/bin/sed '$d' "$file_line_remove"
			F_log "Removed retry line from $file_line_remove"
		fi
		F_clean_exit
	fi

	F_terminal_check "Checking Internet status..."

	if F_internet_ping ; then
		printf "\r%b Internet check                   : %s successful pings, appears up \n" "$tERASE$tCHECKOK" "$good_ping"
		return 0
	else
		F_terminal_check_fail "Failed pinging $(F_test_sites | wc -l) test sites"
		wait_secs=30

		while [ "$wait_secs" != '0' ] ; do
			printf "%b %b%s%b seconds before next attempt \r" "$tERASE$tCHECK" "$tGRN" "$wait_secs" "$tCLR"
			sleep 1
			wait_secs=$((wait_secs - 1))
		done
		return 1
	fi
} ### internet_check  called with until loop, check connectivity 10 times with 30s intervals

# UPDATE ##############################################################################################################

F_web_update_check() {
	F_terminal_header
	F_terminal_padding ; printf "%bScript Update Check%b \n" "$tTERMHASH $tYEL" "$tCLR" ; F_terminal_padding

	# download wait timer for terminal
	wait_update_time=5
	F_time() {
		while [ "$wait_update_time" != '0' ] ; do
			printf "%b Checking for update %b%s%b secs " "$tTERMHASH" "$tGRN" "$wait_update_time" "$tCLR"
			wait_update_time=$((wait_update_time - 1))
			sleep 1
			printf '\r%b' "$tERASE"
		done
	}

	F_time & time_pid=$!   # start timer wait for vars to be set then kill
	sleep 2   # pretty terminal wait
	git_version="$($git_get | grep 'script_version' | head -n1 | cut -d"=" -f2 | /bin/sed "s/'//g")"
	local_md5="$(/usr/bin/md5sum "$script_name_full" | /usr/bin/awk '{print $1}')"
	server_md5="$($git_get | /usr/bin/md5sum | /usr/bin/awk '{print $1}')"

	if [ -z "$git_version" ] ; then
		/bin/kill "$time_pid" >/dev/null 2>&1
		printf '%b' "$tERASE$tBACK$tERASE"
		printf "\r%b Failed, could not read server script version... aborting update check \n" "$tERASE$tCHECKFAIL"   # stays displayed
		sleep 3   # terminal display
		return 1   # skip everything below
	fi

	/bin/kill "$time_pid" >/dev/null 2>&1
	F_replace_var update_cron_epoch "$(F_date sec)" "$update_src"

	if [ "$script_version" = "$git_version" ] ; then
		if [ "$local_md5" != "$server_md5" ] ; then
			F_replace_var update_avail "hotfix" "$update_src"
			printf '\r%b Success%b checking for update... %bhotfix%b available \n' "$tERASE$tCHECKOK$tGRN" "$tCLR" "$tRED" "$tCLR"
			F_terminal_padding
			F_terminal_show "Change log:"
			/usr/sbin/curl -fsL --retry 3 "https://raw.githubusercontent.com/maverickcdn/wicens/master/CHANGELOG.md" | /bin/sed -n "/^## $script_version/,/^##/p" | head -n -1 | /bin/sed 's/## //'
		else
			printf '\r%b Success%b checking for update... none available \n' "$tERASE$tCHECKOK$tGRN" "$tCLR"
			# cleanup, if no update found, make sure update file is correct
			[ "$update_avail" != 'none' ] && F_replace_var update_avail "none" "$update_src"
			[ "$update_notify_state" = 1 ] && F_replace_var update_notify_state 0 "$update_src"
		fi
	else
		F_replace_var update_avail "$git_version" "$update_src"
		printf '\r%b Success%b checking for update... Ver: %b%s%b available \n' "$tERASE$tCHECKOK$tGRN" "$tCLR" "$tGRN" "$git_version" "$tCLR"
		F_terminal_padding
		F_terminal_show "Change log:"
		/usr/sbin/curl -fsL --retry 3 "https://raw.githubusercontent.com/maverickcdn/wicens/master/CHANGELOG.md" | /bin/sed -n "/^## $git_version/,/^## $script_version/p" | head -n -1 | /bin/sed 's/## //'
	fi

	source "$update_src"   # resource config to update vars in current session
	if [ "$1" = 'force' ] ; then
		F_menu_exit
	fi
} ### web_update_check

F_update_mail_notify() {
	F_terminal_check "Sending update notification Email..."
	{
		[ -n "$user_send_to_cc" ] && echo "Cc: $user_send_to_cc"
		echo "Subject: Update available for wicens script"
		echo "From: $user_from_name <$user_from_addr>"
		echo "Date: $(F_date full)"
		echo ""
		echo "NOTICE"
		echo ""
		echo "Update is available for wicens script on your $fw_device_model"
		echo ""
		if [ "$update_avail" != 'hotfix' ] ; then
			echo "Version $update_avail is available"
			echo ""
			echo "Change log :"
			echo "$(/usr/sbin/curl -fsL --retry 3 "https://raw.githubusercontent.com/maverickcdn/wicens/master/CHANGELOG.md" | /bin/sed -n "/^## $git_version/,/^## $script_version/p" | head -n -1 | /bin/sed 's/## //')"
		else
			echo "A hotfix is available for version $script_version of wicens"
			echo ""
			echo "Change log :"
			echo "$(/usr/sbin/curl -fsL --retry 3 "https://raw.githubusercontent.com/maverickcdn/wicens/master/CHANGELOG.md" | /bin/sed -n "/^## $script_version/,/^##/p" | head -n -1 | /bin/sed 's/## //')"
		fi
		echo ""
		echo "Run wicens script on your router and select option u to update"
		echo ""
		echo "Message sent: $(F_date full)"
		echo "----------------------------------------------------------------------------"
		echo ""
	} > "$mail_file"

	rm -f "$mail_log" 2> /dev/null

	if ! F_send_message; then
		F_log "Error, failed to send update notification Email"
		user_pswd=''
		rm -f "$mail_file"
		return 1   # skip below hopefully resend next cron if message fail
	fi

	user_pswd=''
	rm -f "$mail_file"
	rm -f "$wicens_update_retry"
	F_log_terminal_ok "Finished sending update notification Email"
	F_replace_var update_notify_state 1 "$update_src"
} ### update_mail_notify

F_local_script_update() {
	F_terminal_header

	if [ "$settings_test" = 'OK' ] && [ ! -f "$script_backup_file" ] ; then
		F_terminal_warning
		F_terminal_check_fail "No backup file exists for your config." ; F_terminal_padding
		F_terminal_show "Recommended to create a backup before upgrading" ; F_terminal_padding
		F_terminal_check "C|c to continue - Any key to return to Main Menu"
		read -rsn1 updatebackupwait
		case $updatebackupwait in
			C|c) printf '\r%b' "$tERASE$tBACK$tERASE$tBACK$tERASE" ;;
			*) F_clean_exit reload ;;
		esac
	fi

	saved_update="$update_avail"
	F_terminal_show "Starting script update to ver: $update_avail" ; F_terminal_padding
	F_web_update_check   # confirm saved update avail is current, notify if not

	if [ "$update_avail" != "$saved_update" ] ; then
		F_terminal_check_fail "Error, current downloadable update is newer than saved available update"
		F_terminal_check_ok "Updating with newest update version $update_avail"
	fi

	F_terminal_check "Dowloading...."
	sleep 1

	if /usr/sbin/curl -fsL --retry 3 --connect-timeout 15 "$script_git_src" -o /jffs/scripts/wicens.sh ; then
		[ ! -x "$script_name_full" ] && F_chmod "$script_name_full"
		F_terminal_check_ok "Success, newest script ver $update_avail installed" ; F_terminal_padding
		F_replace_var update_avail "none" "$update_src"
		F_replace_var update_date "$(F_date full)" "$config_src"

		# reset email notifications for new updates
		[ "$update_notify_state" = 1 ] && F_replace_var update_notify_state 0 "$update_src"
	else
		F_terminal_check_fail "Error, failed downloading/saving new script version"
		F_terminal_padding
		F_menu_exit
	fi

	F_terminal_padding
	git_version="$($git_get | grep 'script_version' | head -n1 | cut -d"=" -f2 | /bin/sed "s/'//g")"
	/usr/sbin/curl -fsL --retry 3 "https://raw.githubusercontent.com/maverickcdn/wicens/master/CHANGELOG.md" | /bin/sed -n "/$git_version"'/,/##/p' | head -n -1 | /bin/sed 's/## //'
	F_terminal_padding ; F_terminal_check "Any key to restart script"

	read -rsn1 restartupdatewait
	F_clean_exit reload
} ### local_script_update

F_fw_update_notify() {
	new_fw_ver="$(F_nvram_get webs_state_info)"
	new_fw_ver_pretty="$(echo "$new_fw_ver" | /usr/bin/awk -F '_' '{print $2 "." $3 "_" $4}')"
	F_log_terminal_ok "Sending notification Email for available firmware update version $new_fw_ver_pretty ..."
	{
		[ -n "$user_send_to_cc" ] && echo "Cc: $user_send_to_cc"
		echo "Subject: Firmware Update version $new_fw_ver_pretty available"
		echo "From: $user_from_name <$user_from_addr>"
		echo "Date: $(F_date full)"
		echo ""
		echo "NOTICE"
		echo ""
		echo "Update to Firmware version $new_fw_ver_pretty is available for your $fw_device_model"
		echo ""
		echo "Visit https://www.asuswrt-merlin.net"
		echo ""
		echo "Message sent: $(F_date full)"
		echo "----------------------------------------------------------------------------"
		echo ""
	} > "$mail_file"

	rm -f "$mail_log" 2> /dev/null

	if ! F_send_message; then
		F_log "Error, failed to send firmware update notification Email"
		user_pswd=''
		rm -f "$mail_file"
		return 1
	fi

	user_pswd=''
	rm -f "$mail_file"
	rm -f "$wicens_fw_retry"
	F_log_terminal_ok "Finished sending firmware update notification Email"
	F_replace_var update_fw_notify_state 0 "$update_src"
} ### fw_update_notify

F_fw_updates() {
	if [ "$1" = 'check' ] ; then
		if [ -f '/jffs/scripts/update-notification' ] ; then
			if grep -q "$script_name_full fwupdate" '/jffs/scripts/update-notification' ; then
				return 0
			fi
		fi
		return 1
	fi

	if [ "$1" = 'add' ] ; then
		if [ -f '/jffs/scripts/update-notification' ] ; then
			F_crlf '/jffs/scripts/update-notification'
			[ ! -x '/jffs/scripts/update-notification' ] && F_chmod '/jffs/scripts/update-notification'

			F_terminal_check "Adding wicens to update-notification script"

			if ! grep -q '#!/bin/sh' '/jffs/scripts/update-notification' ; then
				F_terminal_check_fail "Your update-notification does not contain a '#!/bin/sh', please investigate and run again"
				F_log "Your update-notification does not contain a '#!/bin/sh', please investigate and run again"
				F_clean_exit
			fi

			echo "(sh /jffs/scripts/$script_name fwupdate) & wicenspid=\$!   # added by wicens $(F_date full)" >> '/jffs/scripts/update-notification'
			echo "logger -t \"update-notification[\$\$]\" \"Started wicens with pid \$wicenspid\"   # added by wicens $(F_date full)" >> '/jffs/scripts/update-notification'
			F_terminal_check_ok "ADDED wicens entry to update-notification"
		else
			touch '/jffs/scripts/update-notification'
			F_terminal_check_ok "Created update-notification in /jffs/scripts/"

			if echo '#!/bin/sh' >> /jffs/scripts/update-notification ; then
				if echo "(sh $script_name_full fwupdate) & wicenspid=\$!  # added by wicens $(F_date full)" >> /jffs/scripts/update-notification ; then
					echo "logger -t \"update-notification[\$\$]\" \"Started wicens with pid \$wicenspid\"   # added by wicens $(F_date full)" >> '/jffs/scripts/update-notification'
					F_chmod '/jffs/scripts/update-notification'
					F_terminal_check_ok "ADDED entry for wicens fwupdate in /jffs/scripts/update-notification"
					F_log "Created update-notification in /jffs/scripts/ and added entry for wicens"
				else
					F_log_show "Critical error, failed writing to update-notification"
					F_clean_exit
				fi
			else
				F_terminal_check_fail "Critical error, failed to add 'shebang' to update-notification"
				F_log "Critical error, failed to add 'shebang' to update-notification"
				F_clean_exit
			fi
		fi

		F_replace_var user_fw_update_notification 0 "$config_src"
	fi

	if [ "$1" = 'remove' ] ; then
		F_terminal_check "Removing wicens entry in update-notification"
		if [ -f '/jffs/scripts/update-notification' ] ; then
			if grep -q "$script_name_full fwupdate" '/jffs/scripts/update-notification' ; then
				/bin/sed -i "\| $script_name_full |d" '/jffs/scripts/update-notification'
				/bin/sed -i '/Started wicens with pid/d' '/jffs/scripts/update-notification'
				F_log_terminal_ok "Removed update-notification entry for wicens"
			else
				F_terminal_check_ok "No entry found for wicens in /jffs/scripts/update-notification to remove"
			fi

			if [ "$(wc -l < /jffs/scripts/update-notification)" -eq 1 ] ; then
				if grep -q "#!/bin/sh" "/jffs/scripts/update-notification"; then
					F_log_terminal_ok "/jffs/scripts/update-notification appears empty, removing file"
					rm -f /jffs/scripts/update-notification
				fi
			fi
		else
			F_terminal_check_ok "/jffs/scripts/update-notification doesn't exist"
		fi

		F_replace_var user_fw_update_notification 1 "$config_src"
	fi
} # fw_updates

# SCRIPT TEST/CONTROL #################################################################################################

F_settings_test() {
	settings_test='OK'
	amtm_status='FAIL'

	# amtm check valid
	if F_opt_amtm check ; then
		amtm_status='OK'

		# if sync enabled confirm sync
		if [ "$amtm_import" = 0 ] ; then
			F_opt_amtm confirm
		fi
	fi

	if [ -z "$user_from_addr" ] || [ -z "$user_message_type" ] || [ -z "$user_send_to_addr" ] || [ -z "$user_smtp_server" ] ; then
		settings_test='FAIL'
		fail_reason="$(printf "[%bFAIL%b] Missing core settings \n\n" "$tRED" "$tCLR")"
	fi

	[ "$user_message_count" -eq 0 ] && settings_test='FAIL'

	if [ "$user_message_count" -ge 2 ] && [ -z "$user_message_interval_1" ] ; then
		fail_reason="$(printf "[%bFAIL%b] Email notifications set to %s, missing interval 1/2 value \n\n" "$tRED" "$tCLR" "$user_message_count")"
		F_log "Email notifications set to $user_message_count, missing interval 1/2 value"
		settings_test='FAIL'
	fi

	if [ "$user_message_count" -ge 3 ] && [ -z "$user_message_interval_2" ] ; then
		fail_reason="$(printf "[%bFAIL%b] Email notifications set to %s, missing interval 2/3 value \n\n" "$tRED" "$tCLR" "$user_message_count")"
		F_log "Email notifications set to $user_message_count, missing interval 2/3 value"
		settings_test='FAIL'
	fi

	if [ "$user_message_count" -eq 4 ] && [ -z "$user_message_interval_3" ] ; then
		fail_reason="$(printf "[%bFAIL%b] Email notifications set to %s, missing interval 3/4 value \n\n" "$tRED" "$tCLR" "$user_message_count")"
		F_log "Email notifications set to $user_message_count, missing interval 3/4 value"
		settings_test='FAIL'
	fi

	if [ ! -f "$cred_loc" ] && [ "$user_message_type" != 'smtp_isp_nopswd' ] && [ "$settings_test" = 'OK' ] ; then
		fail_reason="$(printf "[%bFAIL%b] Email send type set to %s but missing required password \n\n" "$tRED" "$tCLR" "$user_message_type")"
		F_log "Email send type set to $user_message_type but missing required password"
		settings_test='FAIL'
	fi

	if [ "$user_message_count" = '0' ] && [ "$settings_test" = 'OK' ] ; then
		fail_reason="$(printf "[%bFAIL%b] Missing total Email notifications count \n\n" "$tRED" "$tCLR")"
		settings_test='FAIL'
	fi

	# CLEAN UP
	# clean old user_pswd if setup was edited
	[ -f "$cred_loc" ] && [ "$user_message_type" = 'smtp_isp_nopswd' ] && rm -f "$cred_loc"

	# if old intervals exist but message count changed to 1, reset intervals
	if [ -n "$user_message_interval_1" ] || [ -n "$user_message_interval_2" ] || [ -n "$user_message_interval_3" ] ; then
		if [ "$user_message_count" = '1' ] ; then
			F_replace_var user_message_interval_1 "''" "$config_src"
			F_replace_var user_message_interval_2 "''" "$config_src"
			F_replace_var user_message_interval_3 "''" "$config_src"
		fi
	fi

	# only if someone manually deletes saved WAN IP
	if [ -z "$saved_wan_ip" ] && [ "$settings_test" = 'OK' ] && [ "$passed_options" = 'manual' ] ; then
		F_saved_wan_ip_create
		F_log_show "Missing WAN IP"
		F_clean_exit reload
	fi

	if [ "$settings_test" = 'OK' ] ; then
		return 0
	else
		return 1
	fi
} ### settings_test

F_ready_check() {
	if [ "$settings_test" != 'OK' ] ; then
		if [ "$from_menu" = 'yes' ] ; then
			[ "$1" = 'pswdset' ] && return 0
			[ "$1" != 'options' ] && F_terminal_header ; F_terminal_padding   # not sent here from a menu option, displayed already
			F_terminal_check_fail "Error, no Email settings have been setup"
			F_terminal_padding; F_terminal_show "Use menu option 1 to add settings"
			F_menu_exit
		else
			[ "$passed_options" != 'manual' ] && F_log "CRITICAL ERROR, no/incomplete Email config found in this script"
			[ "$passed_options" != 'manual' ] && F_log "Run $script_name_full to add a config to this script"
			F_clean_exit fail
		fi
		return 1

	else # passes test but trying to establish pswd with isp_type or incomplete settings
		if [ "$1" = 'pswdset' ] ; then
			if [ "$user_message_type" = 'smtp_isp_nopswd' ] || [ -z "$user_message_type" ] ; then
				F_terminal_check_fail "Cannot add password, SMTP type is either empty or set to ISP type"
				F_terminal_padding ;F_terminal_show "Use menu option 1 to edit settings"
				F_menu_exit
			fi
		fi
		return 0
	fi
} ### ready_check   runs F_settings test and allows or not

F_clean_exit() {
	[ "$1" = 'reload' ] && exec /bin/sh "$script_name_full" reload

	F_terminal_check "Exiting, removing $script_lock file"
	[ -f "$script_lock" ] && rm -f "$script_lock"
	[ -f "$script_mail_lock" ] && rm -f "$script_mail_lock"
	[ -f "$ntp_lock" ] && rm -f "$ntp_lock"

	if [ ! -f "$script_lock" ] ; then
		F_terminal_check_ok "Removed $script_lock file"

		printf "%b Goodbye%b \n\n" "$tERASE$tCHECKOK$tYEL" "$tCLR"
		[ "$1" = 'reset' ] && exec /bin/sh "$script_name_full"
		[ "$1" = 'fail' ] && exit 1
		exit 0
	else
		if [ "$$" != "$(/bin/sed -n '2p' "$script_lock")" ] ; then
			F_terminal_check_ok "Exiting, removing $script_lock file"
			F_terminal_show "Lock file still present but not from this process..."
			F_terminal_show "likely another process started while this one was exiting"
			[ "$1" = 'reload' ] && exec /bin/sh "$script_name_full"
			[ "$1" = 'fail' ] && exit 1
			exit 0
		else
			F_terminal_check_fail "CRITICAL ERROR - Failed to remove lock file"
			F_log "CRITICAL ERROR - Failed to remove lock file"
			exit 99
		fi
	fi
} ### clean_exit

# STATUS/TERMINAL #####################################################################################################
#######################################################################################################################

F_terminal_header() {
	clear
	/bin/sed -n '2,11p' "$script_name_full"

	if [ "$fw_build_no" = '384' ] || [ "$fw_build_no" = '386' ] ; then
		printf "%5s%b%s%b -- %bver: %s%b -- %b%s%b FW ver: %b%s.%s_%s%b\n" "" "$tGRN" "$(F_date full)" "$tCLR" "$tYEL" "$script_version" "$tCLR" "$tGRN" "$fw_device_model" "$tCLR" "$tGRN" "$fw_build_no" "$fw_build_sub" "$fw_build_extend" "$tCLR"
	else
		printf "%2s%b%s%b -- %bver: %s%b -- %b%s%b FW ver: %b%s.%s%b\n" "" "$tGRN" "$(F_date full)" "$tCLR" "$tYEL" "$script_version" "$tCLR" "$tGRN" "$fw_device_model" "$tCLR" "$tGRN" "$fw_build_no" "$fw_build_extend" "$tCLR"
	fi

	[ "$test_mode" = 'yes' ] && printf "%b %b###  Test Mode - Sending $user_message_count message(s) ### %b\n" "$tTERMHASH" "$tYEL" "$tCLR"
	F_terminal_separator
} ### terminal_header

F_status() {
	update_rem=$((update_period - update_diff))
	F_terminal_header
	[ "$building_settings" = 'yes' ] && printf '%b %bWelcome to the WICENS setup - E|e to exit at anytime %b \n' "$tTERMHASH" "$tGRN" "$tCLR" && F_terminal_padding
	[ "$edit_settings" = 'yes' ] &&	printf '%b %bWelcome to the WICENS config editor %b\n' "$tTERMHASH" "$tGRN" "$tCLR" && F_terminal_padding

	F_terminal_header_print "Current saved WAN IP             : " "$saved_wan_ip"
	F_terminal_header_print "Current Email send to address    : " "$user_send_to_addr"
	F_terminal_header_print "Current Email send to CC address : " "$user_send_to_cc"
	F_terminal_header_print "Current Email server addr:port   : " "$user_smtp_server"
	F_terminal_header_print "Current Email send format type   : " "$user_message_type"
	[ -f "$cred_loc" ] && F_terminal_header_print "Current Email password           : " "Pswd saved"
	F_terminal_header_print "Current Email send from address  : " "$user_from_addr"
	F_terminal_header_print "Current Email message from name  : " "$user_from_name"
	F_terminal_header_print "Total # Email notifications set  : " "$user_message_count"
	[ "$user_message_count" -gt 1 ] 2>/dev/null && F_terminal_header_print "Interval between Email 1/2       : " "$user_message_interval_1"
	[ "$user_message_count" -gt 2 ] 2>/dev/null && F_terminal_header_print "Interval between Email 2/3       : " "$user_message_interval_2"
	[ "$user_message_count" -gt 3 ] 2>/dev/null && F_terminal_header_print "Interval between Email 3/4       : " "$user_message_interval_3"
	[ "$user_message_type" = "smtp_ssl" ] && F_terminal_header_print "Current Email protocol           : " "$protocol"
	F_terminal_header_print "Cron run interval                : " "10 minutes"

	if [ -n "$user_custom_subject" ] ; then
		user_custom_subject_show="$user_custom_subject_decoded"
		[ ${#user_custom_subject_show} -gt 31 ] && user_custom_subject_show="$(echo "$user_custom_subject_decoded" | cut -c -28 | /bin/sed 's/$/.../g')"
		F_terminal_header_print "Custom Subject line set          : " "$user_custom_subject_show"
	fi

	if [ -n "$user_custom_text" ] ; then
		user_custom_text_show="$user_custom_text_decoded"
		[ ${#user_custom_text_show} -gt 31 ] && user_custom_text_show="$(echo "$user_custom_text_decoded" | cut -c -28 | /bin/sed 's/$/.../g')"
		F_terminal_header_print "Custom message text is set       : " "$user_custom_text_show"
	fi

	if [ -n "$user_custom_script_decoded" ] ; then
		user_custom_script_show="$user_custom_script_decoded"
		[ ${#user_custom_script_show} -gt 31 ] && user_custom_script_show="$(echo "$user_custom_script_decoded" | cut -c 28- | /bin/sed 's/^/.../g')"
		F_terminal_header_print "Custom script path               : " "$user_custom_script_show"
	fi

	[ -n "$user_script_call_time" ] && F_terminal_header_print "Custom script call time          : " "$user_script_call_time"
	F_terminal_header_print "Number of cron checks            : " "$cron_run_count"
	F_terminal_header_print "Number of wan-event checks       : " "$wancall_run_count"
	F_terminal_header_print "Total IP changes since install   : " "$ip_change_count"
	F_terminal_header_print "Script install date              : " "$install_date"
	[ -n "$update_date" ] && F_terminal_header_print "Script last updated date         : " "$update_date"
	F_terminal_header_print "Script configured date           : " "$created_date"
	[ -n "$saved_wan_date" ] && F_terminal_header_print "Current saved WAN IP recorded on : " "$saved_wan_date"
	[ -n "$last_cron_run" ] && F_terminal_header_print "Last monitored with cron         : " "$last_cron_run"
	[ -n "$last_wancall_run" ] && F_terminal_header_print "Last ran with wan-event          : " "$last_wancall_run"
	[ -n "$saved_wan_epoch" ] && F_terminal_header_print "Current saved WAN IP lease age   : " "$(F_calc_lease)"
	[ -n "$last_ip_change" ] && F_terminal_header_print "Last IP change                   : " "$last_ip_change"

	router_uptime="$(/usr/bin/awk '{print $1}' /proc/uptime | cut -d'.' -f1)"
	uptime_pretty="$(printf '%dd %dh %dm %dsec\n' $((router_uptime/86400)) $((router_uptime%86400/3600)) $((router_uptime%3600/60)) $((router_uptime%60)))"
	F_terminal_header_print "Current router uptime            : " "$uptime_pretty"

	[ "$user_update_notification" = '0' ] && [ "$update_avail" = 'none' ] && F_terminal_header_print "Secs to next update check w/cron : " "$update_rem"

	if [ "$amtm_import" = 0 ] && [ "$amtm_status" = 'OK' ] ; then
		F_terminal_header_print "Sync from AMTM Email config      : " "Enabled"
	else
		F_terminal_header_print_d "Sync from AMTM Email config      : " "Disabled"
	fi

	if F_auto_run checkall && [ "$settings_test" = 'OK' ] ; then
		F_terminal_header_print "WAN IP change Email notify       : " "Enabled"
	else
		F_terminal_header_print_d "WAN IP change Email notify       : " "Disabled"
	fi


	if F_auto_run checkall && [ "$user_update_notification" = 0 ] && [ "$settings_test" = 'OK' ] ; then
		F_terminal_header_print "Script update Email notify       : " "Enabled"
	else
		F_terminal_header_print_d "Script update Email notify       : " "Disabled"
	fi

	if [ "$user_fw_update_notification" = 0 ] && [ "$settings_test" = 'OK' ] ; then
		F_terminal_header_print "Firmware update Email notify     : " "Enabled"
	else
		F_terminal_header_print_d "Firmware update Email notify     : " "Disabled"
	fi

	[ "$update_avail" != 'none' ] && [ "$update_avail" != 'hotfix' ] && F_terminal_header_print "New version is available!        : " "Version $update_avail"
	[ "$update_avail" != 'none' ] && [ "$update_avail" = 'hotfix' ] && F_terminal_header_print "Hotfix update is available!      : " "Hotfix for v$script_version"
	
	F_terminal_header_print "Config file versions             : " "User: v$build_settings_version Core: v$update_settings_version"
	F_terminal_show '---------------------------------------------------------------------'

	if [ "$1" = 'view' ] ; then
		if [ "$settings_test" != 'OK' ] ; then
			printf '%s\n' "$fail_reason"
		fi
		F_cru check
		F_serv_start check
		F_wan_event check
		return 0
	fi
} ### status

# Menu ################################################################################################################
#######################################################################################################################

F_menu_exit() {
	F_terminal_padding
	F_terminal_check "Any key to return to the Main Menu - E||e to Exit"

	read -rsn1 exitwait
	case $exitwait in
		e|E) F_terminal_check_ok "Exiting." ; F_clean_exit ;;
		*) F_clean_exit reload ;;
	esac
} ### menu_exit

F_main_menu() {
	F_terminal_header

	selection=''
	from_menu='yes'
	printf "       Option                      Select   Status \n" ;F_terminal_separator

	if F_auto_run checkall && [ "$settings_test" = 'OK' ] ; then
		F_terminal_header_print "WAN IP change Email notify---: M||m " "Enabled"
	else
		F_terminal_header_print_d "WAN IP change Email notify---: M||m " "Disabled"
	fi

	if [ "$settings_test" = 'OK' ] ; then
		F_terminal_header_print "Create/Edit Email settings---: 1    " "Exists"
	else
		F_terminal_header_print_d "Create/Edit Email settings---: 1    " "Incomplete - V|v to view errors"
	fi

	printf "%b Custom Email msg text--------: 2     " "$tTERMHASH"
	if [ -n "$user_custom_text" ] ; then
		printf "%bExists%b\n" "$tGRN" "$tCLR"
	else
		printf "%bUnused%b\n" "$tPUR" "$tCLR"
	fi

	printf "%b Custom Email msg subject-----: 3     " "$tTERMHASH"
	if [ -n "$user_custom_subject" ] ; then
		printf "%bExists%b\n" "$tGRN" "$tCLR"
	else
		printf "%bUnused%b\n" "$tPUR" "$tCLR"
	fi

	printf "%b Custom script execution------: 4     " "$tTERMHASH"
	if [ -n "$user_custom_script" ] ; then
		printf "%bExists%b   -   Action:%b %s%b \n" "$tGRN" "$tCLR" "$tGRN" "$user_script_call_time" "$tCLR"
	else
		printf "%bUnused%b\n" "$tPUR" "$tCLR"
	fi

	printf "%b Script update Email notify---: 5     " "$tTERMHASH"
	if [ "$user_update_notification" = 0 ] && [ "$settings_test" = 'OK' ] && F_auto_run checkall ; then
		printf "%bEnabled%b\n" "$tGRN" "$tCLR"
	else
		printf "%bDisabled%b\n" "$tRED" "$tCLR"
	fi

	printf "%b Firmware update Email notify-: 6     " "$tTERMHASH"
	if F_fw_updates check ; then
		if [ "$user_fw_update_notification" = 0 ] && [ "$settings_test" = 'OK' ] ; then
			printf "%bEnabled%b\n" "$tGRN" "$tCLR"
		else
			printf "%bDisabled%b\n" "$tRED" "$tCLR"
		fi
	else
		printf "%bDisabled%b\n" "$tRED" "$tCLR"
	fi

	if [ "$amtm_status" = 'OK' ] && [ "$settings_test" = 'FAIL' ] ; then
		F_terminal_header_print "AMTM Email config found------: 9    " "Ready to import"
	fi

	if [ "$settings_test" != 'OK' ] && [ -f "$script_backup_file" ] ; then
		F_terminal_header_print "Backup Email config----------: B||b " "Found - option B|b to restore"
	fi

	F_terminal_separator
	F_terminal_show "View current status/settings-: V||v"
	F_terminal_show "Show sample Email------------: S||s"
	F_terminal_show "Send a test Email------------: T||t"
	F_terminal_show "Show Email send log----------: L||l"
	F_terminal_show "Reset cron/wan-event counts--: N||n"
	F_terminal_show "Email password update entry--: P||p"
	F_terminal_show "Reset script to default------: R||r"
	F_terminal_show "Disable WAN IP Email notify--: D||d"
	F_terminal_show "Toggle terminal color on/off-: C||c"
	F_terminal_show "Uninstall script-------------: U||u"
	F_terminal_show "Backup/Restore settings menu-: B||b"

	if [ "$update_avail" != 'none' ] && [ "$update_avail" != 'hotfix' ] ; then
		F_terminal_header_print "Update script----------------: I||i "  "Update available - version $update_avail"
	elif [ "$update_avail" != 'none' ] && [ "$update_avail" = 'hotfix' ] ; then
		F_terminal_header_print "Update script----------------: I||i " "Hotfix available!"
	else
		F_terminal_show "Check for script update------: F||f"
	fi

	F_terminal_show "About script-----------------: A||a"
	F_terminal_show "Exit-------------------------: E||e"

	F_terminal_padding ;F_terminal_check "Selection : "

	read -r selection
	printf "%b" "$tBACK$tERASE"

	case $selection in
		1) if [ "$settings_test" = 'OK' ] ; then
				F_edit_settings
			else
				F_build_settings
			fi
			;;
		'1f'|'1F') F_build_settings ;;
		2) until F_opt_custom ; do : ; done ; F_menu_exit ;;
		3) until F_opt_subject ; do : ; done ; F_menu_exit ;;
		4) until F_opt_script ; do : ; done ; F_menu_exit ;;
		5) F_opt_notifications ;;
		6) F_opt_fw_notifications ;;
		9) if [ "$amtm_status" = 'OK' ] && [ "$settings_test" = 'FAIL' ] ; then
				F_opt_amtm import
			else
				printf "%b %s is an invalid entry, any key to retry" "$tCHECKFAIL" "$selection" ; read -rsn1 invalidwait ; return 1
			fi
			;;
		a|A) F_opt_about ;;
		b|B) F_opt_backup_restore ;;
		c|C) F_opt_color ;;
		d|D) F_opt_disable ;;
		e|E) F_clean_exit ;;
		f|F) F_web_update_check force ;;
		i|I) if [ "$update_avail" != 'none' ] ; then   # option only avail if we found an update
				F_local_script_update
			else
				printf "%b %s is an invalid entry, any key to retry" "$tCHECKFAIL" "$selection" ; read -rsn1 invalidwait ; return 1
			fi
			;;
		l|L) F_opt_error ;;
		m|M) F_opt_manual ;;
		n|N) F_opt_count ;;
		p|P) until F_opt_pswd ; do : ; done ; F_menu_exit ;;
		r|R) F_opt_reset ;;
		s|S) F_opt_sample ;;
		t|T) passed_options='test' ;;   #  fall through to settings test then check arg
		u|U) F_opt_uninstall ;;
		v|V) F_status view && F_menu_exit ;;
		*) [ -n "$selection" ] && printf "%b %s is an invalid entry, any key to retry" "$tCHECKFAIL" "$selection" && read -rsn1 invalidwait && return 1 ;;
	esac
}   ### main menu

#######################################################################################################################
################### Start - check/set ntp/time - lock check/set - options check #######################################
#######################################################################################################################

F_ntp() {
	ntp_lock='/tmp/wicens_ntp.lock'
	[ -f "$ntp_lock" ] && exit 0   # script already running waiting on NTP sync

	if [ "$(F_nvram_get ntp_ready)" -ne 1 ] ; then
		echo "$$" > "$ntp_lock" ; echo "wicens ntp lock" >> "$ntp_lock"
		ntp_wait_time=0
		F_log_show "NTP is not synced, waiting upto 600 seconds (10min) checking every second for NTP sync...   CTRL+C to exit"

		while [ "$(F_nvram_get ntp_ready)" -ne 1 ] && [ "$ntp_wait_time" -lt 600 ] ; do
			ntp_wait_time="$((ntp_wait_time + 1))"
			printf '\r%b Elapsed time : %s secs' "$tTERMHASH" "$ntp_wait_time"
			sleep 1
			printf '%b' "$tERASE"
		done

		if [ "$ntp_wait_time" -ge 600 ] ; then
			F_log_show "NTP failed to sync and update router time after 10 mins"
			F_log_show "Please check your NTP date/time settings"
			rm -f "$ntp_lock" && F_clean_exit
		fi
	fi

	[ -f "$ntp_lock" ] && rm -f "$ntp_lock"   # remove ntplock on success after waiting for ntp
	# time set
	TZ="$(cat /etc/TZ)"
	export TZ
	run_date="$(F_date full)"
	run_epoch="$(F_date sec)"
} ### ntp

F_lock() {
	if [ "$1" = 'create' ] ; then
		touch "$script_lock"
		{
		echo "wicens lock file"
		echo "$$"
		echo "$(F_date sec)"
		echo "Lockfile for $script_name_full to prevent duplication"
		echo "Created $run_date"
		echo "Option : $passed_options "
		} >> "$script_lock"
		return 0
	fi

	# if lock exists already check age/process etc
	if [ -f "$script_lock" ] ; then
		locked_process="$(/bin/sed -n '2p' $script_lock)"   # pid
		process_created="$(/bin/sed -n '5p' $script_lock)"   # started on
		process_calledby="$(/bin/sed -n '6p' $script_lock)"  # created by
		process_time="$(/bin/sed -n '3p' $script_lock)"   # started seconds time
		lock1_diff_time="$((run_epoch - process_time))"
		F_terminal_header
		F_terminal_show "wicens failed to start"
		F_terminal_padding

		if [ -f "$script_mail_lock" ] ; then   # if wicens.lock doesnt exist neither should this, so only check this if first lock exists
			# calculate wicenssendmail.lock age limit from user interval settings
			loop_count_run=3		# check user_message_intervals and convert to seconds to check lock file age limits

			while [ "$loop_count_run" != '0' ] ; do
				newval="$(eval 'echo "${user_message_interval_'"$loop_count_run"'}"')"   # reading variable user_message_interval_1/2/3
				interval_type="$(echo "$newval" | /bin/sed -e "s/^.*\(.\)$/\1/")"	# strip second,minute,hour,day
				time_period="$(echo "$newval" | /bin/sed 's/[a-z]$//')"	# strip time value
				if [ "$interval_type" = 'd' ] ; then
					time_factor='86400'
				elif [ "$interval_type" = 'h' ] ; then
					time_factor='3600'
				elif [ "$interval_type" = 'm' ] ; then
					time_factor='60'
				else
					time_factor='1'
				fi
				converted_seconds=$((time_period * time_factor))
				if [ "$loop_count_run" = '3' ] ; then
					interval_time_count_3="$converted_seconds"
				elif [ "$loop_count_run" = '2' ] ; then
					interval_time_count_2="$converted_seconds"
				elif [ "$loop_count_run" = '1' ] ; then
					interval_time_count_1="$converted_seconds"
				fi
				loop_count_run=$((loop_count_run - 1))
			done

			check_lock_count=$((interval_time_count_1+interval_time_count_2+interval_time_count_3+100))  # add 100secs just incase script happens to be exiting or had start delays reads original wicens.lock start date seconds

			if [ "$((run_epoch - $(/bin/sed -n '4p' $script_mail_lock)))" -gt "$check_lock_count" ] ; then
				rm -f "$script_mail_lock"
				printf "%b from %s on %s\n" "$tTERMHASH" "$process_calledby" "$process_created"
				F_terminal_show "Removed stale wicenssendmail.lock file, any key to continue"
				F_log "NOTICE - Removed stale wicenssendmail.lock file started by $process_calledby on $process_created"
				[ "$passed_options" = 'manual' ] && read -rsn1 staleremove
			else
				if [ ! -d "/proc/$locked_process" ] ; then # process that created doesnt exist
					F_log_show "CRITICAL ERROR - wicens.lock and wicenssendmail.lock exist"
					F_log "CRITICAL ERROR - files $process_created by $process_calledby"
					printf "%b created %s by %s\n" "$tTERMHASH" "$process_created" "$process_calledby"
					F_log_show "Process that created doesn't exist, script was killed during Email send"
					rm -f "$script_lock"
					rm -f "$script_mail_lock"
					F_log_show "CRITICAL ERROR - Removed dead wicens.lock and wicenssendmail.lock files"
					[ "$passed_options" = 'manual' ] && F_terminal_check "Any key to continue" && read -rsn1 staleremove
				else
					F_terminal_show "wicens.lock and wicenssendmail.lock exist"
					F_terminal_show "Lock files not over age limit"
					F_terminal_show "Process still exists, likely sending Email notifcations."
					F_terminal_show "Lock file $process_created"
					F_terminal_show "Use sh $script_name_full remove"
					F_terminal_show "To manually remove lock files and kill running processes" ; F_terminal_padding
					[ "$passed_options" = 'manual' ] && F_log "wicens.lock and wicenssendmail.lock exist, lock files not over age limit, process still exists, likely sending Email notifcations."
					exit 0
				fi
			fi
		else
			F_terminal_show "$script_mail_lock doesnt exist but $script_lock does"
		fi    # done checking wicenssendmail.lock

		if [ ! -d "/proc/$locked_process" ] ; then   # process that created doesnt exist
				F_terminal_show "NOTICE - Removed stale wicens.lock file, process doesn't exist"
				F_log "NOTICE - Process doesn't exist - Removed stale wicens.lock file, $process_calledby and started $process_created"
				rm -f "$script_lock"
				F_terminal_padding ;F_terminal_show "Any key to start script"
				[ "$passed_options" = 'manual' ] && read -rsn1 lock_notify_wait
		else
			if [ "$lock1_diff_time" -gt 330 ] ; then   # based on if internet is down google attempts is 5 mins
				F_log_show "Lock file exists for running process older than 5 mins but not sending Email"
				printf "%b Killing process %s and deleting lock file %s" "$tTERMHASH" "$locked_process" "$process_created"
				F_log "Killing old process $locked_process started by $process_calledby and deleting lock file $process_created"
				/bin/kill "$locked_process"
				rm -f "$script_lock"
				F_log_show "Done, killed stale process, removed lock file"
				F_terminal_padding ;F_terminal_show "Any key to start script"
				[ "$passed_options" = 'manual' ] && read -rsn1 lock_notify_wait
			else
				F_terminal_show "wicens.lock file exists, but is not yet 5 mins old"
				F_terminal_show "wait till lock file ages, or remove manually with option 'remove'"
				printf "%b wicens.lock file process %s\n"  "$tTERMHASH" "$process_created"
				printf "%b wicens.lock file created by %srun\n" "$tTERMHASH" "$process_calledby" ;F_terminal_padding
				exit 0
			fi
		fi
	fi # end of wicens.lock and wicenssendmail.lock
# locks dont exist/removed continue below
} ### lock_check

F_integrity_check() {
	if [ "$update_settings_version" != "$current_core_config" ] ; then   # if new updated core config differs from saved, update
		F_terminal_header
		F_log_terminal_fail "wicens core config is not current, updating"
		# current file is already sourced, remove file and change new file with loaded vars
		rm -f "$update_src"
		F_default_update_create && F_log_terminal_ok "core config v${current_core_config} created, updating w/user settings/router settings"

		# v2->v3 need to pull for F_firmware_check
		build_full="$(F_nvram_get buildno)"
		build_no="$(echo "$build_full" | cut -f1 -d '.')"
		build_sub="$(echo "$build_full" | cut -f2 -d '.')"
		build_extend="$(F_nvram_get extendno)"

		F_firmware_check

		echo "# Updated ver $current_core_config $(F_date full)" >> "$update_src"

		source "$update_src"
		F_log_terminal_ok "Done, updated wicens core config file to v${current_core_config}"

		if F_auto_run checkall ; then   # if enabled reset if any changes to wan-event/services-start/cru
			F_auto_run remove > /dev/null 2>&1   # remove entries
			F_auto_run add > /dev/null 2>&1   # readd updated entries
			F_log_show "Updated wan-event/services-start/cru entries"
		fi
		F_terminal_check "Any key to continue..."
		read -rsn1 updatedwait
		printf '\r%b' "$tERASE"
	fi

	if [ "$build_settings_version" != "$current_user_config" ] ; then   # if new updated user config differs from saved, update
		F_terminal_header
		F_log_terminal_fail "wicens user config is not current, updating"
		# current file is already sourced, remove file and change new file with loaded vars
		rm -f "$config_src"
		F_default_create && F_log_terminal_ok "user config v${current_user_config} created, updating w/user settings"

		F_replace_var saved_wan_ip "$saved_wan_ip" "$config_src"
		F_replace_var saved_wan_date "$saved_wan_date" "$config_src"
		F_replace_var saved_wan_epoch "$saved_wan_epoch" "$config_src"
		F_replace_var user_from_name "$user_from_name" "$config_src"
		F_replace_var user_smtp_server "$user_smtp_server" "$config_src"
		F_replace_var user_from_addr "$user_from_addr" "$config_src"
		F_replace_var user_send_to_addr "$user_send_to_addr" "$config_src"
		F_replace_var user_send_to_cc "$user_send_to_cc" "$config_src"
		F_replace_var user_message_type "$user_message_type" "$config_src"
		F_replace_var user_message_count "$user_message_count" "$config_src"
		F_replace_var user_message_interval_1 "$user_message_interval_1" "$config_src"
		F_replace_var user_message_interval_2 "$user_message_interval_2" "$config_src"
		F_replace_var user_message_interval_3 "$user_message_interval_3" "$config_src"
		F_replace_var user_custom_subject "$user_custom_subject" "$config_src"
		F_replace_var user_custom_text "$user_custom_text" "$config_src"
		F_replace_var user_custom_script "$user_custom_script" "$config_src"
		F_replace_var user_custom_script_time "$user_custom_script_time" "$config_src"
		[ "$user_update_notification" = 0 ] && F_replace_var user_update_notification 0 "$config_src"
		[ "$user_fw_update_notification" = 0 ] && F_replace_var user_fw_update_notification 0 "$config_src"
		F_replace_var cron_run_count "$cron_run_count" "$config_src"
		F_replace_var last_cron_run "$last_cron_run" "$config_src"
		F_replace_var last_wancall_run "$last_wancall_run" "$config_src"
		F_replace_var wancall_run_count "$wancall_run_count" "$config_src"
		[ -n "$last_ip_change" ] && F_replace_var last_ip_change "$last_ip_change" "$config_src"
		F_replace_var ip_change_count "$ip_change_count" "$config_src"
		F_replace_var install_date "$install_date" "$config_src"
		[ -z "$install_date" ] && F_replace_var install_date "$(F_date full)" "$config_src"   # v2 > v3
		[ -n "$update_date" ] && F_replace_var update_date "$update_date" "$config_src"
		[ -n "$created_date" ] && F_replace_var created_date "$created_date" "$config_src"
		F_replace_var last_wancall_log_count "$last_wancall_log_count" "$config_src"
		F_replace_var opt_color "$opt_color" "$config_src"
		F_replace_var log_cron_msg "$log_cron_msg" "$config_src"
		F_replace_var ssl_flag "$ssl_flag" "$config_src"
		if [ -z "$protocol" ] ; then
			F_replace_var protocol "smtps" "$config_src"
		else
			F_replace_var protocol "$protocol" "$config_src"
		fi
		F_replace_var amtm_import "$amtm_import" "$config_src"

		echo "# Updated from $build_settings_version to $current_user_config $(F_date full)" >> "$config_src"

		source "$config_src"

		F_log_terminal_ok "Done, updated wicens user config file to v${current_user_config}"
		F_terminal_check "Any key to continue..."
		read -rsn1 update2wait
		printf '\r%b' "$tBACK$tERASE"
	fi
} ### config integrity check

F_run_args() {
	if [ "$passed_options" = 'reload' ] ; then   # no need to check other options on script reloads
		until F_main_menu ; do : ; done

	elif [ "$passed_options" = 'manual' ] ; then
		# only check alias/FW ver with manual runs
		build_full="$(F_nvram_get buildno)"
		build_no="$(echo "$build_full" | cut -f1 -d '.')"
		build_sub="$(echo "$build_full" | cut -f2 -d '.')"
		build_extend="$(F_nvram_get extendno)"

		# firmware compatibility check
		if [ -z "$fw_build_no" ] || [ -z "$fw_build_sub" ] || [ -z "$fw_build_extend" ] ; then   # first run will be unpopulated
			F_replace_var install_date "$(F_date full)" "$config_src"
			F_firmware_check
			F_clean_exit reload
		fi

		# check if user has upgraded firmware and update config  saving to config avoids numerous nvram calls every run
		if [ "$fw_build_no" = '386' ] || [ "$fw_build_no" = '384' ] ; then
			if [ "$build_no" -gt "$fw_build_no" ] ; then
				F_firmware_check fwupdate
			elif [ "$build_no" = "$fw_build_no" ] && [ "$build_sub" -gt "$fw_build_sub" ] ; then
				F_firmware_check fwupdate
			elif [ "$build_no" = "$fw_build_no" ] && [ "$build_sub" = "$fw_build_sub" ] && [ "$build_extend" -gt "$fw_build_extend" ] ; then
				F_firmware_check fwupdate
			fi
		elif [ "$fw_build_no" = '374' ] ; then
			johnsub="${build_extend:0:2}"
			if [ "$johnsub" -gt "$fw_build_sub" ] ; then
				F_firmware_check fwupdate
			fi
		fi

		F_alias

		# cleanup password backup if config backup doesnt exist
		[ -f "$cred_loc_bak" ] && [ ! -f "$cred_loc" ] && [ ! -f "$script_backup_file" ] && rm -f "$cred_loc_bak"

		# if Email send failed 5 times we need to clear out the file for future
		if [ -f "$wicens_wanip_retry" ] || [ -f "$wicens_fw_retry" ] || [ -f "$wicens_update_retry" ] || [ -f "$wicens_send_retry" ] ; then
			F_terminal_header
			F_terminal_padding ; F_terminal_show "A failed Email retry file exists... removing" ; F_terminal_padding
			[ -f "$wicens_wanip_retry" ] && cat "$wicens_wanip_retry" && F_terminal_padding
			[ -f "$wicens_fw_retry" ] && cat "$wicens_fw_retry" && F_terminal_padding
			[ -f "$wicens_update_retry" ] && cat "$wicens_update_retry" && F_terminal_padding
			[ -f "$wicens_send_retry" ] && cat "$wicens_send_retry" && F_terminal_padding
			rm -f "$wicens_wanip_retry" "$wicens_fw_retry" "$wicens_update_retry" "$wicens_send_retry" 2>/dev/null

			F_menu_wait 15
		fi

		# start wicens menu
		until F_main_menu ; do : ; done
	fi

	##### auto-run options ############################################################################################
	###################################################################################################################

	F_ready_check   # ensure script is configured to be able to autorun, log errors otherwise

	if [ "$passed_options" = 'test' ] ; then
		F_opt_test

	elif [ "$passed_options" = 'cron' ] ; then
		new_cron_count="$((cron_run_count + 1))"
		F_replace_var cron_run_count "$new_cron_count" "$config_src"
		F_replace_var last_cron_run "$run_date" "$config_src"

		# cron - Sunday logging #######################################################################################
		weekly_wancall_total=$((wancall_run_count - last_wancall_log_count))   # log msg count

		if [ "$(F_date +'%u')" = '7' ] && [ "$log_cron_msg" = '0' ] ; then
			F_log "Started successfully by wan-event connected $weekly_wancall_total times in the last week, $wancall_run_count times since install"
			[ -n "$last_wancall_run" ] && F_log "Last wan-event connected trigger $last_wancall_run"
			F_log "Recorded $ip_change_count IP change(s) since install"
			F_replace_var last_wancall_log_count "$wancall_run_count" "$config_src"
			F_replace_var log_cron_msg 1 "$config_src"
		fi

		if [ "$(F_date +'%u')" = '1' ] && [ "$log_cron_msg" = '1' ] ; then   # monday reset
			F_replace_var log_cron_msg 0 "$config_src"
		fi

		# cron - update check #########################################################################################
		if [ "$user_update_notification" = '0' ] && [ "$update_avail" = 'none' ] ; then   # if update already found dont recheck
			update_cron_diff=$((run_epoch - update_cron_epoch))

			if [ "$update_cron_diff" -gt "$update_period" ] ; then   # check for webupdate every 48hours
				sleep "$(F_random_num)"   # good internet neighbor

				internet_check_count=0
				until F_internet_check ; do : ; done

				F_web_update_check
				F_replace_var update_cron_epoch "$(F_date sec)" "$update_src"
			fi
		fi

		# cron - update notification initial and retry if we found avail update in F_web_update_check #################
		if [ "$update_avail" != 'none' ] && [ "$update_notify_state" = '0' ] && [ "$user_update_notification" = '0' ] ; then   # no notification yet sent for update & enabled
			if [ -f "$wicens_update_retry" ] ; then   # set 5 time retry
				echo "# Attempting to send script update notification $(F_date full)" >> "$wicens_update_retry"
			else
				echo "# Attempting to send script update-notification $(F_date full)" > "$wicens_update_retry"
			fi

			if [ "$(wc -l < "$wicens_update_retry")" -le "$max_email_retry" ] ; then
				internet_check_count=0
				until F_internet_check update ; do : ; done
				F_log "Update available for wicens script, run manually to update"
				F_log "Sending update notification Email"
				F_update_mail_notify
			else
				F_log "Critical error, attempted to send script update Email $max_email_retry times, giving up"
				F_replace_var update_notify_state 1 "$update_src"   # set like we had success to only log error 1 time
			fi
		fi

		# cron - fw update notification retry #########################################################################
		if [ "$update_fw_notify_state" = '1' ] ; then   # fw_update_notify failed sending msg try again
			echo "# Attempting to send script fw update notification $(F_date full)" >> "$wicens_fw_retry"

			# dont exit continue to forwarder/ipcheck
			if [ "$(wc -l < "$wicens_fw_retry")" -le "$max_email_retry" ] ; then   # retry created in wicens fwupdate
				internet_check_count=0
				until F_internet_check fwupdate ; do : ; done
				F_fw_update_notify
			else
				F_log "Critical error, attempted to send Firmware update Email $max_email_retry times, giving up"
				F_replace_var update_fw_notify_state 0 "$update_src"   # set like we had success to only log error 1 time
			fi
		fi

		# cron - wicens forwarder retry ###############################################################################
		if [ -f "$wicens_send_retry" ] ; then   # retry created in wicens send
			source "$wicens_send_retry"   # source as retry needs msg/sendto

			if [ "$(wc -l < "$wicens_send_retry")" -le "$((max_email_retry + 4))" ] ; then   # retry for forwarder has 4 lines coded
				F_opt_forward
			else
				wicens_send_retry_age=$((run_epoch - wicens_send_retry_time))
				if [ "$wicens_send_retry_age" -gt "$retry_wait_period" ] ; then   # email failed 5 times w/internet up, after 6 hrs try again
					rm -f "$wicens_send_retry"  # remove to refresh
					F_opt_forward
				fi
			fi
		fi

		# cron - wicens IP check ######################################################################################
		if ! F_do_compare ; then
			if [ -f "$wicens_wanip_retry" ] ; then
				if [ "$(wc -l < "$wicens_wanip_retry")" -ge "$((max_email_retry + 2))" ] ; then
					source "$wicens_wanip_retry"
					wicens_wanip_retry_age=$((run_epoch - wicens_wanip_retry_time))

					if [ "$wicens_wanip_retry_age" -gt "$retry_wait_period" ] ; then
						rm -f "$wicens_wanip_retry"   # remove and refresh attempts fall through to F_send_mail
					else
						F_clean_exit   # done cron check exit
					fi

				fi
			fi
			F_send_mail   # sets wicens_wanip_retry, clears on success and exits clean
		fi

	# called by wan-event connected
	elif [ "$passed_options" = 'wancall' ] ; then
		new_wancall_count="$((wancall_run_count + 1))"
		F_log "Started by 'wan-event connected' trigger... sleeping 30secs before running IP compare"
		F_replace_var wancall_run_count "$new_wancall_count" "$config_src"
		F_replace_var last_wancall_run "$run_date" "$config_src"
		sleep 30   # let connection settle before checking anything

		# if called by wancall ensure we start fresh 5 attempts
		[ -f "$wicens_wanip_retry" ] && rm -f "$wicens_wanip_retry"

		if ! F_do_compare ; then
			F_send_mail
		fi

	# called by update-notification event
	elif [ "$passed_options" = 'fwupdate' ] ; then
		if [ "$user_fw_update_notification" = '0' ] ; then   # user optd into fw notfications
			[ -f "$wicens_fw_retry" ] && rm -f "$wicens_fw_retry"   # if retry file exists remove, we were called by update-notification again

			echo "# Attempting to send script fw update-notification $(F_date full)" > "$wicens_fw_retry"
			F_log_show "Started by update-notification trigger, sending firmware update notification"

			# set 1 at start of attempt set to 0 by F_fw_update_notify msg success and checked by cron
			F_replace_var update_fw_notify_state 1 "$update_src"
			F_fw_update_notify
			F_clean_exit
		fi

	# called as email forwarder
	elif [ "$passed_options" = 'send' ] ; then
		if [ -z "$fwd_send_msg" ] ; then
			F_log_show "Error, script called as forwarder but no Email message defined"
			F_clean_exit fail
		elif [ ! -f "$fwd_send_msg" ] ; then
			F_log_show "Error, script called as forwarder but can't find $fwd_send_msg Email message"
			F_clean_exit fail
		fi

		if [ -n "$fwd_send_addr" ] ; then
			F_log_terminal_ok "wicens script started as forwarder, attempting to send $fwd_send_msg to $fwd_send_addr"
		else
			F_log_terminal_ok "wicens script started as forwarder, attempting to send $fwd_send_msg to $user_send_to_addr"
		fi

		if F_opt_forward ; then
			F_clean_exit
		else
			F_clean_exit fail
		fi
	fi   # run args done
} ### arg_options

#######################################################################################################################
# first script commands ###############################################################################################

# validate args
case $passed_options in
	'reload') run_date="$(F_date full)" ; run_epoch="$(F_date sec)" ; passed_options='manual' ;;

	'cron'|'wancall'|'fwupdate'|'manual'|'test'|'send') F_ntp
	                                                    F_lock
	                                                    F_lock create
	                                                    [ -f "$mail_file" ] && rm -f "$mail_file"
	                                                    [ "$passed_options" = 'send' ] && fwd_send_msg="$2" && fwd_send_addr="$3"
	                                                    ;;

	'remove') F_opt_remove ;;   # manually remove lock files

	*) printf "\nwicens.sh \"%b\" is an invalid option\n\n" "$passed_options"
	   exit 0
	   ;;
esac

# load user settings/validate
F_user_settings

# check how script was run and launch
F_run_args

#######################################################################################################################
#######################################################################################################################
# END
