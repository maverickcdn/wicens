#!/bin/sh
############################################################################
#                               _                                          #
#                    _      __ (_)_____ ___   ____   _____                 #
#                   | | /| / // // ___// _ \ / __ \ / ___/                 #
#                   | |/ |/ // // /__ /  __// / / /(__  )                  #
#                   |__/|__//_/ \___/ \___//_/ /_//____/                   #
#                                                                          #
#                 'WAN IP Change Email Notification Script'                #
############################################################################

# Thanks to all who contribute(d) at SNBforums, pieces of your code are here ;)
# shellcheck disable=SC3045,SC2034,SC3003   # disable notices about posix compliant -s   reads unused vars   backspace in pswd check
# written by maverickcdn January 2021
# github.com/maverickcdn/wicens
# modified firmware checks to allow LTS Fork by john9527 March 2021 (special thanks to john9527 @ snbforums for adding compatibility for getrealip.sh)
# SNBforums thread https://www.snbforums.com/threads/wicens-wan-ip-change-email-notification-script.69294/

# START ---------------------------------------------------------------------------------------------------------------
script_version='1.12'

#################################################
saved_wan_ip=''
saved_wan_date=''
saved_wan_epoch=''
#################################################

# -------------------  TERMINAL PRINT STUFF ---------------------------------------------------------------------------

opt_color='yes'
tGRN="\033[1;32m" ;tRED="\033[1;31m" ;tPUR="\033[1;95m" ;tYEL="\033[1;93m" ;tCLR="\033[0m" ;tERASE="\033[2K" ;tBACK="\033[1A"
[ "$opt_color" = 'no' ] && tGRN='' && tRED='' && tPUR='' tYEL='' && tCLR=''
tCHECK="[${tYEL}WAIT${tCLR}]" ;tCHECKOK="[${tGRN} OK${tCLR} ]" ;tCHECKFAIL="[${tRED}FAIL${tCLR}]" ;tTERMHASH="[${tPUR}-##-${tCLR}]"

F_terminal_show() { printf -- "%b %s\n" "$tTERMHASH" "$1" ;}
F_terminal_padding() { printf "\n" ;}
F_terminal_separator() { echo '----------------------------------------------------------------------------' ;}
F_terminal_entry() { printf "%b %s" "$tTERMHASH" "$1" ;}
F_terminal_check() { printf "%b %s" "$tCHECK" "$1" ;}
F_terminal_check_ok() { printf "\r%b %s\n" "$tERASE$tCHECKOK" "$1" ;}
F_terminal_check_fail() { printf "\r%b %s\n" "$tERASE$tCHECKFAIL" "$1" ;}
F_terminal_header_print() { printf "%b %s %b%s%b\n" "$tTERMHASH" "$1" "$tGRN" "$2" "$tCLR" ;}
F_terminal_warning() { printf "%b%45s\n%45s\n%45s%b\n\n" "$tRED" "#################" "#    WARNING    #" "#################" "$tCLR" ;}
F_fail_entry() { F_terminal_check_fail "Invalid entry, any key to retry" && read -rsn1 "invalidwait" && printf "%b" "$tBACK$tERASE" && continue ;}

F_log_this() { printf "%s : %s" "$passed_options" "$1" | logger -t "wicens[$$]" ;}
F_log_and_show() { F_log_this "$*" ; F_terminal_show "$1" ;}
F_log_and_terminal_ok() { F_terminal_check_ok "$1" ;F_log_this "$1" ;}

# ----------------- MISC GLOBAL ---------------------------------------------------------------------------------------

[ "$1" = 'debug' ] && shift && set -x
F_ctrlc_clean() { printf "\n%b Script interrupted...\n" "$tTERMHASH" ; F_clean_exit ;}
trap F_ctrlc_clean INT
script_start_time=$(cut -f1 -d ' ' '/proc/uptime' | tr -d '.' )
[ -z "$saved_wan_epoch" ] && saved_wan_epoch="$(date +%s)"
passed_options="$1"
script_name_full="/jffs/scripts/$(basename "$0")"
script_name="$(basename "$0")"			# v1.12
pulled_device_name=$(nvram get lan_hostname)
pulled_lan_name=$(nvram get lan_domain)
[ -z "$(nvram get odmpid)" ] && device_model="$(nvram get productid)" || device_model="$(nvram get odmpid)"
[ ! -x "$script_name_full" ] && chmod a+rx "$script_name_full"   # incase script was installed but not made exec for cron
build_no=$(nvram get buildno | cut -f1 -d '.')
build_sub=$(nvram get buildno | cut -f2 -d '.')
build_extend=$(nvram get extendno)
# FW check
[ "$build_no" = '374' ] && extend_no=${build_extend:0:2} || extend_no=0			# v1.12
if [ "$build_no" != '386' ] || [ "$build_no" = '384' ] && [ "$build_sub" -lt 15 ] || [ "$build_no" = '374' ] && [ "$extend_no" -lt 48 ]; then
	F_terminal_header
	F_terminal_check_fail "Sorry this version of firmware is not compatible, please update to 384.15 or newer, or 374 LTS release 48 or newer to utilize this script"
	F_terminal_padding
	exit 0
fi

# alias
if [ ! "alias | grep -q 'wicens='" ] ; then
	(alias "wicens='sh ${script_name_full}'") &
fi
if [ ! -f "/jffs/configs/profile.add" ] ; then
	echo "alias wicens=\"sh ${script_name_full}\"   # added by wicens" > /jffs/configs/profile.add
elif [ ! "grep -q \"alias wicens=\" '/jffs/configs/profile.add'" ] ; then
	echo "alias wicens=\"sh ${script_name_full}\"   # added by wicens" >> /jffs/configs/profile.add
fi


# -------------  USER SETTINGS ----------------------------------------------------------------------------------------

user_from_name=''
if [ -z "$user_from_name" ] ; then   # tries to auto generate a from name on first run
	if [ -n "$pulled_device_name" ] && [ -n "$pulled_lan_name" ] ; then
		user_from_name="$pulled_device_name.$pulled_lan_name"
	else
		user_from_name="$device_model"
	fi
fi
user_smtp_server=''
user_from_addr=''
user_send_to_addr=''
user_send_to_cc=''
user_pswd=''
user_message_type=''
user_cron_interval='minute'
user_cron_period='31'
user_message_count=''
user_message_interval_1=''
user_message_interval_2=''
user_message_interval_3=''
user_custom_subject=''
user_custom_text=''
user_custom_script=''
user_custom_script_w=''

cron_run_count=0
last_cron_run=''
last_wancall_run=''
wancall_run_count=0
last_ip_change='never'
created_date=''
last_cron_log_count=0
last_wancall_log_count=0

[ "$user_custom_script_w" = 'w' ] && user_script_call_time='wait' ; [ "$user_custom_script_w" = 'i' ] && user_script_call_time='immediate'
user_custom_text_decoded="$(echo "$user_custom_text" | openssl base64 -d)"
user_custom_subject_decoded="$(echo "$user_custom_subject" | openssl base64 -d)"
user_custom_script_decoded="$(echo "$user_custom_script" | openssl base64 -d)"

# -------------  START OPTIONS  ---------------------------------------------------------------------------------------

F_opt_about() {
	clear
	{   # start of | more
	printf "	WICENS - WAN IP Change Email Notification Script. \n\n"

	printf "This script when configured will send an Email (1-4) at variable intervals \n"
	printf "X(second/minute/hour/day) to your Email notifying you when your WAN IP\n"
	printf "has changed.  \n\n"

	printf "Supports GMail, Hotmail, Outlook \n\n"

	printf "SMTP Email send formats available: \n"
	printf "sendmail - StartTLS v1.1 higher (eg. GMail port 587) \n"
	printf "sendmail - StartTLS v1 only \n"
	printf "curl     - SSL (eg GMail port 465) \n"
	printf "sendmail - SMTP plain auth (no encryption) \n"
	printf "sendmail - ISP based (no password reqd, generally port 25) \n\n"

	printf "IMPORTANT - If using GMail, you must enable 'insecure app' access to your  \n"
	printf "GMail account. If you use 2factor authentication you must setup an assigned\n"
	printf "password in GMail for this script to use. \n\n"

	printf "IMPORTANT - Your Email address(es) are stored as plain text within this    \n"
	printf "script.  Your Email password is obfuscated and saved to the script.        \n"
	printf "If you dont practice good security habits around your router ssh access,   \n"
	printf "this script might not be for you. \n\n"

	printf "Uses firmware built in getrealip.sh to retrieve your WAN IP using Google   \n"
	printf "STUN server. This will show your WAN IP regardless if your router is behind\n"
	printf "NAT (unbridged modem) or not. \n\n"

	printf "Executed by settable minute || hour cron run (default 31min) for checking  \n"
	printf "your current WAN IP. Also executed by 'wan-event connected' trigger. A DHCP\n"
	printf "renewal when your IP changes may not trigger a 'wan-event connected' event.\n\n"

	printf "All cron/wan-event entries are automatically generated upon completion of  \n"
	printf "your Email user login information and is double checked with every run.    \n\n"

	printf "NTP sync must occur to update router date/time for proper script function  \n"

	printf "### Technical ###\n\n"

	printf "Script generates a lock file in /tmp called wicens.lock to prevent         \n"
	printf "duplicate runs as well as another file in /tmp called wicenssendmail.lock  \n"
	printf "when sending Email notifications. Script will automatically remove (with   \n"
	printf "cron) stale lock files if original starting process no longer exists or    \n"
	printf "lock files are over age limit. \n\n"

	printf "Sendmail/Curl output for Emails is saved to /tmp/wicenssendmail.log for    \n"
	printf "debugging if neeeded.  This file can be viewed by running this script and  \n"
	printf "select option 6 \n\n"

	printf "Sendmail doesnt always return an error code on a misconfiguration so false \n"
	printf "send success can occur.  If script says Email has sent but no Email received\n"
	printf "use option 6 from the Main Menu to read sendmail output for errors\n\n"

	printf "The script does not update its saved WAN IP until the script has completed \n"
	printf "sending all notifications and adds to the Email message of success or      \n"
	printf "failure	in updating it, so in the event of message failure it should run   \n"
	printf "again with next cron run and attempt to send again.\n\n"

	printf "Using option S you can call your own script either immediately upon WAN IP \n"
	printf "change detection, or wait until all Email messages have been sent and      \n"
	printf "script has successfully updated. Script will be put in background as to not\n"
	printf "block this script \n\n"

	printf "Every Sunday the script will log the number of calls from cron/wan-event. \n\n"

	printf "Thank you for using this script. \n\n"
	} | more
	F_menu_exit
} ### about

F_opt_backup_restore() {
	F_backup() {
		if [ -f /jffs/scripts/wicensconfig.bak ] ; then
			while true; do
				F_terminal_warning ;F_terminal_padding
				F_terminal_show "Backup file exists, Y to overwrite, any key to return to Main Menu"
				read -rsn1 "configremove"
				case "$configremove" in
					y|Y) rm -f /jffs/scripts/wicensconfig.bak ; printf "%b" "$tBACK$tERASE" ;;
					*) exec sh "$script_name_full" ;;
				esac
				break
			done
		fi

		F_terminal_check "Starting backup"
		touch /jffs/scripts/wicensconfig.bak
		echo "wicens backup created $(date +%c) - ver:$script_version - DO NOT EDIT THIS FILE" >> /jffs/scripts/wicensconfig.bak
		if {   # start file output
			echo "$saved_wan_ip" ;echo "$saved_wan_date"
			echo "$user_from_name" ;echo "$user_smtp_server" ;echo "$user_from_addr" ;echo "$user_send_to_addr" ;echo "$user_send_to_cc"
			echo "$user_pswd" ;echo "$user_message_type" ;echo "$user_cron_interval" ;echo "$user_cron_period"
			echo "$user_message_count" ;echo "$user_message_interval_1" ;echo "$user_message_interval_2" ;echo "$user_message_interval_3"
			echo "$user_custom_subject" ;echo "$user_custom_text"
			echo "$cron_run_count" ;echo "$last_cron_run" ;echo "$last_wancall_run" ;echo "$wancall_run_count"
			echo "$last_ip_change" ;echo "$last_cron_log_count" ;echo "$last_wancall_log_count" ;echo "$saved_wan_epoch"
			echo "$user_custom_script" ;echo "$user_custom_script_w"
			printf '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n'   # for update room so old configs dont copy last line over
			} >> /jffs/scripts/wicensconfig.bak ; then
				F_terminal_check_ok "Backup successful, saved to /jffs/scripts/wicensconfig.bak"
		else
				F_terminal_check_fail "Backup failed, could not output to /jffs/scripts/wicensconfig.bak"
		fi
	}

	F_restore() {
		F_terminal_check "Restoring backup"
		if [ ! -f /jffs/scripts/wicensconfig.bak ] ; then
			F_terminal_check_fail "Error, no backup found in /jffs/scripts/wicensconfig.bak"
			F_menu_exit

		else
			F_config_line() { head -n "$1" /jffs/scripts/wicensconfig.bak | tail -n1 ;}   # pass a line number to write
			sed -i "1,/saved_wan_ip=.*/{s/saved_wan_ip=.*/saved_wan_ip='$(F_config_line 2)'/;}" "$script_name_full"
			sed -i "1,/saved_wan_date=.*/{s/saved_wan_date=.*/saved_wan_date='$(F_config_line 3)'/;}" "$script_name_full"
			sed -i "1,/user_from_name=.*/{s/user_from_name=.*/user_from_name='$(F_config_line 4)'/;}" "$script_name_full"
			sed -i "1,/user_smtp_server=.*/{s/user_smtp_server=.*/user_smtp_server='$(F_config_line 5)'/;}" "$script_name_full"
			sed -i "1,/user_from_addr=.*/{s/user_from_addr=.*/user_from_addr='$(F_config_line 6)'/;}" "$script_name_full"
			sed -i "1,/user_send_to_addr=.*/{s/user_send_to_addr=.*/user_send_to_addr='$(F_config_line 7)'/;}" "$script_name_full"
			sed -i "1,/user_send_to_cc=.*/{s/user_send_to_cc=.*/user_send_to_cc='$(F_config_line 8)'/;}" "$script_name_full"
			sed -i "1,/user_pswd=.*/{s/user_pswd=.*/user_pswd='$(F_config_line 9)'/;}" "$script_name_full"
			sed -i "1,/user_message_type=.*/{s/user_message_type=.*/user_message_type='$(F_config_line 10)'/;}" "$script_name_full"
			sed -i "1,/user_cron_interval=.*/{s/user_cron_interval=.*/user_cron_interval='$(F_config_line 11)'/;}" "$script_name_full"
			sed -i "1,/user_cron_period=.*/{s/user_cron_period=.*/user_cron_period='$(F_config_line 12)'/;}" "$script_name_full"
			sed -i "1,/user_message_count=.*/{s/user_message_count=.*/user_message_count='$(F_config_line 13)'/;}" "$script_name_full"
			sed -i "1,/user_message_interval_1=.*/{s/user_message_interval_1=.*/user_message_interval_1='$(F_config_line 14)'/;}" "$script_name_full"
			sed -i "1,/user_message_interval_2=.*/{s/user_message_interval_2=.*/user_message_interval_2='$(F_config_line 15)'/;}" "$script_name_full"
			sed -i "1,/user_message_interval_3=.*/{s/user_message_interval_3=.*/user_message_interval_3='$(F_config_line 16)'/;}" "$script_name_full"
			sed -i "1,/user_custom_subject=.*/{s/user_custom_subject=.*/user_custom_subject='$(F_config_line 17)'/;}" "$script_name_full"
			sed -i "1,/user_custom_text=.*/{s/user_custom_text=.*/user_custom_text='$(F_config_line 18)'/;}" "$script_name_full"
			sed -i "1,/cron_run_count=.*/{s/cron_run_count=.*/cron_run_count=$(F_config_line 19)/;}" "$script_name_full"
			sed -i "1,/last_cron_run=.*/{s/last_cron_run=.*/last_cron_run='$(F_config_line 20)'/;}" "$script_name_full"
			sed -i "1,/last_wancall_run=.*/{s/last_wancall_run=.*/last_wancall_run='$(F_config_line 21)'/;}" "$script_name_full"
			sed -i "1,/wancall_run_count=.*/{s/wancall_run_count=.*/wancall_run_count=$(F_config_line 22)/;}" "$script_name_full"
			sed -i "1,/last_ip_change=.*/{s/last_ip_change=.*/last_ip_change=$(F_config_line 23)/;}" "$script_name_full"
			sed -i "1,/last_cron_log_count=.*/{s/last_cron_log_count=.*/last_cron_log_count=$(F_config_line 24)/;}" "$script_name_full"
			sed -i "1,/last_wancall_log_count=.*/{s/last_wancall_log_count=.*/last_wancall_log_count=$(F_config_line 25)/;}" "$script_name_full"
			sed -i "1,/saved_wan_epoch=.*/{s/saved_wan_epoch=.*/saved_wan_epoch='$(F_config_line 26)'/;}" "$script_name_full"
			sed -i "1,/user_custom_script=.*/{s/user_custom_script=.*/user_custom_script='$(F_config_line 27)'/;}" "$script_name_full"
			sed -i "1,/user_custom_script_w=.*/{s/user_custom_script_w=.*/user_custom_script_w='$(F_config_line 28)'/;}" "$script_name_full"
			sed -i "1,/created_date=.*/{s/created_date=.*/created_date=''/;}" "$script_name_full"   # reset to nil resets with first rerun

		fi
		F_terminal_check_ok "Done writing settings to script"
		F_terminal_show "Remember to save /jffs/scripts/wicensconfig.bak somewhere safe"
	}

	F_terminal_header
	F_terminal_show "Backup/Restore Settings Menu" ;F_terminal_padding
	while true; do
		F_terminal_check "B to Backup Current Script Settings, R to Restore Settings"
		read -rsn1 "bandrwait"
		case "$bandrwait" in
			b|B) F_terminal_check_ok "B selected for backup" ;F_backup ;F_menu_exit ;;
			r|R) F_terminal_check_ok "R selected for restore" ;F_restore ;F_menu_exit ;;
			*) F_terminal_check_fail "Invalid entry, B or R - any key to retry, E return to Main Menu"
				read -rsn1 brinvalid
				case "$brinvalid" in
					e|E) F_main_menu ;;
					*) printf "%b" "$tBACK$tERASE" ;continue ;;
				esac ;;
		esac
		break
	done
} # backup_restore

F_opt_color() {
	F_terminal_padding
	if [ "$opt_color" = "yes" ]; then
		F_terminal_check "Setting script to no color mode"
		sed -i "1,/opt_color=.*/{s/opt_color=.*/opt_color='no'/;}" "$script_name_full"
		F_terminal_check_ok "Done, wicens script set to no color mode"
	elif [ "$opt_color" = "no" ]; then
		F_terminal_check "Setting script to color mode"
		sed -i "1,/opt_color=.*/{s/opt_color=.*/opt_color='yes'/;}" "$script_name_full"
		F_terminal_check_ok "Done, wicens script set to color mode"
	fi
	F_terminal_show "Return to Main Menu to view changes"
	F_menu_exit
} ### color

F_opt_count() {
	F_terminal_header
	F_terminal_warning
	F_terminal_show "This will remove all saved cron/wancall counts and install date"
	F_terminal_padding
	while true; do
		F_terminal_check "Are you sure you wish to reset? Y or N"
		read -rsn1 "reset_wait"
		case "$reset_wait" in
			y|Y) F_terminal_check_ok "Ok received, resetting counts..."
			     ! F_reset_count && F_terminal_check_fail "Counts reset failed" ;;
			n|N) F_terminal_check_ok "No received" ; F_menu_exit ;;
			*) F_fail_entry ;;
		esac
		break
	done
	F_menu_exit
} ### count

F_opt_custom() {
	F_terminal_header ;F_terminal_show "Custom Text Entry Menu" ;F_terminal_padding
	if [ -z "$user_custom_text" ] ; then
		F_terminal_show "Enter your line of custom plain text to add to the Email message(s)"
		F_terminal_show "eg.  Router hidden in moms closet, 2 vpn clients to update"
		F_terminal_show "Entry must be one line, can use \\n to create new line in Email msg"
		F_terminal_padding ;F_terminal_entry "Text : "
		read -r "user_custom_text_entry"
		F_terminal_padding
		# ensure we empty any saved vars if brought here by N new entry but left entry blank
		[ -z "$user_custom_text_entry" ] && sed -i "1,/user_custom_text=.*/{s/user_custom_text=.*/user_custom_text=''/;}" "$script_name_full" && return 0
		while true ; do
			printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$user_custom_text_entry" "$tCLR"
			read -rsn1 "yesorno"
			case "$yesorno" in
				y|Y) custom_text_encoded=$(echo "$user_custom_text_entry" | openssl base64 | tr -d '\n')   # base64 no worries of sed conflicts
				if sed -i "1,/user_custom_text=.*/{s~user_custom_text=.*~user_custom_text='$custom_text_encoded'~;}" "$script_name_full" ; then
						F_terminal_check_ok "Done writing custom text to script" ;user_custom_text="$user_custom_text_entry"
					else
						F_terminal_check_fail "Error, sed failed writing custom text to script" ;F_clean_exit
					fi ;;
				n|N) return 1 ;;
				*) F_fail_entry ;;
			esac
			break
		done

	else
		F_terminal_show "Custom text already set :" ;F_terminal_padding ;F_terminal_show "$user_custom_text_decoded" ;F_terminal_padding
		while true ; do
			F_terminal_check "(Y)keep - (N)enter new - (R)remove current "
			read -rsn1 "yesornowremove"
			case "$yesornowremove" in
				y|Y) F_terminal_check_ok "Keeping currently saved custom text" ;;
				n|N) user_custom_text='' ;return 1 ;;
				r|R) if sed -i "1,/user_custom_text=.*/{s/user_custom_text=.*/user_custom_text=''/;}" "$script_name_full" ; then
						F_terminal_check_ok "Done, custom text cleared" ;user_custom_text=''
					else
						F_terminal_check_fail "Error, sed failed to reset custom text" ;F_clean_exit
					fi ;;
				*) F_terminal_check_fail "Invalid entry, Y/N/R - any to key to retry" ; read -rsn1 "invalidwait" ; printf "%b" "$tBACK$tERASE" ; continue ;;
			esac
			break
		done
	fi
} ### custom_text

F_opt_disable() {
	F_terminal_header ;F_terminal_warning ;F_terminal_show "This will remove all auto start entries in wan-event, cron, and"
	F_terminal_show "services-start. Saved Email settings and WAN IP will remain."
	F_terminal_show "You will not receive an Email notification if your WAN IP changes."
	F_terminal_show "Manually run script to reactivate auto starts" ;F_terminal_padding
	while true; do
		F_terminal_check "Are you sure you wish to disable? Y or N"
		read -rsn1 "disable_wait"
		case "$disable_wait" in
			y|Y) F_terminal_check_ok "Ok received, disabling..." ; F_disable_autorun ;;
			n|N) F_terminal_check_ok "No received, exiting..." ;;
			*) F_fail_entry ;;
		esac
		break
	done
	F_menu_exit
} ### disable

F_opt_error() {
	if [ -f /tmp/wicenssendmail.log ]; then
		F_terminal_show "Contents of last Email send log : "
		cat /tmp/wicenssendmail.log
		F_terminal_padding ;F_terminal_check_ok "End of contents." ;F_menu_exit
	else
		F_terminal_padding ;F_terminal_show "No log file found" ;F_terminal_padding ;F_terminal_check "Any key to continue"
		read -rsn1 logwait
		exec sh "$script_name_full"
	fi
} # error

F_opt_pswd() {
	until F_smtp_pswd ; do : ; done
	F_menu_exit
} ### pswd

F_opt_remove() {
	F_terminal_padding

	if [ -f "/tmp/wicens.lock" ]; then
		process_id="$(sed -n '2p' /tmp/wicens.lock)"   # pid
		process_created="$(sed -n '5p' /tmp/wicens.lock)"   # started on

		if [ -d "/proc/$process_id" ]; then # process that created exist
			F_terminal_show "Process exists attached to lock file.... killing process"
			kill -9 "$process_id" 2> /dev/null
			printf "%b Killed process %s and deleting lock file %s" "$tERASE$tCHECKOK" "$process_id" "$process_created" ;F_terminal_padding
			F_log_this "Killed old process $process_id and deleting lock file $process_created"
		fi

		F_terminal_check "Removing lock file 1 of 2"
		rm -f "/tmp/wicens.lock"
		F_terminal_check_ok "Removed lock file 1 of 2 "

	else
		F_terminal_check_fail "1st lock file not present"
	fi

	F_terminal_check "Removing lock file 2 of 2"
	if [ -f "/tmp/wicenssendmail.lock" ]; then
		rm -f "/tmp/wicenssendmail.lock"
		F_terminal_check_ok "Removed lock file 2 of 2 "
		F_clean_exit

	else
		F_terminal_check_fail "2nd lock file not present"
		F_clean_exit
	fi
} ### remove

F_opt_reset() {
	F_terminal_header ;F_terminal_warning ;F_terminal_show "This will remove all saved settings"
	F_terminal_show "And cron/services-start/wan-event entries" ;F_terminal_padding
	while true; do
		F_terminal_check "Are you sure you wish to reset? Y or N"
		read -rsn1 "reset_wait"
		case "$reset_wait" in
			y|Y) F_terminal_header ;F_terminal_check_ok "Ok received, resetting..." ;;
			n|N) F_terminal_check_ok "No received, exiting..." ; F_clean_exit ;;
			*) F_fail_entry ;;
		esac
		break
	done

	! F_reset_do && F_terminal_check_fail "Reset failed"
	! F_reset_count && F_terminal_check_fail "Counts reset failed"
	! F_disable_autorun && F_terminal_check_fail "Auto run removal failed"
	F_menu_exit
} ### reset

F_opt_sample() {
	F_terminal_header ;F_terminal_show "Sample Email output:" ;F_terminal_padding
	current_wan_ip="x.x.x.x"   # fake for email
	passed_options='sample'   # for setup just fake running sample
	loop_run=1
	user_message_count=1
	test_mode_active="yes"
	F_email_message
	cat /tmp/wicensmail.txt ;F_terminal_padding
	rm -f /tmp/wicensmail.txt
	F_terminal_show "End of Email output"
	[ "$building_settings" != 'yes' ] && F_menu_exit
} ### sample

F_opt_script() {
	F_terminal_header ;F_terminal_show "Custom Script Path Entry Menu" ;F_terminal_padding
	if [ -z "$user_custom_script" ] ; then
		while true ; do
			F_terminal_show "Do you want your custom script to execute immediately on WAN IP"
			F_terminal_show "change detection, or wait till all Email messages configured"
			F_terminal_show "have finished sending" ;F_terminal_padding
			F_terminal_entry "w for wait    i for immediately : "
			read -rsn1 user_script_wait_entry
			case "$user_script_wait_entry" in
				w|i) if sed -i "1,/user_custom_script_w=.*/{s~user_custom_script_w=.*~user_custom_script_w='$user_script_wait_entry'~;}" "$script_name_full" ; then
						F_terminal_check_ok "Done writing custom script exec time to script" ;user_custom_script_w="$user_script_wait_entry"
						else
							F_terminal_check_fail "Error, sed failed writing custom script exec time to script" ;F_clean_exit
						fi ;;
				*) F_terminal_check_fail "Invalid entry, any key to retry" && read -rsn1 "invalidwait" && printf "%b" "$tBACK$tERASE$tBACK$tERASE$tBACK$tERASE$tBACK$tERASE$tBACK$tERASE" && continue;;
			esac
			break
		done

		F_terminal_padding ;F_terminal_check "Any key to continue..." ;read -rsn1 waitscript
		clear ;F_terminal_header ;F_terminal_show "Custom Script Path Entry Menu" ;F_terminal_padding
		[ "$user_custom_script_w" = 'w' ] && custom_exec='wait' ;[ "$user_custom_script_w" = 'i' ] && custom_exec='immediate'
		printf "%b Script execution set to : %b \n" "$tTERMHASH" "$custom_exec" ;F_terminal_padding
		F_terminal_show "Enter the full path to your script"
		F_terminal_show "eg. /jffs/scripts/customscript.sh" ;F_terminal_padding
		F_terminal_entry "Path : "
		read -r user_custom_script_entry
		while true ; do
				F_terminal_padding
				printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$user_custom_script_entry" "$tCLR"
				read -rsn1 "yesorno"
				case "$yesorno" in
					y|Y) if [ ! -f "$user_custom_script_entry" ] ; then
							F_terminal_check_fail "Could not locate custom script"
							F_terminal_show "Any key to return to Main Menu"
							read -rsn1 nofind
							exec sh "$script_name_full"
						fi
						custom_script_encoded=$(echo "$user_custom_script_entry" | openssl base64 | tr -d '\n')   # base64 no worries of sed conflicts
						if sed -i "1,/user_custom_script=.*/{s~user_custom_script=.*~user_custom_script='$custom_script_encoded'~;}" "$script_name_full" ; then
							F_terminal_check_ok "Done writing custom script path to script" ;user_custom_script="$user_custom_script_entry"
						else
							F_terminal_check_fail "Error, sed failed writing custom script path to wicens script" ;F_clean_exit
						fi ;;
					n|N) return 1 ;;
					*) F_fail_entry ;;
				esac
				break
			done

	else
		F_terminal_show "Custom script path already set" ;F_terminal_padding ;F_terminal_show "$user_custom_script_decoded" ;F_terminal_padding
		while true ; do
			F_terminal_check "(Y)keep - (N)enter new - (R)remove current "
			read -rsn1 "yesornowremove"
			case "$yesornowremove" in
				y|Y) F_terminal_check_ok "Keeping currently saved custom script path" ;;
				n|N) user_custom_script='' ;return 1 ;;
				r|R) if sed -i "1,/user_custom_script=.*/{s/user_custom_script=.*/user_custom_script=''/;}" "$script_name_full" ; then
						F_terminal_check_ok "Done, custom script path cleared" ;user_custom_script=''
					else
						F_terminal_check_fail "Error, sed failed to reset custom script path" ;F_clean_exit
					fi ;;
				*) F_terminal_check_fail "Invalid entry, Y/N/R - any to key to retry" ; read -rsn1 "invalidwait" ; printf "%b" "$tBACK$tERASE" ; continue ;;
			esac
			break
		done
	fi
} ### script

F_opt_subject() {
	F_terminal_header ;F_terminal_show "Custom Subject Menu" ;F_terminal_padding
	if [ -z "$user_custom_subject" ]; then
		F_terminal_show "Enter the text for a custom Subject line you wish to use"
		printf "%b Default Subject text is: %bWAN IP has changed on %s%b\n" "$tTERMHASH" "$tGRN" "$device_model" "$tCLR"
		F_terminal_padding ;F_terminal_show "If you wish to use the new or current WAN IP, add the var names"
		F_terminal_show "\$current_wan_ip and \$saved_wan_ip to your text (like shown)"
		F_terminal_show "Model of router var is \$device_model"
		F_terminal_padding ;F_terminal_entry "Subject: "
		read -r "user_custom_subject_entry"
		F_terminal_padding
		[ -z "$user_custom_subject_entry" ] && return 0
		while true; do
			printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$user_custom_subject_entry" "$tCLR"
			read -rsn1 "yesorno"
			case "$yesorno" in
				y|Y) custom_subject_encoded=$(echo "$user_custom_subject_entry" | openssl base64 | tr -d '\n')
					if sed -i "1,/user_custom_subject=.*/{s~user_custom_subject=.*~user_custom_subject='$custom_subject_encoded'~;}" "$script_name_full" ; then
						user_custom_subject="$user_custom_subject_entry"
						F_terminal_check_ok "Done. user_custom_subject set to : $user_custom_subject_entry"
					else
						F_terminal_check_fail "Error, sed failed to write custom subject to script"
						F_clean_exit
					fi
					;;
				n|N) return 1 ;;
				*) F_fail_entry ;;
			esac
			break
		done

	else
		F_terminal_show "Custom subject already set :" ;F_terminal_padding ;F_terminal_show "$user_custom_subject_decoded" ;F_terminal_padding
		while true; do
			F_terminal_check "(Y)keep - (N)enter new - (R)remove current "
			read -rsn1 "yesornowremove"
			case "$yesornowremove" in
				y|Y) F_terminal_check_ok "Keeping currently saved custom subject" ;;
				n|N) user_custom_subject=""
				     return 1 ;;
				r|R) if sed -i "1,/user_custom_subject=.*/{s/user_custom_subject=.*/user_custom_subject=''/;}" "$script_name_full" ; then
						F_terminal_check_ok "Custom subject cleared" ;user_custom_subject=
					else
						F_terminal_check_fail "Error, sed failed to clear custom subject" ;F_clean_exit
					fi ;;
				*) F_terminal_check_fail "Invalid entry, Y/N/R - any to key to retry" && read -rsn1 "invalidwait" && printf "%b" "$tBACK$tERASE" && continue ;;
			esac
			break
		done
	fi
} ### subject

F_opt_test() {
	test_mode_active="yes"
	user_message_count="1"
	F_log_this "Test mode started, sending test Email"
	current_wan_ip="x.x.x.x Test Mode"
	F_start_message
	F_auto_run_check
	internet_check_count=0
	until F_internet_check ; do : ; done
	printf "[%bFAIL%b] Current WAN IP is : %b%s%b --- %bNo Match%b\n" "$tRED" "$tCLR" "$tRED" "$current_wan_ip" "$tCLR" "$tRED" "$tCLR"
	F_send_mail   # return to menu or exit in F_send_mail
} ### test

F_opt_uninstall() {
	F_uninstall_do() {
		if ! F_disable_autorun; then
			F_terminal_check_fail "Error, auto run removal failed" ;F_log_this "Error, auto run removal failed"
			F_log_and_show "Be sure to manually remove entries in"
			F_log_and_show "cru l using cru d command"
			F_log_and_show "/jffs/scripts/services-start wicens entry"
			F_log_and_show "/jffs/scripts/wan-event wicens entry"
		fi

		[ -f "/jffs/configs/Equifax_Secure_Certificate_Authority.pem" ] && rm -f /jffs/configs/Equifax_Secure_Certificate_Authority.pem
		[ -f "/tmp/wicens.lock" ] && rm -f /tmp/wicens.lock
		[ -f "/tmp/wicenssendmail.lock" ] && rm -f /tmp/wicenssendmail.lock
		[ -f "/tmp/wicenssendmail.log" ] && rm -f /tmp/wicenssendmail.log
		[ -f "/tmp/wicensmail.txt" ] && rm -f /tmp/wicensmail.txt
		unalias wicens 2>/dev/null
		if [ -f "/jffs/configs/profile.add" ] ; then
			grep -q 'alias wicens=' '/jffs/configs/profile.add' && sed -i '/alias wicens=/d' '/jffs/configs/profile.add'
		fi
		[ ! -s /jffs/configs/profile.add ] && rm -f /jffs/configs/profile.add
		rm -f "$script_name_full"

		if [ -f "/jffs/scripts/wicensconfig.bak" ] ; then
			F_terminal_padding ;F_terminal_check "wicens settings backup exists, R to remove, any key to keep"
			read -rsn1 "backupremove"
			printf "%b" "$tERASE$tBACK$tERASE"
			case "$backupremove" in
				r|R) rm -f /jffs/scripts/wicensconfig.bak && F_terminal_check_ok "Removed /jffs/scripts/wicensconfig.bak" ;;
				*) F_terminal_check_ok "Keeping /jffs/scripts/wicensconfig.bak" ;;
			esac
		fi
		F_terminal_check_ok "Done. Uninstalled" ;F_terminal_padding ;exit 0
	} # uninstall_do

	F_terminal_header ;F_terminal_warning ;F_terminal_show "This will remove the WICENS script entirely from your system" ;F_terminal_padding
	while true; do
		F_terminal_check "Are you sure you wish to uninstall? Y or N"
		read -rsn1 "uninstall_wait"
		case "$uninstall_wait" in
			y|Y) F_terminal_check_ok "Uninstalling" ; F_terminal_padding ; F_uninstall_do ;;
			n|N) F_terminal_check_ok "No received, exiting..." ; F_menu_exit ;;
			*) F_fail_entry ;;
		esac
		break
	done
} ### uninstall


# -------------  BUILD USER SETTINGS FUNCTIONS ------------------------------------------------------------------------

#requires being passed a line # for head to terminate on
F_terminal_entry_header() { F_start_message | head -n "$1" ; F_terminal_separator ; F_terminal_padding ;}

# all user entry functions called by until loops and return 1 for failed input and restart or return 0 with completed Y in while loop
F_send_to_addr() {
	F_terminal_entry_header 15
	F_terminal_show "Enter the Email address you wish to send notification Emails" ;F_terminal_show "to when your WAN IP changes"
	F_terminal_show "eg.  myrecipient@myemail.com"
	[ -n "$user_send_to_addr" ] && printf "%b Currently set to : %b%s%b \n" "$tTERMHASH" "$tGRN" "$user_send_to_addr" "$tCLR" && F_terminal_show "Leave entry blank to keep current"
	F_terminal_padding ;F_terminal_entry "Send to address : "
	read -r "send_to_entry"

	[ -z "$user_send_to_addr" ] && [ -z "$send_to_entry" ] && F_terminal_show "Error, Email send to address cannot be empty, any key to retry" && read -rsn1 "waitsendto" && return 1
	[ -z "$send_to_entry" ] && send_to_entry="$user_send_to_addr"
	F_terminal_padding
	while true; do   # loop for invalid entries
		printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$send_to_entry" "$tCLR"
		read -rsn1 "yesorno"
		case "$yesorno" in
			y|Y) sed -i "1,/user_send_to_addr=.*/{s/user_send_to_addr=.*/user_send_to_addr='$send_to_entry'/;}" "$script_name_full"
			     user_send_to_addr="$send_to_entry" ;;
			n|N) return 1 ;;
			*) F_fail_entry ;;
		esac
		break
	done
} ### send_to_addr

F_send_to_cc() {
	if [ -n "$user_send_to_cc" ]; then
		F_terminal_entry_header 16
		printf "%b Second Email recipient already set to : %s \n\n" "$tTERMHASH" "$user_send_to_cc" ;F_terminal_padding
		while true; do
			F_terminal_check "(Y)keep (N)enter new (R)remove current & skip to server entry"   # for edits can remove 2nd email if wanted.
			read -rsn 1 "ccmailwait2"
			case "$ccmailwait2" in
				y|Y) return 0 ;;
				n|N) user_send_to_cc="currently none" ; return 1 ;;
				r|R) sed -i "1,/user_send_to_cc=.*/{s/user_send_to_cc=.*/user_send_to_cc=''/;}" "$script_name_full" && user_send_to_cc="currently none" && return 0 ;;
				*) F_terminal_check_fail "Invalid Entry , Y/N/R - any key to retry" ; read -rsn1 "invalidwait" ; printf "%b" "$tBACK$tERASE" ; continue ;;
			esac
			break
		done

	else
		user_send_to_cc="currently none"  # set var for setup terminal menus
		F_terminal_entry_header 16
		F_terminal_show "Enter a 2nd Email address you wish to send notification Emails"
		F_terminal_show "to when your WAN IP changes"
		F_terminal_show "eg.  my2ndrecipient@myemail.com"
		F_terminal_padding ;F_terminal_show "Leave entry blank to leave CC option blank and continue"
		F_terminal_padding ;F_terminal_entry "Send to CC address : "
		read -r "send_to_cc_entry"

		[ -z "$send_to_cc_entry" ] && return 0

		F_terminal_padding
		while true; do
			printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$send_to_cc_entry" "$tCLR"
			read -rsn1 "yesorno" in
			case "$yesorno" in
				y|Y) sed -i "1,/user_send_to_cc=.*/{s/user_send_to_cc=.*/user_send_to_cc='$send_to_cc_entry'/;}" "$script_name_full"
				     user_send_to_cc="$send_to_cc_entry" ;;
				n|N) user_send_to_cc= ;return 1 ;;
				*) F_fail_entry ;;
			esac
			break
		done
	fi
} ### send_to_cc

F_smtp_server() {
	F_terminal_entry_header 17
	F_terminal_show "Enter the SMTP server address and port # like as shown for your"
	F_terminal_show "Email provider - eg.  smtp.myemailprovider.com:25"
	[ -n "$user_smtp_server" ] && printf "%b Currently set to : %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_smtp_server" "$tCLR" && F_terminal_show "Leave entry blank to keep current"
	F_terminal_padding ;F_terminal_entry "Server address/port : "
	read -r "smtp_server_entry"

	[ -z "$user_smtp_server" ] && [ -z "$smtp_server_entry" ] && F_terminal_show "Error, Server address cannot be empty, any key to retry" && read -rsn1 waitsmtpserv && return 1
	[ -z "$smtp_server_entry" ] && smtp_server_entry="$user_smtp_server"
	F_terminal_padding
	while true; do
		printf "%b Is %b%s%b correct? Y or N " "$tCHECK" "$tGRN" "$smtp_server_entry" "$tCLR"
		read -rsn1 "yesorno"
		case "$yesorno" in
			y|Y) sed -i "1,/user_smtp_server=.*/{s/user_smtp_server=.*/user_smtp_server='$smtp_server_entry'/;}" "$script_name_full"
			     user_smtp_server="$smtp_server_entry" ;;
			n|N) return 1 ;;
			*) F_fail_entry ;;
		esac
		break
	done
} ### smtp_server

F_send_type() {
	F_terminal_entry_header 18
	F_terminal_show "SMTP Email server send configuration type                Selection"
	F_terminal_padding
	F_terminal_show "WITH password and StartTLS - eg.GMail(587)/Hotmail/Outlook - 1"
	F_terminal_show "WITH password and SSL required - eg.GMail(465)             - 2"
	F_terminal_show "ISP type with NO password and NO StartTLS/SSL-eg.port 25   - 3"
	F_terminal_show "WITH password and NO StartTLS or SSL (plain auth)          - 4"
	F_terminal_show "WITH password and StartTLS v1                              - 5"
	[ -n "$user_message_type" ] && F_terminal_padding && printf "%b Currently set to : %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_message_type" "$tCLR" && F_terminal_show "Leave selection blank to keep current setting"
	F_terminal_padding ;F_terminal_entry "Selection : "

	read -r "send_type_entry"
	case "$send_type_entry" in
		1|2|3|4|5) ;;
		"") if [ -n "$user_message_type" ]; then
				send_type_entry="$user_message_type"
			else
				F_terminal_check_fail "Invalid entry, 1,2,3,4,5 only - any key to retry" && read -rsn1 "invalidwait" && return 1
			fi ;;
		*) F_terminal_check_fail "Invalid Entry, 1,2,3,4,5 only - any key to retry" && read -rsn1 "invalidwait" && return 1 ;;
	esac

	F_terminal_padding
	while true; do
		printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$send_type_entry" "$tCLR"
		read -rsn1 "yesorno"
		case "$yesorno" in
			y|Y) ;;
			n|N) return 1 ;;
			*) F_fail_entry ;;
		esac
		break
	done

	[ "$send_type_entry" = "1" ] &&  sed -i "1,/user_message_type=.*/{s/user_message_type=.*/user_message_type='smtp_start_tls'/;}" "$script_name_full" && user_message_type="smtp_start_tls"
	[ "$send_type_entry" = "2" ] &&  sed -i "1,/user_message_type=.*/{s/user_message_type=.*/user_message_type='smtp_ssl'/;}" "$script_name_full" && user_message_type="smtp_ssl"
	[ "$send_type_entry" = "3" ] &&  sed -i "1,/user_message_type=.*/{s/user_message_type=.*/user_message_type='smtp_isp_nopswd'/;}" "$script_name_full" && user_message_type="smtp_isp_nopswd"
	[ "$send_type_entry" = "4" ] &&  sed -i "1,/user_message_type=.*/{s/user_message_type=.*/user_message_type='smtp_plain_auth'/;}" "$script_name_full" && user_message_type="smtp_plain_auth"
	[ "$send_type_entry" = "5" ] &&  sed -i "1,/user_message_type=.*/{s/user_message_type=.*/user_message_type='smtp_start_tls_v1'/;}" "$script_name_full" && user_message_type="smtp_start_tls_v1"

	if [ "$user_message_type" != 'smtp_isp_nopswd' ] && [ "$user_message_type" != 'smtp_plain_auth' ]; then
		F_terminal_padding ;F_terminal_padding
		F_terminal_show "If using GMail for your sending service"
		F_terminal_show "Insecure app access MUST be enabled in your GMail account settings"
		F_terminal_show "If you use 2-factor authentication"
		F_terminal_show "You must setup an app pswd for this script"
		F_terminal_show "Any key to continue" && read -rsn1 "notify_wait"
	fi
	return 0
} ### send_type

F_from_email_addr() {
	F_terminal_entry_header 19
	F_terminal_show "Enter the Email send from (login) address for your Email provider"
	F_terminal_show "eg.  myemail@myemailprovider.com"
	[ -n "$user_from_addr" ] && printf "%b Currently set to : %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_from_addr" "$tCLR" && F_terminal_show "Leave entry blank to keep current"
	F_terminal_padding ;F_terminal_entry "From Email addr : "
	read -r "from_email_addr_entry"

	[ -z "$user_from_addr" ] && [ -z "$from_email_addr_entry" ] && F_terminal_show "Error, from(login) address cannot be empty, any key to retry" && read -rsn1 waitfromemail && return 1
	[ -z "$from_email_addr_entry" ] && from_email_addr_entry="$user_from_addr"
	F_terminal_padding
	while true; do
		printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$from_email_addr_entry" "$tCLR"
		read -rsn1 "yesorno"
		case "$yesorno" in
			y|Y) sed -i "1,/user_from_addr=.*/{s/user_from_addr=.*/user_from_addr='$from_email_addr_entry'/;}" "$script_name_full"
			     user_from_addr="$from_email_addr_entry" ;;
			n|N) return 1 ;;
			*) F_fail_entry ;;
		esac
		break
	done
} ### from_email_addr

F_from_name() {
	F_terminal_entry_header 20
	F_terminal_show "Enter the 'message from name' for the notification Email"
	[ -n "$user_from_name" ] && printf "%b Currently set to : %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_from_name" "$tCLR" && F_terminal_show "Leave entry blank to keep current"
	F_terminal_padding ;F_terminal_entry "Email from name : "
	read -r "from_name_entry"

	[ -z "$user_from_name" ] && [ -z "$from_name_entry" ] && F_terminal_show "Error, Script could not auto-fill from name, cannot be blank, any key to retry" && read -rsn1 waitfromname && return 1
	[ -z "$from_name_entry" ] && from_name_entry="$user_from_name"
	F_terminal_padding
	while true; do
		printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$from_name_entry" "$tCLR"
		read -rsn1 "yesorno"
		case "$yesorno" in
			y|Y) sed -i "1,/user_from_name=.*/{s/user_from_name=.*/user_from_name='$from_name_entry'/;}" "$script_name_full"
			     user_from_name="$from_name_entry" ;;
			n|N) return 1;;
			*) F_fail_entry ;;
		esac
		break
	done
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

	F_terminal_entry_header 21
	F_terminal_show "Enter the password for your Email"
	[ -n "$user_pswd" ] && F_terminal_show "Saved password exists, leave blank to use saved"
	F_terminal_padding ;F_terminal_entry "Password  : "
	F_pswd_entry
	password_entry_1="$passwordentry"

	[ -n "$user_pswd" ] && [ -z "$passwordentry" ] && printf "%b" "$tBACK$tERASE" && F_terminal_check_ok "Keeping saved" && return 0   # keep saved password

	if [ -z "$user_pswd" ] && [ -z "$passwordentry" ] ; then
		F_terminal_show "Error - Password cannot be empty, Retry(any key) Main Menu(M)"
		read -rsn1 "waitsmtppswd"
		case "$waitsmtppswd" in
			m|M) exec sh "$script_name_full" ;;
		esac
		return 1
	fi

	passwordentry=''
	F_terminal_entry "Reconfirm : "
	F_pswd_entry
	password_entry_2="$passwordentry"

	if [ "$password_entry_1" != "$password_entry_2" ] || [ -z "$password_entry_2" ] ; then
		F_terminal_check_fail "Passwords do not match, any key to retry"
		read -rsn1 "nomatchwait"
		return 1
	fi

	# encrypt/base64 remove new lines so no sed errors
	user_pswd_encrypt=$(echo "$password_entry_1" | openssl enc -md sha512 -pbkdf2 -aes-256-cbc -a -salt -pass pass:"$(nvram get boardnum | sed 's/://g')" | tr -d '\n')

	if sed -i "1,/user_pswd=.*/{s,user_pswd=.*,user_pswd='$user_pswd_encrypt',;}" "$script_name_full" ; then
		F_terminal_check_ok "Password successfully encrypted and saved"
		return 0
	else
		F_terminal_show "Failed updating script with encrypted password"
		return 0
	fi
} ### smtp_pswd

F_term_show_msgcount() {
	if [ "$user_message_count" = '1' ] || [ -z "$user_message_count" ]; then
		[ "$1" = 'message' ] && F_terminal_entry_header 21
		[ "$1" = 'cron' ] && F_terminal_entry_header 22
	elif [ "$user_message_count" = '2' ]; then
		[ "$1" = 'message' ] && F_terminal_entry_header 22
		[ "$1" = 'cron' ] && F_terminal_entry_header 23
	elif [ "$user_message_count" = '3' ]; then
		[ "$1" = 'message' ] && F_terminal_entry_header 23
		[ "$1" = 'cron' ] && F_terminal_entry_header 24
	elif [ "$user_message_count" = '4' ]; then
		[ "$1" = 'message' ] && F_terminal_entry_header 24
		[ "$1" = 'cron' ] && F_terminal_entry_header 25
	fi
}

F_message_config() {
	if [ -n "$user_message_count" ]; then
		if [ "$user_message_count" -gt '1' ]; then
			F_term_show_msgcount message
			F_terminal_show "Total notification Email count and intervals"
			F_terminal_padding ;printf "%b Message count already set to %b%s%b \n" "$tTERMHASH" "$tGRN" "$user_message_count" "$tCLR"
			[ -n "$user_message_interval_1" ] && printf "%b Email 1/2 interval) %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_message_interval_1" "$tCLR"
			[ -n "$user_message_interval_2" ] && printf "%b Email 2/3 interval) %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_message_interval_2" "$tCLR"
			[ -n "$user_message_interval_3" ] && printf "%b Email 3/4 interval) %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_message_interval_3" "$tCLR"
			F_terminal_padding
			while true; do
				F_terminal_check "Keep this setting? Y or N"
				read -rsn1 messageexist
				case "$messageexist" in
					y|Y) return 0 ;;
					n|N) ;;
					*) F_fail_entry ;;
				esac
				break
			done

		else   # message count only set to 1
			F_term_show_msgcount message
			F_terminal_show "Total notification Email count (and intervals)" ;F_terminal_padding
			while true; do
				printf "%b Message count already set to %b%s%b, keep this setting? Y or N" "$tCHECK" "$tGRN" "$user_message_count" "$tCLR"
				read -rsn1 messageexist
				case "$messageexist" in
					y|Y) return 0 ;;
					n|N) ;;
					*) F_fail_entry ;;
				esac
				break
			done
		fi
	fi

	user_message_count=   # empty var for term_show_msg_count incase overwriting old (ans:no to keep old settings), doesnt show old entry
	F_term_show_msgcount message
	F_terminal_show "Enter the number of notification Emails (1-4) you wish to send"
	F_terminal_show "with variable intervals you will set in-between each notification"
	F_terminal_show "in the next step"
	F_terminal_padding ;F_terminal_entry "Number of notification Emails (1-4) : "
	read -r "email_send_count_entry"

	case "$email_send_count_entry" in
		[1-4]) ;;
		*) F_terminal_check_fail "Invalid Entry, must be 1,2,3,4 - any key to retry" && read -rsn1 "invalidwait" && return 1 ;;
	esac

	F_terminal_padding
	while true; do
		printf "%b Is %b%s%b correct? Y or N " "$tCHECK" "$tGRN" "$email_send_count_entry" "$tCLR"
		read -rsn1 "yesorno"
		case "$yesorno" in
			y|Y) sed -i "1,/user_message_count=.*/{s/user_message_count=.*/user_message_count='$email_send_count_entry'/;}" "$script_name_full"
			     user_message_count="$email_send_count_entry" ;;
			n|N) return 1 ;;
			*) F_fail_entry ;;
		esac
		break
	done

	user_message_interval_1=   #  reset for edits (terminal show)
	user_message_interval_2=
	user_message_interval_3=
	return 0
} # message_config

F_message_intervals_entry() {
	while [ "$user_message_count" -gt "$message_entry_loop" ] ; do
		F_term_show_msgcount message
		printf "%b Enter an interval type between Email notifications %b and %b\n" "$tTERMHASH" "$tGRN$message_entry_loop$tCLR" "$tGRN$email2count$tCLR"
		F_terminal_show "eg. s = second, m = minutes, h = hours, d = days"
		F_terminal_padding ;F_terminal_entry "Interval period : "
		read -r "message_interval_entry"

		case "$message_interval_entry" in
			s|m|h|d)
				[ "$message_interval_entry" = 's' ] && message_selection='seconds'
				[ "$message_interval_entry" = 'm' ] && message_selection='minutes'
				[ "$message_interval_entry" = 'h' ] && message_selection='hours'
				[ "$message_interval_entry" = 'd' ] && message_selection='days'
				printf "%b Enter a time period (%bx %s%b) : " "$tTERMHASH" "$tGRN" "$message_selection" "$tCLR"
				read -r "message_period_entry"
				F_terminal_padding
				if [ "$message_period_entry" -eq "$message_period_entry" ] 2> /dev/null; then

					while true; do
						printf "%b Is %s correct? Y or N" "$tCHECK" "$message_period_entry $message_selection"
						read -rsn1 "yesorno"
						case "$yesorno" in
							y|Y) ;;
							n|N) return 1 ;;
							*) F_fail_entry ;;
						esac
						break
					done
					message_interval_complete="$message_period_entry$message_interval_entry"
					sed -i "1,/user_message_interval_$message_entry_loop=.*/{s/user_message_interval_$message_entry_loop=.*/user_message_interval_$message_entry_loop='$message_interval_complete'/;}" "$script_name_full"
					eval "user_message_interval_$message_entry_loop=$message_interval_complete"   # set vars for terminal show (setup)
				else
					F_terminal_check_fail "Not a valid number, any key to retry" && read -rsn 1 "wait" && return 1
				fi
				message_entry_loop=$((message_entry_loop + 1))
				email2count=$((email2count + 1))
				;;
			*) F_terminal_check_fail "Invalid entry. s/m/h/d only, any key to retry" && read -rsn1 "wait" && return 1 ;;
		esac
	done
} ### message_intervals_entry

F_cron_unit() {
	F_term_show_msgcount cron
	F_terminal_show "Enter an interval time for this script to run in cron"
	F_terminal_padding ;F_terminal_show "DHCP WAN IP changes may not trigger a 'wan-event connected' call"
	F_terminal_show "This script will not run until next cron run time to notify you"
	F_terminal_padding ;printf "%b Select interval in '%bm%b' minutes or hours '%bh%b' : " "$tTERMHASH" "$tGRN" "$tCLR" "$tGRN" "$tCLR"

	read -r "cron_unit_entry"
	case "$cron_unit_entry" in
		m) cron_interval_unit="minute" ;;
		h) cron_interval_unit="hour" ;;
		*) return 1 ;;
	esac
	until F_cron_period ; do : ; done
	return 0
} ### cron_unit

F_cron_period() {
	F_terminal_padding ;printf "%b Enter time value - 'X' %ss : " "$tTERMHASH" "$cron_interval_unit"
	read -r "cron_period_entry"

	if [ "$cron_period_entry" -eq "$cron_period_entry" ] ; then
		if [ "$cron_interval_unit" = 'hour' ]; then
			if [ "$cron_period_entry" -gt 23 ]; then
				F_terminal_show "Error, - cron set to hours interval, value = or < 23 - Hit any key"
				read -rsn1 "intervalerror"
				printf "%b%b%b%b%b%b" "$tBACK" "$tERASE" "$tBACK" "$tERASE" "$tBACK" "$tERASE"
				return 1
			fi
		fi
		if [ "$cron_interval_unit" = 'minute' ]; then
			if [ "$cron_period_entry" -gt 59 ]; then
				F_terminal_show "Error, - cron set to minutes interval, value = or < 59 - Hit any key"
				read -rsn1 "intervalerror"
				printf "%b%b%b%b%b%b" "$tBACK" "$tERASE" "$tBACK" "$tERASE" "$tBACK" "$tERASE"
				return 1
			fi
		fi
		return 0

	else
		F_terminal_show "Invalid entry, try again - Hit any key"
		read -rsn 1 "errorcronwait"
		printf "%b%b%b%b%b%b" "$tBACK" "$tERASE" "$tBACK" "$tERASE" "$tBACK" "$tERASE"
		return 1
	fi
} ### cron_period

F_cron_interval() {
	if [ -n "$user_cron_interval" ] && [ -n "$user_cron_period" ]; then
		F_term_show_msgcount cron
		F_terminal_show "Cron run interval setting"
		F_terminal_padding
		while true; do
			printf "%b Cron aleady set to %b%s%b interval, keep this setting? Y or N" "$tCHECK" "$tGRN" "$user_cron_period $user_cron_interval" "$tCLR"
			read -rsn1 "cronexist"
			case "$cronexist" in
				y|Y) return 0 ;;
				n|N) user_cron_interval=""
				     user_cron_period="" ;;
				*) F_fail_entry ;;
			esac
			break
		done
	fi

	until F_cron_unit ; do : ; done

	cron_interval_entry="$cron_period_entry $cron_interval_unit"
	F_terminal_padding
	while true; do
		printf "%b Is %b%s%b interval correct? Y or N " "$tCHECK" "$tGRN" "$cron_interval_entry" "$tCLR"
		read -rsn1 "yesorno"
		case "$yesorno" in
			y|Y) ;;
			n|N) return 1 ;;
			*) F_fail_entry ;;
		esac
		break
	done

	sed -i "1,/user_cron_interval=.*/{s/user_cron_interval=.*/user_cron_interval='$cron_interval_unit'/;}" "$script_name_full" && user_cron_interval="$cron_interval_unit"
	sed -i "1,/user_cron_period=.*/{s/user_cron_period=.*/user_cron_period='$cron_period_entry'/;}" "$script_name_full" && user_cron_period="$cron_period_entry"
	F_terminal_check_ok "Done setting cron"
	user_cron_interval="$cron_interval_unit"
	user_cron_period="$cron_period_entry"
} ### cron_interval

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
	until F_cron_interval ; do : ; done

	created_on="$run_date"
	if [ -z "$created_date" ]; then
		sed -i "1,/created_date=.*/{s/created_date=.*/created_date='$created_on'/;}" "$script_name_full"
		created_date="$created_on"

	else
		while true; do
			F_start_message ;F_terminal_padding
			F_terminal_check "Upate script with new install date $(date +%c)? Y or N"
			read -rsn1 "updatewait"
			case "$updatewait" in
				y|Y) sed -i "1,/created_date=.*/{s/created_date=.*/created_date='$created_on'/;}" "$script_name_full"
				     F_terminal_check_ok "Updated script with current date/time as install date"
				     created_date="$created_on" ;;   # for terminal show in setup
				n|N) F_terminal_check_ok "Leaving original install date" ;;
				*) F_fail_entry ;;
			esac
			break
		done
	fi

	F_start_message ;F_terminal_show "Adding entries in cron(cru)/services-start/wan-event for wicens"
	F_auto_run_check
	F_terminal_check_ok "Done, entries added in cron(cru)/services-start/wan-event for wicens"
	F_terminal_padding ;F_terminal_check "Any key to continue" ; read -rsn 1 "check_wait"

	if [ -z "$saved_wan_ip" ]; then
		F_saved_wan_ip_create
		F_terminal_check "Any key to continue to sample Email output"
		read -rsn1 "continuewait"
	fi

	F_opt_sample

	F_terminal_padding ;F_terminal_check "Hit t to send a test Email, any key to exit"
	read -rsn1 "setupwait"

	case "$setupwait" in
		t|T) rm -f /tmp/wicens.lock && exec sh /jffs/scripts/$script_name test ;;
		*) ;;
	esac

	printf "\r%b" "$tERASE"
	F_terminal_show "Run wicens on the command line to run script manually with set config"
	F_clean_exit
} ### build_settings

F_saved_wan_ip_create() {
	saved_wan_date="$run_date"
	F_terminal_header
	F_log_and_show "No saved WAN IP found, attempting to write current to this script"
	internet_check_count=0
	until F_internet_check ; do : ; done
	F_current_wan_ip_get
	F_update_script
	saved_wan_ip="$current_wan_ip"
	rm -f /tmp/wicensmail.txt 2> /dev/null
} ### saved_wan_ip_check

F_reset_count() {
	F_terminal_check "Resetting script cron/wancall counts/install date"
	sed -i "1,/cron_run_count=.*/{s/cron_run_count=.*/cron_run_count=0/;}" "$script_name_full"
	sed -i "1,/last_cron_run=.*/{s/last_cron_run=.*/last_cron_run=''/;}" "$script_name_full"
	sed -i "1,/last_cron_log_count=.*/{s/last_cron_log_count=.*/last_cron_log_count=0/;}" "$script_name_full"
	sed -i "1,/wancall_run_count=.*/{s/wancall_run_count=.*/wancall_run_count=0/;}" "$script_name_full"
	sed -i "1,/last_wancall_run=.*/{s/last_wancall_run=.*/last_wancall_run=''/;}" "$script_name_full"
	sed -i "1,/last_wancall_log_count=.*/{s/last_wancall_log_count=.*/last_wancall_log_count=0/;}" "$script_name_full"
	sed -i "1,/created_date=.*/{s/created_date=.*/created_date=''/;}" "$script_name_full"
	F_log_and_terminal_ok "Reset cron/wancall counts, install date to default"

	if [ "$passed_options" = 'count' ] && [ "$last_ip_change" != 'never' ]; then   # if run by count check if remove, otherwise this is only run by full reset
		while true; do
				F_terminal_check "Do you want to reset the last recorded WAN IP change date? Y or N?"
				read -rsn1 "reset_wait"
				case "$reset_wait" in
					y|Y) sed -i "1,/last_ip_change=.*/{s/last_ip_change=.*/last_ip_change='never'/;}" "$script_name_full"
						 F_log_and_terminal_ok "Reset last recorded WAN IP change date"
						 return 0 ;;
					n|N) F_terminal_check_ok "Leaving last WAN IP recorded change date to current"
						 return 0 ;;
					*) F_fail_entry ;;
				esac
				break
		done

	else
		sed -i "1,/last_ip_change=.*/{s/last_ip_change=.*/last_ip_change='never'/;}" "$script_name_full"
	fi
	return 0
} # counts_reset

F_reset_do() {
	printf "\r%b Resetting script to default" "$tERASE$tCHECK"
	sed -i "1,/saved_wan_ip=.*/{s/saved_wan_ip=.*/saved_wan_ip=''/;}" "$script_name_full"
	sed -i "1,/saved_wan_date=.*/{s/saved_wan_date=.*/saved_wan_date=''/;}" "$script_name_full"
	sed -i "1,/saved_wan_epoch=.*/{s/saved_wan_epoch=.*/saved_wan_epoch=''/;}" "$script_name_full"
	sed -i "1,/user_cron_interval=.*/{s/user_cron_interval=.*/user_cron_interval='minute'/;}" "$script_name_full"
	sed -i "1,/user_cron_period=.*/{s/user_cron_period=.*/user_cron_period='31'/;}" "$script_name_full"
	sed -i "1,/user_from_addr=.*/{s/user_from_addr=.*/user_from_addr=''/;}" "$script_name_full"
	sed -i "1,/user_from_name=.*/{s/user_from_name=.*/user_from_name=''/;}" "$script_name_full"
	sed -i "1,/user_send_to_addr=.*/{s/user_send_to_addr=.*/user_send_to_addr=''/;}" "$script_name_full"
	sed -i "1,/user_send_to_cc=.*/{s/user_send_to_cc=.*/user_send_to_cc=''/;}" "$script_name_full"
	sed -i "1,/user_smtp_server=.*/{s/user_smtp_server=.*/user_smtp_server=''/;}" "$script_name_full"
	sed -i "1,/user_pswd=.*/{s/user_pswd=.*/user_pswd=''/;}" "$script_name_full"
	sed -i "1,/user_message_type=.*/{s/user_message_type=.*/user_message_type=''/;}" "$script_name_full"
	sed -i "1,/user_message_count=.*/{s/user_message_count=.*/user_message_count=''/;}" "$script_name_full"
	sed -i "1,/user_message_interval_1=.*/{s/user_message_interval_1=.*/user_message_interval_1=''/;}" "$script_name_full"
	sed -i "1,/user_message_interval_2=.*/{s/user_message_interval_2=.*/user_message_interval_2=''/;}" "$script_name_full"
	sed -i "1,/user_message_interval_3=.*/{s/user_message_interval_3=.*/user_message_interval_3=''/;}" "$script_name_full"
	sed -i "1,/user_custom_subject=.*/{s/user_custom_subject=.*/user_custom_subject=''/;}" "$script_name_full"
	sed -i "1,/user_custom_text=.*/{s/user_custom_text=.*/user_custom_text=''/;}" "$script_name_full"
	sed -i "1,/user_custom_script=.*/{s/user_custom_script=.*/user_custom_script=''/;}" "$script_name_full"
	sed -i "1,/user_custom_script_w=.*/{s/user_custom_script_w=.*/user_custom_script_w=''/;}" "$script_name_full"

	F_log_and_terminal_ok "Done, script reset to default"
	[ -f "/jffs/configs/Equifax_Secure_Certificate_Authority.pem" ] && rm -f /jffs/configs/Equifax_Secure_Certificate_Authority.pem
	[ -f "/tmp/wicenssendmail.log" ] && rm -f /tmp/wicenssendmail.log
	return 0
} ### reset_do

F_disable_autorun() {
	F_terminal_check "Removing cron entry for wicens"
	if cru l | grep -q "$script_name cron" ; then
		cru d "wicens"
		F_terminal_check_ok "Removed cron entry for wicens" ;F_log_this "Removed cron entry for wicens"
	else
		F_terminal_check_ok "No cron(cru) entry for wicens found to remove"
	fi

	F_terminal_check "Removing services-start entry for wicens"
	if [ -f "/jffs/scripts/services-start" ]; then
		if grep -q "$script_name cron" "/jffs/scripts/services-start" 2> /dev/null; then
			sed -i '/cru a wicens/d' /jffs/scripts/services-start
			F_terminal_check_ok "Removed services-start entry for wicens" ;F_log_this "Removed services-start entry for wicens"
		else
			F_terminal_check_ok "No entry found in services-start to remove"
		fi

		if [ "$(wc -l < /jffs/scripts/services-start )" -eq 1 ]; then
			if grep -q "#!/bin/sh" "/jffs/scripts/services-start"; then
				F_terminal_show "/jffs/scripts/services-start appears empty, should I remove it?"
				F_terminal_show "Contents :"
				cat /jffs/scripts/services-start
				F_terminal_padding
				while true; do
					F_terminal_check "Remove? Y or N"
					read -rsn1 "remove_serv_start"
					case "$remove_serv_start" in
						y|Y) rm -f "/jffs/scripts/services-start"
							printf "%b" "$tERASE$tBACK$tERASE$tBACK$tERASE$tBACK$tERASE$tBACK"
							F_terminal_check_ok "Removed /jffs/scripts/services-start" ;F_log_this "Removed /jffs/scripts/services-start"
							;;
						n|N) F_terminal_check_ok "Not removing, leaving /jffs/scripts/services-start in place" ;;
						*) F_fail_entry ;;
					esac
					break
				done
			fi
		fi

	else
		F_terminal_check_ok "/jffs/scripts/services-start is already removed"
	fi

	F_terminal_check "Removing wan-event entry for wicens"
	if [ -f "/jffs/scripts/wan-event" ]; then
		if grep -q "$script_name wancall" "/jffs/scripts/wan-event" 2> /dev/null; then
			sed -i "/$script_name wancall/d" "/jffs/scripts/wan-event"			# john9527
			F_log_and_terminal_ok "Removed wan-event entry for wicens"
		else
			F_terminal_check_ok "No entry found for wicens in /jffs/scripts/wan-event"
		fi

		if [ "$(wc -l < /jffs/scripts/wan-event)" -eq 1 ]; then
			if grep -q "#!/bin/sh" "/jffs/scripts/wan-event"; then
				F_terminal_show "/jffs/scripts/wan-event appears empty, should I remove it?"
				F_terminal_show "Contents :"
				cat /jffs/scripts/wan-event
				F_terminal_padding
				while true; do
					F_terminal_check "Remove? Y or N(any key) "
					read -rsn1 "remove_wanevent"
					case "$remove_wanevent" in
						y|Y) rm -f "/jffs/scripts/wan-event"
							printf "%b" "$tERASE$tBACK$tERASE$tBACK$tERASE$tBACK$tERASE$tBACK"
							F_log_and_terminal_ok "Removed /jffs/scripts/wan-event" ;;
						n|N) F_terminal_check_ok "Not removing , leaving /jffs/scripts/wan-event in place" ;;
						*) F_fail_entry ;;
					esac
					break
				done
			fi
		fi

	else
		F_terminal_check_ok "/jffs/scripts/wan-event is already removed"
	fi
	return 0
} ### disable_autorun


# --------- MAIN FUNCTIONS BELOW --------------------------------------------------------------------------------------

# --------- MAIL ------------------------------------------------------------------------------------------------------

F_email_message() {
	if [ -n "$user_custom_subject" ];then   # needs to be here as current_wan_ip isnt set till right before this runs
		formatted_custom_subject="$(echo "$user_custom_subject_decoded" | sed "s~\$device_model~$device_model~g" | sed "s~\$current_wan_ip~$current_wan_ip~g" | sed "s~\$saved_wan_ip~$saved_wan_ip~g" )"
	fi

	[ -f "/tmp/wicensmail.txt" ] && rm -f "/tmp/wicensmail.txt"
	touch "/tmp/wicensmail.txt"

	{  # start of message output part 1/2
		[ -n "$user_send_to_cc" ] && echo "Cc: $user_send_to_cc"
		[ -z "$user_custom_subject" ] && echo "Subject: WAN IP has changed on $device_model" || echo "Subject: $formatted_custom_subject"
		echo "From: $user_from_name <$user_from_addr>"
		echo "Date: $(date +%c)"
		echo ""
		[ "$test_mode_active" = 'yes' ] && [ "$passed_options" != 'sample' ] && echo "### This is a TEST message ###" && echo ""
		echo "NOTICE"
		echo ""
		echo "WAN IP for $user_from_name $device_model has changed"
		echo ""
		echo "New WAN IP is   : $current_wan_ip"
		echo ""
		echo "Old WAN IP was  : $saved_wan_ip"
		F_calc_lease   # calc and write lease time to email
		echo ""
		[ -n "$user_custom_text" ] && echo -e "$user_custom_text_decoded" && echo ""
		echo "----------------------------------------------------------------------------"
		echo ""
	} >> /tmp/wicensmail.txt # end of output 1/2
	if [ "$user_message_count" -gt 1 ]; then
		if [ "$loop_run" = 1 ]; then
			echo "Message 1 of $user_message_count, you will receive another reminder in $user_message_interval_1" >> /tmp/wicensmail.txt

		else
			echo "Message $loop_run of $user_message_count" >> /tmp/wicensmail.txt
			echo "" >> /tmp/wicensmail.txt
			if [ "$loop_run" = "$user_message_count" ]; then
				echo "No more notifications, update your devices" >> /tmp/wicensmail.txt
				[ "$test_mode_active" != 'yes' ] && echo "" >> /tmp/wicensmail.txt && F_update_script # test mode dont update script

			else
				if [ "$loop_run" = '2' ]; then
					echo "You will receive another reminder in $user_message_interval_2" >> /tmp/wicensmail.txt
				fi
				if [ "$loop_run" = '3' ]; then
					echo "You will receive another reminder in $user_message_interval_3" >> /tmp/wicensmail.txt
				fi
			fi
		fi

	else
		echo "Message 1 of $user_message_count - No more notifications, update your devices" >> /tmp/wicensmail.txt
		[ "$test_mode_active" != 'yes' ] && F_update_script # test mode dont update script, update script outputs to mail message as well
	fi
	{ # start of message output 2/2
		echo ""
		echo "Message sent : $(date +%c)"
		echo ""
		echo "A message from wicens script on your $device_model"
		if [ "$passed_options" != 'sample' ] ; then   # padding incase emails contain footer info
			echo ""
			echo ""
		fi
	} >> /tmp/wicensmail.txt  # end of message output 2/2

	loop_run="$((loop_run + 1))"
} ### email_message

F_send_format_isp() {
	/usr/sbin/sendmail >> /tmp/wicenssendmail.log 2>&1 < /tmp/wicensmail.txt \
	-S "$user_smtp_server" -f "$user_from_addr" -t "$user_send_to_addr"
} ### message_format_isp

F_send_format_start_tls() {
	# -CAfile /jffs/configs/Equifax_Secure_Certificate_Authority.pem
	/usr/sbin/sendmail >> /tmp/wicenssendmail.log 2>&1 < /tmp/wicensmail.txt \
	-H "exec openssl s_client -quiet \
	-starttls smtp \
	-connect $user_smtp_server  \
	-no_ssl3 -no_tls1" \
	-t \
	-f "$user_from_name" -au"$user_from_addr" -ap"$user_pswd" "$user_send_to_addr" -v
} ### message_format_tls

F_send_format_tls_v1() {
	# -CAfile /jffs/configs/Equifax_Secure_Certificate_Authority.pem
	sendmail >> /tmp/wicenssendmail.log 2>&1 < /tmp/wicensmail.txt \
	-H "exec openssl s_client -quiet \
	-tls1 -starttls smtp \
	-connect $user_smtp_server" \
	-t \
	-f "$user_from_name" -au"$user_from_addr" -ap"$user_pswd" "$user_send_to_addr" -v
} ### message_format_tls1_only

F_send_format_plain_auth() {
	/usr/sbin/sendmail >> /tmp/wicenssendmail.log 2>&1 < /tmp/wicensmail.txt \
	-t -S "$user_smtp_server" -f "$user_from_name" "$user_send_to_addr" -au"$user_from_addr" -ap"$user_pswd"
} ### message_format_smtp

F_send_format_ssl() {
	if [ -z "$user_send_to_cc" ]; then
		curl >> /tmp/wicenssendmail.log 2>&1 \
		--url smtps://"$user_smtp_server" \
		--mail-from "$user_from_name" --mail-rcpt "$user_send_to_addr" \
		--upload-file /tmp/wicensmail.txt \
		--ssl-reqd \
		--user "$user_from_addr:$user_pswd" \
		-v
	else
		curl >> /tmp/wicenssendmail.log 2>&1 \
		--url smtps://"$user_smtp_server" \
		--mail-from "$user_from_name" --mail-rcpt "$user_send_to_addr" \
		--mail-rcpt "$user_send_to_cc" \
		--upload-file /tmp/wicensmail.txt \
		--ssl-reqd \
		--user "$user_from_addr:$user_pswd" \
		-v
	fi
} ### message_format_ssl

F_send_message() {
	touch /tmp/wicenssendmail.log
	echo "Created by PID $$ on $(date +%c), ran by $passed_options" >> /tmp/wicenssendmail.log
	if [ "$user_message_type" = 'smtp_isp_nopswd' ]; then
		F_send_format_isp && return 0 || return 1
	elif [ "$user_message_type" = 'smtp_plain_auth' ]; then
		F_send_format_plain_auth && return 0 || return 1
	elif [ "$user_message_type" = 'smtp_start_tls' ]; then
		F_send_format_start_tls && return 0 || return 1
	elif [ "$user_message_type" = 'smtp_start_tls_v1' ]; then
		F_send_format_tls_v1 && return 0 || return 1
	elif [ "$user_message_type" = 'smtp_ssl' ]; then
		F_send_format_ssl && return 0 || return 1
	fi
} ### send_message

F_send_mail() {
	rm -f "/tmp/wicenssendmail.log" 2> /dev/null
	touch "/tmp/wicenssendmail.lock" # temp lockfile#2
	echo "Sending mail for $script_name_full on : $(date +%c)" >> /tmp/wicenssendmail.lock
	echo "Sending mail from $(cat /tmp/wicens.lock)" >> /tmp/wicenssendmail.lock

	loop_run='1'
	while [ "$loop_run" -le "$user_message_count" ] ; do
		printf "%b Sending Email message %s of %s" "$tCHECK" "$loop_run" "$user_message_count"

		F_email_message #  generates Email text and increases loop_run!

		if ! F_send_message; then
			printf "\r%b Error, failed to send Email notification %s of %s\n" "$tERASE$tCHECKFAIL" "$((loop_run - 1))" "$user_message_count"
			F_log_this "CRITICAL ERROR - wicens failed to send Email notification $((loop_run - 1)) of $user_message_count"

			F_log_and_show "Are your Email settings in this script correct? and password?"
			F_log_and_show "Or maybe your Email host server was temporarily down?"
			F_log_and_show "Main Menu - option 6 for errors - p to re-enter password"
			rm -f "/tmp/wicensmail.txt"
		fi

		printf "\r%b Done sending message %s of %s\n" "$tERASE$tCHECKOK" "$((loop_run - 1))" "$user_message_count"
		rm -f "/tmp/wicensmail.txt"
		F_log_this "Done sending Email $((loop_run - 1)) of $user_message_count update your clients to $current_wan_ip"

		if [ "$loop_run" -le "$user_message_count" ]; then

			if [ "$test_mode_active" = 'yes' ];then   # left over from multi Email test
				sleep_count=10
				while [ "$sleep_count" != '0' ]
				do
					printf "%b Sleeping %s second(s) before sending next Email \r" "$tCHECK" "$sleep_count"
					sleep_count=$((sleep_count - 1))
					sleep 1
				done

			else   # test mode NOT active
				if [ "$loop_run" = '2' ]; then
					printf "%b Sleeping %s before sending next Email" "$tCHECK" "$user_message_interval_1"
					F_log_this "Sleeping $user_message_interval_1 before sending next Email"
					sleep "$user_message_interval_1"
				fi
				if [ "$loop_run" = '3' ]; then
					printf "%b Sleeping %s before sending next Email" "$tCHECK" "$user_message_interval_2"
					F_log_this "Sleeping $user_message_interval_2 before sending next Email"
					sleep "$user_message_interval_2"
				fi
				if [ "$loop_run" = '4' ]; then
					printf "%b Sleeping %s before sending next email" "$tCHECK" "$user_message_interval_3"
					F_log_this "Sleeping $user_message_interval_3 before sending next Email"
					sleep "$user_message_interval_3"
				fi
			fi
		fi
	done

	# user_custom_script 'wait' call
	if [ -n "$user_custom_script" ] && [ "$user_custom_script_w" = 'w' ] && [ "$passed_options" != 'test' ] ; then
		(nohup sh "$user_custom_script_decoded" >/dev/null 2>&1) & custom_script_pid=$!			# v1.11
		F_log_this "Executed custom script $user_custom_script_decoded and put in background with PID $custom_script_pid"
		F_terminal_check_ok "Started user custom script and put in background"
	fi

	rm -f "/tmp/wicenssendmail.lock"
	if [ "$from_menu" = 'yes' ] ; then
		F_menu_exit
	else
		F_clean_exit
	fi
} ### send_mail


# ------------ CRON-INTERNET CHECK/GET WAN/EXIT/FINISH ----------------------------------------------------------------

F_auto_run_check() {

	F_cru_check() {
		if cru l | grep -q "$cron_current_setting" ; then
			printf "\r%b Cron(cru) : %s %bexists%b\n" "$tERASE$tCHECKOK" "$(cru l | grep 'wicens')" "$tGRN" "$tCLR"
		else
			cru l | grep -q 'wicens' && cru d 'wicens'   # cleanup old non-matching time entry if exists

			F_terminal_check_fail "No entry found in cron(cru)" ;F_log_this "No entry found in cron(cru), attempting to create"
			printf "%b Adding entry for wicens in cron(cru) with %s interval" "$tCHECK" "$user_cron_period $user_cron_interval"

			if [ "$user_cron_interval" = 'minute' ]; then
				cru a wicens "*/$user_cron_period * * * * $script_name_full cron"
			elif [ "$user_cron_interval" = 'hour' ]; then
				cru a wicens "* */$user_cron_period * * * $script_name_full cron"
			fi

			printf "\r%b Added entry for wicens in cron(cru) with %s %s interval  \n" "$tERASE$tCHECKOK" "$user_cron_period" "$user_cron_interval"
			F_log_this "Created cron(cru) $user_cron_period $user_cron_interval interval entry for wicens"
		fi
	} # cru_check

	F_serv_start_check() {
		if [ -f "/jffs/scripts/services-start" ]; then
			[ ! -x "/jffs/scripts/services-start" ] && chmod a+rx "/jffs/scripts/services-start"
			printf "\r%b /jffs/scripts/services-start %bexists%b\n" "$tERASE$tCHECKOK" "$tGRN" "$tCLR"
			F_terminal_check "Checking for wicens entry"

			if grep -q "$cron_current_setting" "/jffs/scripts/services-start" ; then
				printf "\r%b %s %bexists%b\n" "$tERASE$tCHECKOK" "$(grep 'wicens' "/jffs/scripts/services-start" | cut -c -56)" "$tGRN" "$tCLR"
			else
				# cleanup
				grep -q "cru a wicens" /jffs/scripts/services-start && sed -i '/cru a wicens/d' /jffs/scripts/services-start

				F_terminal_check_fail "No entry in services-start for cron(cru)"
				F_terminal_check "Adding cron(cru) to /jffs/scripts/services-start"

				if ! grep -q '#!/bin/sh' /jffs/scripts/services-start; then
					F_log_this "Your services-start does not contain a '#!/bin/sh', please investigate and run again"
					F_terminal_check_fail "Your services-start does not contain a '#!/bin/sh', please investigate and run again"
					F_clean_exit
				fi

				if [ "$user_cron_interval" = 'minute' ]; then
					echo "cru a wicens \"*/$user_cron_period * * * * /jffs/scripts/$script_name cron\"   # added by wicens" >> /jffs/scripts/services-start
				elif [ "$user_cron_interval" = "hour" ]; then
					echo "cru a wicens \"* */$user_cron_period * * * /jffs/scripts/$script_name cron\"   # added by wicens" >> /jffs/scripts/services-start
				fi

				F_log_and_terminal_ok "Added a cron(cru) entry for wicens to /jffs/scripts/services-start"
			fi

		else
			F_terminal_check_fail "/jffs/scripts/services-start does not exists"
			F_log_this "/jffs/scripts/services-start does not exist, attempting to create"
			F_terminal_check "Creating /jffs/scripts/services-start"
			touch "/jffs/scripts/services-start"
			echo "#!/bin/sh" >> /jffs/scripts/services-start
			if [ "$user_cron_interval" = 'minute' ]; then
				echo "cru a wicens \"*/$user_cron_interval * * * * /jffs/scripts/$script_name cron\"   # added by wicens" >> /jffs/scripts/services-start
			elif [ "$user_cron_interval" = 'hour' ]; then
				echo "cru a wicens \"* */$user_cron_interval * * * /jffs/scripts/$script_name cron\"   # added by wicens" >> /jffs/scripts/services-start
			fi
			chmod a+rx "/jffs/scripts/services-start"
			F_log_and_terminal_ok "Created services-start in /jffs/scripts/, added cron entry"
		fi
	} # serv_start_check

	F_wan_event_check() {
		if [ -f "/jffs/scripts/wan-event" ]; then
			[ ! -x "/jffs/scripts/wan-event" ] && chmod a+rx "/jffs/scripts/wan-event"
			printf "\r%b /jffs/scripts/wan-event %bexists%b\n" "$tERASE$tCHECKOK" "$tGRN" "$tCLR"
			F_terminal_check "Checking for wicens entry"
			if grep -q "/jffs/scripts/$script_name wancall" "/jffs/scripts/wan-event" ; then
				printf "\r%b %s %bexists%b\n" "$tERASE$tCHECKOK" "$(grep "/jffs/scripts/$script_name wancall" "/jffs/scripts/wan-event" | cut -c -62)" "$tGRN" "$tCLR"

			else
				F_terminal_check_fail "No wicens reference found in wan-event script"
				F_terminal_check "Adding wicens to wan-event script on connected event"

				if ! grep -q '#!/bin/sh' /jffs/scripts/wan-event ; then
					F_terminal_check_fail "Your wan-event does not contain a '#!/bin/sh', please investigate and run again"
					F_log_this "Your wan-event does not contain a '#!/bin/sh', please investigate and run again"
					F_clean_exit
				fi

				echo "[ \"\$2\" = 'connected' ] && sh /jffs/scripts/$script_name wancall &   # added by wicens" >> /jffs/scripts/wan-event
				F_log_and_terminal_ok "Added wicens to wan-event with connected event trigger"
			fi

		else
			F_terminal_check_fail "/jffs/scripts/wan-event does not exist"
			F_log_this "/jffs/scripts/wan-event does not exist, attempting to create"
			F_terminal_check "Creating /jffs/scripts/wan-event"
			touch "/jffs/scripts/wan-event"
			echo "#!/bin/sh" >> /jffs/scripts/wan-event
			echo "[ \"\$2\" = 'connected' ] && sh /jffs/scripts/$script_name wancall &   # added by wicens" >> /jffs/scripts/wan-event
			chmod a+rx "/jffs/scripts/wan-event"
			F_terminal_check_ok "Created wan-event in /jffs/scripts/"
			F_terminal_check_ok "Added connected event entry for wicens in /jffs/scripts/wan-event"
			F_log_this "Created wan-event in /jffs/scripts/ and added connected event entry for wicens"
		fi
	} # wan_event_check

	# used in cron and services-start checks
	if [ "$user_cron_interval" = 'hour' ]; then
		cron_current_setting="\* \*/$user_cron_period \* \* \* $script_name_full cron"
	elif [ "$user_cron_interval" = 'minute' ]; then
		cron_current_setting="\*/$user_cron_period \* \* \* \* $script_name_full cron"
	fi

	F_terminal_check "cron(cru) check" && F_cru_check
	F_terminal_check "services-start check" && F_serv_start_check
	F_terminal_check "wan-event check" && F_wan_event_check
} ### auto_run_check

F_google_ping() {
	F_test_sites() { echo "google.com" ;echo "github.com" ;echo "yahoo.com" ;}

	good_ping=0
	for tested_site in $(F_test_sites)
	do
		ping_try_count=1
		while [ "$ping_try_count" != '3' ]
		do
			ping -q -w2 -c1 "$tested_site" > /dev/null 2>&1 && good_ping=$((good_ping + 1)) && break
			ping_try_count=$((ping_try_count + 1))
		done
	done

	[ "$good_ping" -ge 2 ] && return 0 || return 1
} ### google_ping

F_internet_check() {   # called with until loop for better restart control
	internet_check_count=$((internet_check_count + 1))
	if [ "$internet_check_count" = '10' ]; then
		F_terminal_check_fail "Could not ping Google/GitHub/Amazon for the last 5 mins, exiting. Run again with next cron"
		F_log_this "Could not ping Google/GitHub/Amazon for the last 5 mins, exiting. Run again with next cron"
		F_clean_exit
	fi

	F_terminal_check "Checking Internet status"

	if F_google_ping; then
		F_terminal_check_ok "Internet check      : Ping success, appears up"
		return 0

	else
		F_terminal_check_fail "Failed pinging Google/GitHub/Amazon 2 times each"
		wait_secs=30
		while [ "$wait_secs" != '0' ]; do
			printf "%b %b%s%b seconds before next attempt \r" "$tERASE$tCHECK" "$tGRN" "$wait_secs" "$tCLR"
			sleep 1
			wait_secs=$((wait_secs - 1))
		done

		return 1
	fi
} ### internet_check

F_current_wan_ip_get() {
	getrealip_call_count=3   # max tries to get WAN IP

	F_getrealip() {   # watcher for getrealip.sh so if it hangs it doesnt sit around forever
		sleep_wait=5
		( sh /usr/sbin/getrealip.sh | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" ) & command_pid=$!
		( sleep "$sleep_wait" && kill -HUP "$command_pid" 2> /dev/null && rm -f /tmp/wicenswanipget.tmp && F_log_this "NOTICE - Killed hung getrealip.sh process after 5 secs" ) & watcher_pid=$!
		wait "$command_pid" && kill -HUP "$watcher_pid" 2> /dev/null
		getrealip_call_count=$((getrealip_call_count - 1))
	} # getrealip

	while [ "$getrealip_call_count" != '0' ]; do   #  check for WAN IP 3 times
		F_terminal_check "Retrieving WAN IP using getrealip.sh"

		F_getrealip > /tmp/wicenswanipget.tmp   # output to file or watcher doesnt function properly when var=
		current_wan_ip=$(grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" /tmp/wicenswanipget.tmp 2>/dev/null )
		[ -f "/tmp/wicenswanipget.tmp" ] && rm -f /tmp/wicenswanipget.tmp

		if [ -z "$current_wan_ip" ]; then
			if [ "$getrealip_call_count" -eq 0 ]; then
				F_terminal_check_fail "Error retrieving WAN IP 3 times... aborting...."
				F_log_this "Error retrieving WAN IP 3 times... aborting...."
				F_clean_exit
			else
				F_terminal_check_fail "Error retrieving WAN IP, attempt again in 60secs"
				sleep 60
				printf "%b" "$tBACK$tERASE"
			fi

		else
			break
		fi
	done

	F_private_ip() {
			grep -qE "(^127\.)|(^(0)?10\.)|(^172\.(0)?1[6-9]\.)|(^172\.(0)?2[0-9]\.)|(^172\.(0)?3[0-1]\.)|(^169\.254\.)|(^192\.168\.)"
	} # private_ip

	if echo "$current_wan_ip" | F_private_ip ; then
		printf "\r%b WAN IP %s is a private IP, something is wrong" "$tERASE$tCHECKFAIL" "$current_wan_ip"
		F_log_this "ERROR - WAN IP $current_wan_ip is a private IP, something is wrong"
		F_clean_exit
	fi
} ### current_wan_ip_get

F_update_script() {
	[ "$ip_match" = 'no' ] && sed -i "1,/last_ip_change=.*/{s/last_ip_change=.*/last_ip_change='$run_date'/;}" "$script_name_full" # only write on change
	[ "$building_settings" = 'yes' ] && F_terminal_check_ok "IP successfully retrieved"
	printf "%b Updating wicens script with new WAN IP %b%s%b" "$tCHECK" "$tYEL" "$current_wan_ip" "$tCLR"

	if sed -i "1,/saved_wan_ip=.*/{s/saved_wan_ip=.*/saved_wan_ip='$current_wan_ip'/;}" "$script_name_full"; then
		printf "\r%b Updated wicens script with new WAN IP %b%s%b  \n" "$tERASE$tCHECKOK" "$tYEL" "$current_wan_ip" "$tCLR"
		F_terminal_check "Confirming new WAN IP in wicens"

		if grep -q "$current_wan_ip" $script_name_full ; then
			F_log_and_terminal_ok "Success updating wicens script w/ new WAN IP"
			echo "Updating wicens script with new WAN IP $current_wan_ip : Success" >> /tmp/wicensmail.txt
		else
			F_terminal_check_fail "Confirming new WAN IP in wicens"
			F_log_this "FAILED confirmation of updating wicens with new WAN IP : $current_wan_ip"
			echo "Updating wicens script with new WAN IP $current_wan_ip : Confirmation Failed" >> /tmp/wicensmail.txt
		fi
		sed -i "1,/saved_wan_date=.*/{s/saved_wan_date=.*/saved_wan_date='$run_date'/;}" "$script_name_full"
		sed -i "1,/saved_wan_epoch=.*/{s/saved_wan_epoch=.*/saved_wan_epoch='$run_epoch'/;}" "$script_name_full"

	else
		F_terminal_check_fail "Updating wicens with new WAN IP : sed failed"
		F_log_this "FAILED (sed) updating wicens with new WAN IP"
		echo "Updating WICENS script with new WAN IP $current_wan_ip : sed Failed" >> /tmp/wicensmail.txt
	fi
} ### update_script

F_calc_lease() {
	wan_lease_years=0 ;wan_lease_days=0 ;wan_lease_hours=0 ;wan_lease_mins=0 ;wan_lease_secs=0   # set for output
	epoch_diff=$((run_epoch - saved_wan_epoch))
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
	wan_lease_secs=$epoch_diff   			# secs

	# output for Email in F_email_message
	echo ''
	printf "Old WAN IP recorded in script on : %s \n" "$saved_wan_date"
	printf "WAN IP Lease time observed       : "
	[ $wan_lease_years -gt 0 ] && printf "%s yr(s) " "$wan_lease_years"
	[ $wan_lease_days -gt 0 ] && printf "%s day(s) " "$wan_lease_days"
	[ $wan_lease_hours -gt 0 ] && printf "%s hr(s) " "$wan_lease_hours"
	[ $wan_lease_mins -gt 0 ] && printf "%s min(s) " "$wan_lease_mins"
	printf "%s sec(s) \n" "$wan_lease_secs"
} ### calc_lease

F_clean_exit() {
	[ "$passed_options" = 'remove' ] && F_terminal_check_ok "Exiting." && F_terminal_padding && exit 0

	F_terminal_check "Exiting, removing /tmp/wicens.lock file"

	rm -f "/tmp/wicens.lock"
	[ -f "/tmp/wicenssendmail.lock" ] && rm -f "/tmp/wicenssendmail.lock"

	if [ ! -f "/tmp/wicens.lock" ]; then
		F_terminal_check_ok "Removed /tmp/wicens.lock file"
		F_script_finish
		printf "%b Script run time %b%s%b - %bGoodbye%b \n" "$tERASE$tCHECKOK" "$tYEL" "$run_time_pretty" "$tCLR" "$tYEL" "$tCLR"
		F_terminal_padding
		exit 0

	else
		if [ "$$" != "$(sed -n '2p' /tmp/wicens.lock)" ]; then
			F_terminal_check_ok "Exiting, removing /tmp/wicens.lock file"
			F_terminal_show "Lock file still present but not from this process..."
			F_terminal_show "likely another process started while this one was exiting"
			F_script_finish
			printf "%b Script run time %s\n" "$tERASE$tCHECKOK" "$run_time_pretty"
			F_terminal_padding
			exit 0

		else
			F_terminal_check_fail "CRITICAL ERROR - Failed to remove lock file"
			F_log_this "CRITICAL ERROR - Failed to remove lock file"
		fi
	fi
} ### clean_exit

F_script_finish() {
	script_stop_time="$(cut -f1 -d ' ' /proc/uptime | tr -d '.')"
	total_run_time="$((script_stop_time-script_start_time))"
	[ "$total_run_time" -le 99 ] && run_time_pretty="${total_run_time}0 ms" || run_time_pretty="$(echo $total_run_time | sed 's/..$/.&/' | sed 's/$/ s&/')"
} ### script_finish

F_settings_test() {
	settings_test='OK'
	if [ -z "$user_cron_interval" ] || [ -z "$user_cron_period" ] || [ -z "$user_from_addr" ] || [ -z "$user_message_count" ] || [ -z "$user_message_type" ] || [ -z "$user_send_to_addr" ] || [ -z "$user_smtp_server" ]; then
		return 1
	fi

	if [ "$user_message_count" -ge 2 ] && [ -z "$user_message_interval_1" ]; then
		printf "[%bFAIL%b] Email notifications set to %s, missing interval 1/2 value" "$tRED" "$tCLR" "$user_message_count"
		F_log_this "Email notifications set to $user_message_count, missing interval 1/2 value"
		settings_test='FAIL'
	fi

	if [ "$user_message_count" -ge 3 ] && [ -z "$user_message_interval_2" ]; then
		printf "[%bFAIL%b] Email notifications set to %s, missing interval 2/3 value" "$tRED" "$tCLR" "$user_message_count"
		F_log_this "Email notifications set to $user_message_count, missing interval 2/3 value"
		settings_test='FAIL'
	fi

	if [ "$user_message_count" -eq 4 ] && [ -z "$user_message_interval_3" ]; then
		printf "[%bFAIL%b] Email notifications set to %s, missing interval 3/4 value" "$tRED" "$tCLR" "$user_message_count"
		F_log_this "Email notifications set to $user_message_count, missing interval 3/4 value"
		settings_test='FAIL'
	fi

	if [ -z "$user_pswd" ] && [ "$user_message_type" != 'smtp_isp_nopswd' ]; then
		printf "[%bFAIL%b] Email send type set to %s but missing required password" "$tRED" "$tCLR" "$user_message_type"
		F_log_this "Email send type set to $user_message_type but missing required password"
		settings_test='FAIL'
	fi

	# CLEAN UP
	# clean old user_pswd if setup was edited
	[ -n "$user_pswd" ] && [ "$user_message_type" = 'smtp_isp_nopswd' ] && 	sed -i "1,/user_pswd=.*/{s/user_pswd=.*/user_pswd=''/;}" "$script_name_full"
	# if old intervals exist but message count change to 1, reset intervals
	if [ -n "$user_message_interval_1" ] || [ -n "$user_message_interval_2" ] || [ -n "$user_message_interval_3" ] ; then
		if [ "$user_message_count" = '1' ] ; then
			sed -i "1,/user_message_interval_1=.*/{s/user_message_interval_1=.*/user_message_interval_1=''/;}" "$script_name_full"
			sed -i "1,/user_message_interval_2=.*/{s/user_message_interval_2=.*/user_message_interval_2=''/;}" "$script_name_full"
			sed -i "1,/user_message_interval_3=.*/{s/user_message_interval_3=.*/user_message_interval_3=''/;}" "$script_name_full"
		fi
	fi

	# only if someone manually deletes saved WAN IP
	[ -z "$saved_wan_ip" ] && F_saved_wan_ip_create

	# incase ran reset count but didnt rerun setup, or reloading a backup config
	if [ -z "$created_date" ]; then
		created_on="$(date +%c)" && sed -i "1,/created_date=.*/{s/created_date=.*/created_date='$created_on'/;}" "$script_name_full"
		created_date="$created_on"   # for terminal show
	fi

	if [ "$settings_test" = 'OK' ]; then
		return 0
	else
		return 1
	fi
} ### settings_test


# ------------------- END OF MAIN FUNCTIONS ---------------------------------------------------------------------------

# ------------------- TERMINAL MESSAGES -------------------------------------------------------------------------------

F_terminal_header() {
	clear
	sed -n '2,10p' "$0"
	printf "%5s%b%s%b -- %bver: %s%b -- %b%s%b FW ver: %b%s.%s_%s%b\n\n" "" "$tGRN" "$run_date" "$tCLR" "$tYEL" "$script_version" "$tCLR" "$tGRN" "$device_model" "$tCLR" "$tGRN" "$build_no" "$build_sub" "$build_extend" "$tCLR"
	[ "$test_mode_active" = 'yes' ] && printf "%b %b###  Test Mode - Sending $user_message_count message(s) ### %b\n" "$tTERMHASH" "$tYEL" "$tCLR" && F_terminal_padding
} ### terminal_header

F_start_message() {
	F_terminal_header
	[ "$building_settings" = 'yes' ] && F_terminal_show "Welcome to the WICENS setup" && F_terminal_padding
	printf "%b Current saved WAN IP             :  %b%s%b\n" "$tTERMHASH" "$tGRN" "$saved_wan_ip" "$tCLR"
	F_terminal_header_print "Current Email send to address    : " "$user_send_to_addr"
	[ -n "$user_send_to_cc" ] && F_terminal_header_print "Current Email send to CC address : " "$user_send_to_cc"
	F_terminal_header_print "Current Email server addr:port   : " "$user_smtp_server"
	F_terminal_header_print "Current Email send format type   : " "$user_message_type"
	F_terminal_header_print "Current Email send from address  : " "$user_from_addr"
	F_terminal_header_print "Current Email message from name  : " "$user_from_name"
	F_terminal_header_print "Total # Email notifications set  : " "$user_message_count"
	[ "$user_message_count" -gt 1 ] 2>/dev/null && F_terminal_header_print "Interval between Email 1/2       : " "$user_message_interval_1"
	[ "$user_message_count" -gt 2 ] 2>/dev/null && F_terminal_header_print "Interval between Email 2/3       : " "$user_message_interval_2"
	[ "$user_message_count" -gt 3 ] 2>/dev/null && F_terminal_header_print "Interval between Email 3/4       : " "$user_message_interval_3"
	F_terminal_header_print "Cron run interval                : " "$user_cron_period $user_cron_interval"
	if [ -n "$user_custom_subject" ]; then
		user_custom_subject_show="$user_custom_subject_decoded"
		[ ${#user_custom_subject} -gt 31 ] && user_custom_subject_show=$(echo "$user_custom_subject_decoded" | cut -c -28 | sed 's/$/.../g')
		F_terminal_header_print "Custom Subject line set          : " "$user_custom_subject_show"
	fi
	if [ -n "$user_custom_text" ]; then
		user_custom_text_show="$user_custom_text_decoded"
		[ ${#user_custom_text} -gt 31 ] && user_custom_text_show=$(echo "$user_custom_text_decoded" | cut -c -28 | sed 's/$/.../g')
		F_terminal_header_print "Custom message text is set       : " "$user_custom_text_show"
	fi
	F_terminal_header_print "Number of cron calls             : " "$cron_run_count"
	F_terminal_header_print "Number of wan-event calls        : " "$wancall_run_count"
	[ -n "$last_cron_run" ] && F_terminal_header_print "Last ran with cron               : " "$last_cron_run"
	[ -n "$last_wancall_run" ] && F_terminal_header_print "Last ran with wan-event          : " "$last_wancall_run"
	F_terminal_header_print "Last IP change                   : " "$last_ip_change"
	F_terminal_header_print "Script installed on              : " "$created_date"
	F_terminal_show '---------------------------------------------------------------------'
} ### start_message

F_menu_exit() {
	F_terminal_padding
	printf "%b Any key to return to main menu, E to exit" "$tCHECK"
	read -rsn1 exitwait
	case "$exitwait" in
		e|E) F_terminal_check_ok "Exiting."
		     F_clean_exit ;;
		*) [ -f "/tmp/wicens.lock" ] && rm -f /tmp/wicens.lock ;exec sh "$script_name_full" ;;
	esac
} ### menu_exit

F_main_menu() {
	from_menu='yes'
	F_terminal_header
	printf  "       Auto Run                             Status \n" ;F_terminal_separator
	printf "%b Cron(cru) status-------------:       " "$tTERMHASH"
	cru l | grep -q 'wicens' && printf "%bActive%b\n" "$tGRN" "$tCLR" || printf "%bDisabled%b\n" "$tRED" "$tCLR"
	printf "%b services-start status--------:       " "$tTERMHASH"
	grep -q "$script_name cron" 2> /dev/null '/jffs/scripts/services-start' && printf "%bActive%b\n" "$tGRN" "$tCLR" || printf "%bDisabled%b\n" "$tRED" "$tCLR"
	printf "%b wan-event connected status---:       " "$tTERMHASH"
	grep -q "$script_name wancall" 2> /dev/null '/jffs/scripts/wan-event' && printf "%bActive%b\n" "$tGRN" "$tCLR" || printf "%bDisabled%b\n" "$tRED" "$tCLR"
	F_terminal_separator; printf "       Option                      Select   Status \n" ;F_terminal_separator

	if F_settings_test ; then
		printf "%b Run/enable script------------: m%b     Ready%b\n" "$tTERMHASH" "$tGRN" "$tCLR"
		printf "%b Create/edit settings---------: 1%b     Exists%b\n" "$tTERMHASH" "$tGRN" "$tCLR"
	else
		printf "%b Create/edit settings---------: 1%b     No settings exist%b\n" "$tTERMHASH" "$tRED" "$tCLR"
	fi
	printf "%b Custom Email msg text--------: 2" "$tTERMHASH" ;[ -n "$user_custom_text" ] && printf "%b     Exists%b\n" "$tGRN" "$tCLR" || printf "%b     Unused%b\n" "$tPUR" "$tCLR"
	printf "%b Custom Email msg subject-----: 3" "$tTERMHASH" ;[ -n "$user_custom_subject" ] && printf "%b     Exists%b\n" "$tGRN" "$tCLR" || printf "%b     Unused%b\n" "$tPUR" "$tCLR"
	printf "%b Custom script execution------: s" "$tTERMHASH" ;[ -n "$user_custom_script" ] && printf "%b     Exists%b   -   Action:%b %s%b \n" "$tGRN" "$tCLR" "$tGRN" "$user_script_call_time" "$tCLR" || printf "%b     Unused%b\n" "$tPUR" "$tCLR"
	F_terminal_separator ;F_terminal_show "Show sample Email------------: 4"
	F_terminal_show "Send a test Email------------: 5"
	F_terminal_show "Show Email send log----------: 6"
	F_terminal_show "Reset cron/wan-even counts---: 7"
	F_terminal_show "Email password entry menu----: p"
	F_terminal_show "Reset script to default------: r"
	F_terminal_show "Disable script---------------: d"
	F_terminal_show "Toggle terminal color on/off-: c"
	F_terminal_show "Uninstall script-------------: u"
	F_terminal_show "Backup/Restore settings menu-: b"
	F_terminal_show "About script-----------------: a"
	F_terminal_show "Exit-------------------------: e"
	F_terminal_padding ;F_terminal_check "Selection : " ;read -r "selection"
	printf "%b" "$tBACK$tERASE"
	case "$selection" in
		1) F_lock_create && F_build_settings ;;
		2) until F_opt_custom ; do : ; done ;F_menu_exit ;;
		3) until F_opt_subject ; do : ; done ;F_menu_exit ;;
		s) until F_opt_script ; do : ; done ;F_menu_exit ;;
		4) F_opt_sample ;;
		5) passed_options='test' ;;   #  fall through to settings test then check arg
		6) F_opt_error ;;
		7) F_lock_create && F_opt_count ;;
		a|A) F_opt_about ;;
		b|B) F_opt_backup_restore ;;
		c|C) F_opt_color ;;
		d|D) F_lock_create && F_opt_disable ;;
		e|E) F_clean_exit ;;
		m|M) ;;
		p|P) until F_opt_pswd ; do : ; done ; F_menu_exit ;;
		r|R) F_lock_create && F_opt_reset ;;
		u|U) F_lock_create && F_opt_uninstall ;;   # create lock to block any potential cron runs while uninstall, uses reset to clear first
		*) [ -n "$selection" ] && printf "%b %s is an invalid entry, any key to retry" "$tCHECKFAIL" "$selection" && read -rsn1 invalidwait ;return 1 ;;
	esac
}   ### main menu

F_lock_create() {
	touch "/tmp/wicens.lock"
	{
	echo "wicens lock file"
	echo "$$"
	date +%s
	echo "Lockfile for $script_name_full to prevent duplication"
	echo "Created $run_date"
	echo "Option : $passed_options "
	} >> /tmp/wicens.lock
} ### lock_create

# ------------- END OF FUNCTIONS --------------------------------------------------------------------------------------
# ------------- LOCK CHECK - SETTINGS CHECK - LOCK CREATE - RUN -------------------------------------------------------

# early check options
[ "$1" = 'remove' ] && F_opt_remove   # manual remove lock file
[ "$1" = '' ] && passed_options='manual'    # used in lock file and log to show manual vs cron vs wancall run

# lock check
if [ -f "/tmp/wicens.lock" ]; then
	locked_process=$(sed -n '2p' /tmp/wicens.lock)   # pid
	process_created=$(sed -n '5p' /tmp/wicens.lock)   # started on
	process_calledby=$(sed -n '6p' /tmp/wicens.lock)   # created by
	process_time=$(sed -n '3p' /tmp/wicens.lock)   # started seconds time
	lock1_diff_time=$(($(date +%s) - process_time))
	F_terminal_header
	F_terminal_show "wicens failed to start"
	F_terminal_padding

	if [ -f "/tmp/wicenssendmail.lock" ]; then   # if wicens.lock doesnt exist neither should this, so only check this if first lock exists

		# calculate wicenssendmail.lock age limit
		loop_count_run=3		# check user_message_intervals and convert to seconds to check lock file age limits
		while [ "$loop_count_run" != '0' ]; do
			newval=$(eval 'echo "${user_message_interval_'"$loop_count_run"'}"')   # reading variable user_message_interval_1/2/3
			interval_type=$(echo "$newval" | sed -e "s/^.*\(.\)$/\1/")	# strip second,minute,hour,day
			time_period=$(echo "$newval" | sed 's/[a-z]$//')	# strip time value

			if [ "$interval_type" = 'd' ]; then
				time_factor='86400'
			elif [ "$interval_type" = 'h' ]; then
				time_factor='3600'
			elif [ "$interval_type" = 'm' ]; then
				time_factor='60'
			else
				time_factor='1'
			fi

			converted_seconds=$((time_period * time_factor))

			if [ "$loop_count_run" = '3' ]; then
				interval_time_count_3="$converted_seconds"
			elif [ "$loop_count_run" = '2' ]; then
				interval_time_count_2="$converted_seconds"
			elif [ "$loop_count_run" = '1' ]; then
				interval_time_count_1="$converted_seconds"
			fi
			loop_count_run=$((loop_count_run - 1))
		done

		check_lock_count=$((interval_time_count_1+interval_time_count_2+interval_time_count_3+100))  # add 100secs just incase script happens to be exiting or had start delays reads original wicens.lock start date seconds
		if [ "$(($(date +%s) - $(sed -n '4p' /tmp/wicenssendmail.lock)))" -gt "$check_lock_count" ]; then
			rm -f "/tmp/wicenssendmail.lock"
			printf "%b from %s on %s\n" "$tTERMHASH" "$process_calledby" "$process_created"
			F_terminal_show "Removed stale wicenssendmail.lock file, any key to continue"
			F_log_this "NOTICE - Removed stale wicenssendmail.lock file started by $process_calledby on $process_created"
			[ "$passed_options" = 'manual' ] && read -rsn1 "staleremove"

		else
			if [ ! -d "/proc/$locked_process" ]; then # process that created doesnt exist
				F_log_and_show "CRITICAL ERROR - wicens.lock and wicenssendmail.lock exist"
				F_log_this "CRITICAL ERROR - files $process_created by $process_calledby"
				printf "%b created %s by %s\n" "$tTERMHASH" "$process_created" "$process_calledby"
				F_log_and_show "Process that created doesn't exist, script was killed during Email send"
				rm -f "/tmp/wicens.lock"
				rm -f "/tmp/wicenssendmail.lock"
				F_log_and_show "CRITICAL ERROR - Removed dead wicens.lock and wicenssendmail.lock files"
				[ "$passed_options" = 'manual' ] && F_terminal_check "Any key to continue" && read -rsn1 "staleremove"

			else
				F_terminal_show "wicens.lock and wicenssendmail.lock exist"
				F_terminal_show "Lock files not over age limit"
				F_terminal_show "Process still exists, likely sending Email notifcations."
				F_terminal_show "Lock file $process_created"
				F_terminal_show "Use sh $script_name_full remove"
				F_terminal_show "To manually remove lock files and kill running processes" ;F_terminal_padding
				[ "$passed_options" = 'manual' ] && F_log_this "wicens.lock and wicenssendmail.lock exist, lock files not over age limit, process still exists, likely sending Email notifcations."
				exit 0
			fi
		fi

	else
		F_terminal_show "/tmp/wicenssendmail.lock doesnt exist but wicens.lock does"
	fi    # done checking wicenssendmail.lock

	if [ ! -d "/proc/$locked_process" ]; then   # process that created doesnt exist
			F_terminal_show "NOTICE - Removed stale wicens.lock file, process doesn't exist"
			F_log_this "NOTICE - Process doesn't exist - Removed stale wicens.lock file, $process_calledby and started $process_created"
			rm -f "/tmp/wicens.lock"
			F_terminal_padding ;F_terminal_show "Any key to start script"
			[ "$passed_options" = 'manual' ] && read -rsn1 "lock_notify_wait"

	else
		if [ "$lock1_diff_time" -gt 330 ]; then   # based on if internet is down google attempts is 5 mins
			F_terminal_show "Lock file exists for running process older than 5 mins but not sending Email"
			printf "%b Killing process %s and deleting lock file %s" "$tTERMHASH" "$locked_process" "$process_created"
			F_log_this "Killing old process $locked_process started by $process_calledby and deleting lock file $process_created"
			kill "$locked_process"
			rm -f "/tmp/wicens.lock"
			F_log_and_show "Done, killed stale process, removed lock file"
			F_terminal_padding ;F_terminal_show "Any key to start script"
			[ "$passed_options" = 'manual' ] && read -rsn1 "lock_notify_wait"

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

F_lock_create			# v1.10  moved, locked before ntp check

# ntp time wait
if [ "$(nvram get ntp_ready)" -eq 0 ] ; then			# v1.10
	ntp_wait_time=0
	while [ "$(nvram get ntp_ready)" -eq 0 ] && [ "$ntp_wait_time" -lt 300 ] ; do
		ntp_wait_time="$((ntp_wait_time + 1))"
		if [ "$ntp_wait_time" -eq 120 ]; then
			F_log_and_show "Waiting for NTP to sync, 2 mins have passed, waiting 3 more mins"
		fi
		sleep 1
	done
	if [ "$ntp_wait_time" -ge 300 ] ; then
		F_log_and_show "NTP failed to sync and update router time after 5 mins"
		F_log_and_show "Please check your NTP date/time settings"
		F_clean_exit
	fi
fi

run_date=$(date +%c)			# v1.10  moved from global
run_epoch=$(date +%s)			# v1.10  moved from global

# check args start run
case "$1" in
	'cron'|'wancall'|'test') ;;
	'') until F_main_menu ; do : ; done ;;
	*) printf "\n%b %s is an invalid option\n" "$tTERMHASH" "$1" && F_clean_exit ;;
esac

# check settings exist
if ! F_settings_test; then  # check after arguments (dont move up)
	if [ "$from_menu" = 'yes' ] ; then
		F_terminal_header
		F_terminal_check_fail "Error, no Email config found in this script"
		F_menu_exit
	else
		[ "$passed_options" != 'manual' ] && F_log_this "CRITICAL ERROR, no/incorrect Email config found in this script"
		[ "$passed_options" != 'manual' ] && F_log_this "run $script_name_full to add a config to this script"
		F_clean_exit
	fi
fi

# ---------------  CONFIGURED SCRIPT  RUN START BELOW  ----------------------------------------------------------------

[ -f "/tmp/wicensmail.txt" ] && rm -f "/tmp/wicensmail.txt"   # if email message still exists somehow, cleanup
[ -f "/tmp/wicenssendmail.lock" ] && rm -f "/tmp/wicenssendmail.lock"   # if mail lock exists somehow, cleanup

# user_pswd for script to use
[ -n "$user_pswd" ] && user_pswd=$(echo "$user_pswd" | openssl enc -md sha512 -pbkdf2 -aes-256-cbc -d -a -pass pass:"$(nvram get boardnum | sed 's/://g')" )

# F_lock_create   # lock script no duplication			v1.10 moved up

# test mode after settings test and pswd conversion
[ "$passed_options" = 'test' ] && F_opt_test

if [ "$1" = 'cron' ]; then
	new_cron_count="$((cron_run_count + 1))"
	sed -i "1,/cron_run_count=.*/{s/cron_run_count=.*/cron_run_count=$new_cron_count/;}" "$script_name_full"
	sed -i "1,/last_cron_run=.*/{s/last_cron_run=.*/last_cron_run='$run_date'/;}" "$script_name_full"

	# below is all Sunday logging
	log_cron_msg=0
	weekly_cron_total=$((cron_run_count - last_cron_log_count))  # log msg count
	weekly_wancall_total=$((wancall_run_count - last_wancall_log_count))   # log msg count

	if [ "$(date +%u)" = '7' ] && [ "$log_cron_msg" = '0' ]; then
		F_log_this "Started successfully with cron $weekly_cron_total times in the last week"
		F_log_this "Ran $cron_run_count times since install with cron at $user_cron_period $user_cron_interval intervals"
		F_log_this "Started successfully by wan-event connected $weekly_wancall_total times in the last week, $wancall_run_count times since install"
		[ -n "$last_Wancall_run" ] && F_log_this "Last wan-event connected trigger $last_wancall_run"
		sed -i "1,/log_cron_msg=.*/{s/log_cron_msg=.*/log_cron_msg=1/;}" "$script_name_full"  # ensure we only write to log once
		sed -i "1,/last_cron_log_count=.*/{s/last_cron_log_count=.*/last_cron_log_count=$cron_run_count/;}" "$script_name_full"   # write current total
		sed -i "1,/last_wancall_log_count=.*/{s/last_wancall_log_count=.*/last_wancall_log_count=$wancall_run_count/;}" "$script_name_full"
	fi

	if [ "$(date +%u)" = '1' ] && [ "$log_cron_msg" = '1' ]; then
		sed -i "1,/log_cron_msg=.*/{s/log_cron_msg=.*/log_cron_msg=0/;}" "$script_name_full"  # monday reset to log again sunday
	fi
	# end of Sunday logging
fi

if [ "$1" = 'wancall' ]; then
	new_wancall_count="$((wancall_run_count + 1))"
	F_log_this "Started by 'wan-event connected' trigger"   #, sleeping 90s, wait for WAN DHCP/NTP to catch up"			v1.10 rewrite
#	sleep 90   # wait for dhcp/ntp on reboot to catch up			v1.10 disabled
#	run_date="$(date +%c)"   # date could be May 4/5 Dec 31 etc in $run_date on reboot wan-event connect, above sleep should correct			#v1.10 disabled
	sed -i "1,/wancall_run_count=.*/{s/wancall_run_count=.*/wancall_run_count=$new_wancall_count/;}" "$script_name_full"
	sed -i "1,/last_wancall_run=.*/{s/last_wancall_run=.*/last_wancall_run='$run_date'/;}" "$script_name_full"
fi

F_start_message   # terminal display
F_auto_run_check   # cron/wan-event/services-start check
internet_check_count=0   # set checks to 0, +1 in F_internet_check (max 10)
until F_internet_check ; do : ; done   # monitors/runs F_google_ping (attempts 5mins/30s interval)
F_current_wan_ip_get   # runs getrealip.sh to retrieve true wan ip

# compare, exit or send mail/update
printf "\r%b getrealip.sh result : Current WAN IP is %b%s%b \n" "$tERASE$tCHECKOK" "$tGRN" "$current_wan_ip" "$tCLR"
if [ "$current_wan_ip" = "$saved_wan_ip" ]; then
	printf "%b WAN IP compare      : Match - Current saved WAN IP %b%s%b\n" "$tCHECKOK" "$tGRN" "$saved_wan_ip" "$tCLR"
	if [ "$from_menu" = 'yes' ] ; then
		F_menu_exit
	else
		F_clean_exit
	fi

else
	printf "%b WAN IP compare      : No Match - Current saved WAN IP %b%s%b \n" "$tERASE$tCHECKFAIL" "$tPUR" "$saved_wan_ip" "$tCLR"
	F_log_this "WAN IP has changed to $current_wan_ip "
	ip_match='no'
	# user_custom_script 'immediate' call
	if [ -n "$user_custom_script" ] && [ "$user_custom_script_w" = 'i' ] && [ "$passed_options" != 'test' ] ; then
		(nohup sh "$user_custom_script_decoded" >/dev/null 2>&1) & custom_script_pid=$!			# v1.11
		F_log_this "Executed custom script $user_custom_script_decoded and put in background with PID $custom_script_pid"
		F_terminal_check_ok "Started user custom script and put in background"
	fi
	F_send_mail
fi
# END -----------------------------------------------------------------------------------------------------------------
