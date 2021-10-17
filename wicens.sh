#!/bin/sh
############################################################################
#                               _                                          #
#                    _      __ (_)_____ ___   ____   _____                 #
#                   | | /| / // // ___// _ \ / __ \ / ___/                 #
#                   | |/ |/ // // /__ /  __// / / /(__  )                  #
#                   |__/|__//_/ \___/ \___//_/ /_//____/                   #
#                                                                          #
#                 'WAN IP Change Email Notification Script'                #
#                                                                          #
############################################################################
# Thanks to all who contribute(d) at SNBforums, pieces of your code are here ;)
# shellcheck disable=SC3045,SC2034,SC3003   # disable notices about posix compliant -s   reads unused vars   backspace in pswd check
# written by maverickcdn Oct 2021
# github.com/maverickcdn/wicens
# modified firmware checks to allow LTS Fork by john9527 March 2021 (special thanks to john9527 @ snbforums for adding compatibility for getrealip.sh)
# SNBforums thread https://www.snbforums.com/threads/wicens-wan-ip-change-email-notification-script.69294/

# START ###########################################################################################
script_version='2.00'
script_ver_date='October 16 2021'
script_name="$(basename "$0")"
script_name_full="/jffs/scripts/$script_name"  # "/jffs/scripts/$(basename $0)"
script_dir='/jffs/addons/wicens'
script_git_src='https://raw.githubusercontent.com/maverickcdn/wicens/master/wicens.sh'
mail_file='/tmp/wicens_email.txt'   # temp file for mail text
mail_log="${script_dir}/wicens_email.log"   # log file for sendmail/curl
config_src="${script_dir}/wicens_user_config.wic"   # user settings
script_backup_file="${script_dir}/wicens_user_config.bak"   # user settings backup src
update_src="${script_dir}/wicens_update_conf.wic"   # update info
update_check_period=900   # only re-check for update after 15 mins
[ ! -d "$script_dir" ] && mkdir "$script_dir"
[ "$1" = 'debug' ] && shift && set -x

# script misc #####################################################################################
if grep -q $'\x0D' "$script_name_full" ; then dos2unix "$script_name_full" && exec sh "$script_name_full" ; fi   # CRLF
[ ! -x "$script_name_full" ] && chmod a+rx "$script_name_full"   # incase script was installed but not made exec for cron
F_ctrlc_clean() { printf "\n\n%b Script interrupted...\n" "$tTERMHASH" ; F_clean_exit ;}   # CTRL+C catch with trap
trap F_ctrlc_clean INT   # trap ctrl+c exit clean
passed_options="$1" ; [ "$1" = '' ] && passed_options='manual'   # used to show manual vs cron vs wancall run
pulled_device_name="$(nvram get lan_hostname)"
pulled_lan_name="$(nvram get lan_domain)"
[ -z "$(nvram get odmpid)" ] && device_model="$(nvram get productid)" || device_model="$(nvram get odmpid)"
# vars from user config below #####################################################################
[ -f "$config_src" ] && . "$config_src"
[ -f "$update_src" ] && . "$update_src"
[ -z "$saved_wan_epoch" ] && saved_wan_epoch="$(/bin/date +%s)"
user_custom_subject_decoded="$(echo "$user_custom_subject" | openssl base64 -d)"
user_custom_text_decoded="$(echo "$user_custom_text" | openssl base64 -d)"
user_custom_script_decoded="$(echo "$user_custom_script" | openssl base64 -d)"
if [ -n "$user_custom_script_time" ] ; then
	[ "$user_custom_script_time" = 'i' ] && user_script_call_time='immediate' || user_script_call_time='wait'
fi
ip_regex='([0-9]{1,3}[\.]){3}[0-9]{1,3}'
current_wan_ip=''
original_wan_ip="$(grep 'saved_wan_ip' 2>/dev/null < "$config_src" | grep -Eo "$ip_regex")"
original_wan_date="$(grep 'saved_wan_date' 2>/dev/null < "$config_src" | cut -d'=' -f2 | tr -d "'")"
original_wan_epoch="$(grep 'saved_wan_epoch' 2>/dev/null < "$config_src" | cut -d'=' -f2 | tr -d "'")"
cred_loc="${script_dir}/.wicens_cred.enc"

# terminal colors #################################################################################
tGRN="\033[1;32m" ;tRED="\033[1;31m" ;tPUR="\033[1;95m" ;tYEL="\033[1;93m" ;tCLR="\033[0m" ;tERASE="\033[2K" ;tBACK="\033[1A"
[ "$opt_color" = 'no' ] && tGRN='' && tRED='' && tPUR='' && tYEL='' && tCLR=''
tCHECK="[${tYEL}WAIT${tCLR}]" ;tCHECKOK="[${tGRN} OK${tCLR} ]" ;tCHECKFAIL="[${tRED}FAIL${tCLR}]" ;tTERMHASH="[${tPUR}-##-${tCLR}]"

# terminal/logging functions ######################################################################
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
F_log() { printf "%s : %s" "$passed_options" "$1" | logger -t "wicens[$$]" ;}
F_log_show() { F_log "$1" ; F_terminal_show "$1" ;}
F_log_terminal_ok() { F_terminal_check_ok "$1" ; F_log "$1" ;}
F_log_terminal_fail() { F_terminal_check_fail "$1" ; F_log "$1" ;}
# firmware check ##################################################################################
build_no="$(nvram get buildno | cut -f1 -d '.')"
build_sub="$(nvram get buildno | cut -f2 -d '.')"
build_extend="$(nvram get extendno)"
[ "$build_no" = '374' ] && extend_no=${build_extend:0:2} || extend_no=0
if [ "$build_no" != '386' ] || [ "$build_no" = '384' ] && [ "$build_sub" -lt 15 ] || [ "$build_no" = '374' ] && [ "$extend_no" -lt 48 ]; then
	F_terminal_header
	F_terminal_check_fail "Sorry this version of firmware is not compatible, please update to 384.15 or newer, or 374 LTS release 48 or newer to utilize this script"
	F_terminal_padding
	exit 0
fi

# alias ###########################################################################################
if [ ! -f '/jffs/configs/profile.add' ] ; then
	echo "alias wicens=\"sh ${script_name_full}\"   # added by wicens" > /jffs/configs/profile.add
elif ! grep -q "alias wicens=" '/jffs/configs/profile.add' ; then
	echo "alias wicens=\"sh ${script_name_full}\"   # added by wicens" >> /jffs/configs/profile.add
fi

# empty user_name #################################################################################
if [ -z "$user_from_name" ] ; then   # tries to auto generate a from name on first run
	if [ -n "$pulled_device_name" ] && [ -n "$pulled_lan_name" ] ; then
		user_from_name="${pulled_device_name}.${pulled_lan_name}"
	else
		user_from_name="$device_model"
	fi
fi

# MENU OPTIONS ####################################################################################

F_opt_about() {
	clear
	{   # start of | more
	printf "	WICENS - WAN IP Change Email Notification Script. \n\n"

	printf "This script when configured will send an Email (1-4) at variable intervals \n"
	printf "X(second/minute/hour/day) to your Email(s) notifying you when your WAN IP  \n"
	printf "has changed.  \n\n"

	printf "Supports GMail, Hotmail, Outlook, ISP based Email\n\n"

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
	printf "script.  Your Email password is encrypted and saved to router storage.     \n"
	printf "If you dont practice good security habits around your router ssh access,   \n"
	printf "this script might not be for you. \n\n"

	printf "Script compares IP in NVRAM to saved IP with wancall connected events and  \n"
	printf "cron, cron is also a watchdog and monitors for failed Email attempts.      \n"
	printf "Should NVRAM IP be unavailable for whatever reason script will use         \n"
	printf "firmware built in getrealip.sh to retrieve your WAN IP using Google STUN   \n"
	printf "server.                                                                  \n\n"
	
	printf "Script will display a notification if an update is available.            \n\n"

	printf "All cron/wan-event entries are automatically created with this script    \n\n"

	printf "NTP sync must occur to update router date/time for proper script function\n\n"

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

	printf "Every Sunday the script will log the number of calls from wan-event.     \n\n"

	printf "Thank you for using this script. \n\n"
	} | more
	F_menu_exit
} ### about

F_opt_backup_restore() {
	F_backup() {
		if [ -f "$script_backup_file" ] ; then
			while true; do
				F_terminal_warning ; F_terminal_padding
				F_terminal_show "Backup file exists, Y to overwrite, any key to return to Main Menu"
				read -rsn1 configremove
				case $configremove in
					y|Y) rm -f "$script_backup_file" ; [ -f "${script_dir}/.wicens_cred.bak" ] && rm -f "${script_dir}/.wicens_cred.bak" ; printf "%b" "$tBACK$tERASE" ;;
					*) F_clean_exit reload;;
				esac
				break
			done
		fi
		F_terminal_check "Starting backup"
		if cp "$config_src" "$script_backup_file" ; then
			if [ -f "$cred_loc" ] ; then
				if ! cp "$cred_loc" "${script_dir}/.wicens_cred.bak" ; then
					F_terminal_check_fail "Critical error, could not backup saved pswd"
					F_clean_exit
				else
					F_terminal_check_ok "Success backing up password"
				fi
			fi
			sed -i "1,/created_date=.*/{s/created_date=.*/created_date=''/;}" "$script_backup_file"   # reset install date
			F_terminal_check_ok "Backup successful, saved to $script_backup_file"
			echo "# Backup created $(/bin/date)" >> "$script_backup_file"
		else
			F_terminal_check_fail "Critical error, backup failed, could not output to $script_backup_file"
		fi
		[ "$1" = 'resetbackup' ] && F_terminal_check "Any key to continue..." && read -rsn1 rstbakwait
	} # backup

	F_restore() {
		F_terminal_check "Restoring backup"
		if cp -f "$script_backup_file" "$config_src" ; then
			echo "# File restored from backup on $(/bin/date)" >> "$config_src"
			created_on="$(/bin/date +%c)"
			sed -i "1,/created_date=.*/{s/created_date=.*/created_date='$created_on'/;}" "$config_src"   # new install date
			source "$config_src"
			F_status
			F_terminal_padding ; F_terminal_check_ok "Done restoring backup settings to script"
			if [ "$user_message_type" != 'smtp_isp_nopswd' ] ; then
				if [ -f "${script_dir}/.wicens_cred.bak" ] ; then
					if cp -f "${script_dir}/.wicens_cred.bak" "$cred_loc" ; then
						F_terminal_check_ok "Pswd successfully restored"
					else	
						F_terminal_check_fail "Critical error, backed up pswd not restored"
					fi
				else
					F_terminal_check_fail "No backup pswd file found to restore, menu option p to re-add"
				fi
			fi
		else
			F_terminal_check_fail "Critical error copying backup to script"
		fi
	} # restore

	[ "$1" = 'resetbackup' ] && F_backup resetbackup && return 0   # from F_reset valid config incase want to save before reset
	F_terminal_header ; F_terminal_padding
	printf "%bBackup/Restore Settings Menu %b \n" "$tTERMHASH $tYEL" "$tCLR"  ; F_terminal_padding
	if ! F_settings_test && [ ! -f "$script_backup_file" ] ; then
		F_terminal_warning ; F_terminal_padding
		F_terminal_check_fail "Error invalid current settings and no backup found to restore"
		F_terminal_padding ; F_terminal_show "Use Menu option 1 to edit settings" ; F_terminal_padding
		F_menu_exit
	fi
	while true; do
		if [ -f "$script_backup_file" ] ; then
			F_terminal_check_ok "Backup found!   R to Restore Settings" ; F_terminal_padding
		else
			F_terminal_check_fail "No backup found for restore" ; F_terminal_padding
		fi
		if F_settings_test ; then
			F_terminal_check_ok "Valid config found!   B to Backup current config" ; F_terminal_padding
		else
			F_terminal_check_fail "No valid config found for backup, menu opt 1 to add a config" ; F_terminal_padding
		fi
		F_terminal_show "E to return to menu"
		F_terminal_padding ; F_terminal_check "Selection : "
		read -r bandrwait
		case $bandrwait in
			b|B) if ! F_settings_test ; then
					F_terminal_check_fail "Error, no valid config found to backup"
					F_terminal_padding ; F_terminal_check "Any key to return to main menu"
					read -rsn1 backupwait ; F_main_menu
				else
					printf '%b' "$tBACK$tERASE" ; F_terminal_check_ok "B selected for backup" ; F_backup ; F_menu_exit
				fi ;;
			r|R) if  [ -f "$script_backup_file" ] ; then
					printf '%b' "$tBACK$tERASE" ; F_terminal_check_ok "R selected for restore" ; F_restore ; F_menu_exit
				else
					printf '%b' "$tBACK$tERASE" ; F_terminal_check_fail "Invalid entry, no valid backup exists"
					read -rsn1 invalwait ; F_opt_backup_restore ; continue
				fi ;;
			e|E) F_main_menu ;;
			*) F_terminal_check_fail "Invalid entry, B or R - any key to retry, E return to Main Menu"
				read -rsn1 brinvalid
				case $brinvalid in
					e|E) F_clean_exit reload ;;
					*) F_opt_backup_restore ;;
				esac ;;
		esac
		break
	done
} # backup_restore

F_opt_color() {
	F_terminal_padding
	[ ! -f "$config_src" ] && F_default > "$config_src" && source "$config_src"   # if config file doesnt exist create
	if [ "$opt_color" = 'yes' ]; then
		F_terminal_check "Setting script to no color mode"
		sed -i "1,/opt_color=.*/{s/opt_color=.*/opt_color='no'/;}" "$config_src"
		F_terminal_check_ok "Done, wicens script set to no color mode"
	elif [ "$opt_color" = 'no' ]; then
		F_terminal_check "Setting script to color mode"
		sed -i "1,/opt_color=.*/{s/opt_color=.*/opt_color='yes'/;}" "$config_src"
		F_terminal_check_ok "Done, wicens script set to color mode"
	fi
	F_terminal_show "Return to Main Menu to view changes"
	F_menu_exit
} ### color

F_opt_count() {
	if [ ! -f "$config_src" ] ; then
		F_terminal_check_fail "No saved config file found to reset"
		F_menu_exit
	fi
	F_terminal_header
	F_terminal_header_print "Number of cron checks            : " "$cron_run_count"
	F_terminal_header_print "Number of wan-event checks       : " "$wancall_run_count"
	[ -n "$last_cron_run" ] && F_terminal_header_print "Last monitored with cron         : " "$last_cron_run"
	[ -n "$last_wancall_run" ] && F_terminal_header_print "Last ran with wan-event          : " "$last_wancall_run"
	F_terminal_header_print "Last IP change                   : " "$last_ip_change"
	F_terminal_header_print "IP changes recorded              : " "$ip_change_count"
	F_terminal_header_print "Script installed on              : " "$created_date"
	F_terminal_show '---------------------------------------------------------------------'
	F_terminal_padding
	F_terminal_warning
	F_terminal_show "This will remove cron call, wancall counts and install date"
	F_terminal_padding
	while true; do
		F_terminal_check "Are you sure you wish to reset? Y or N"
		read -rsn1 reset_wait
		case $reset_wait in
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
	F_terminal_header ; printf "%b %bCustom Text Entry Menu%b \n" "$tTERMHASH" "$tYEL" "$tCLR" ; F_terminal_padding
	F_ready_check options
	if [ -z "$user_custom_text" ] ; then
		F_terminal_show "Enter your line of custom plain text to add to the Email message(s)"
		F_terminal_show "eg.  Router hidden in moms closet, 2 vpn clients to update"
		F_terminal_show "Entry must be one line, can use \\n to create new line in Email msg"
		F_terminal_padding ; F_terminal_entry "Text : "
		read -r user_custom_text_entry
		F_terminal_padding
		# ensure we empty any saved vars if brought here by N new entry but left entry blank
		[ -z "$user_custom_text_entry" ] && sed -i "1,/user_custom_text=.*/{s/user_custom_text=.*/user_custom_text=''/;}" "$config_src" && return 0
		while true ; do
			printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$user_custom_text_entry" "$tCLR"
			read -rsn1 custyesorno
			case $custyesorno in
				y|Y) custom_text_encoded="$(echo "$user_custom_text_entry" | openssl base64 | tr -d '\n')"   # base64 no worries of sed conflicts
				if sed -i "1,/user_custom_text=.*/{s~user_custom_text=.*~user_custom_text='$custom_text_encoded'~;}" "$config_src" ; then
						F_terminal_check_ok "Done writing custom text to script" ; user_custom_text="$user_custom_text_entry"
					else
						F_terminal_check_fail "Error, sed failed writing custom text to script" ; F_clean_exit reload
					fi ;;
				n|N) return 1 ;;
				*) F_fail_entry ;;
			esac
			break
		done
	else
		F_terminal_show "Custom text already set :" ; F_terminal_padding
		F_terminal_show "$user_custom_text_decoded" ; F_terminal_padding
		while true ; do
			F_terminal_check "(Y)keep - (N)enter new - (R)remove current "
			read -rsn1 yesornowremove
			case $yesornowremove in
				y|Y) F_terminal_check_ok "Keeping currently saved custom text" ;;
				n|N) user_custom_text='' ; return 1 ;;
				r|R) if sed -i "1,/user_custom_text=.*/{s/user_custom_text=.*/user_custom_text=''/;}" "$config_src" ; then
						F_terminal_check_ok "Done, custom text cleared" ; user_custom_text=''
					else
						F_terminal_check_fail "Error, sed failed to reset custom text" ; F_clean_exit
					fi ;;
				*) F_terminal_check_fail "Invalid entry, Y/N/R - any to key to retry" ; read -rsn1 invalidwait ; printf "%b" "$tBACK$tERASE" ; continue ;;
			esac
			break
		done
	fi
} ### custom_text

F_opt_disable() {
	F_terminal_header ; F_terminal_warning ; F_terminal_show "This will remove all auto start entries in wan-event, cron, and"
	F_terminal_show "services-start. Saved Email settings and WAN IP will remain."
	F_terminal_show "You will not receive an Email notification if your WAN IP changes."
	F_terminal_show "Manually run script to reactivate auto starts" ;F_terminal_padding
	while true; do
		F_terminal_check "Are you sure you wish to disable? Y or N"
		read -rsn1 disable_wait
		case $disable_wait in
			y|Y) F_terminal_check_ok "Ok received, disabling..." ; F_disable_autorun ;;
			n|N) F_terminal_check_ok "No received, exiting..." ;;
			*) F_fail_entry ;;
		esac
		break
	done
	F_menu_exit
} ### disable

F_opt_error() {
	if [ -f "$mail_log" ]; then
		F_terminal_show "Contents of last Email send log : "
		cat "$mail_log" | more
		F_terminal_padding ; F_terminal_check_ok "End of contents." ; F_menu_exit
	else
		F_terminal_padding ; F_terminal_show "No log file found"
		F_menu_exit
	fi
} # error

F_opt_manual() {
	F_ready_check
	F_status
	F_auto_run_check
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
	if [ -f "$script_lock" ]; then
		process_id="$(sed -n '2p' "$script_lock")"   # pid
		process_created="$(sed -n '5p' "$script_lock")"   # started on
		if [ -d "/proc/$process_id" ]; then # process that created exist
			F_terminal_show "Process exists attached to lock file.... killing process"
			kill -9 "$process_id" 2> /dev/null
			printf "%b Killed process %s and deleting lock file %s" "$tERASE$tCHECKOK" "$process_id" "$process_created" ;F_terminal_padding
			F_log "Killed old process $process_id and deleting lock file $process_created"
		fi
		F_terminal_check "Removing lock file 1 of 2"
		rm -f "$script_lock"
		F_terminal_check_ok "Removed lock file 1 of 2 "
	else
		F_terminal_check_fail "1st lock file not present"
	fi
	F_terminal_check "Removing lock file 2 of 2"
	if [ -f "$script_mail_lock" ]; then
		rm -f "$script_mail_lock"
		F_terminal_check_ok "Removed lock file 2 of 2 "
		F_clean_exit
	else
		F_terminal_check_fail "2nd lock file not present"
		F_clean_exit
	fi
} ### remove

F_opt_reset() {
	if F_settings_test ; then
		F_terminal_header ; F_terminal_warning ; printf "%b %bScript reset menu%b \n" "$tTERMHASH" "$tYEL" "$tCLR" ; F_terminal_padding
		F_terminal_check_ok "Found valid config" ;F_terminal_padding
		F_terminal_show "You're about to reset, would you like to make a backup?" ; F_terminal_padding
		while true; do
			F_terminal_check "Hit b to create a backup, r to reset without backup, e to exit"
			read -rsn1 backup_wait
			case $backup_wait in
				b|B) F_terminal_header ; F_terminal_check_ok "Creating backup" ; (F_opt_backup_restore resetbackup) ;;
				r|R) break ;;
				e|E) F_main_menu ;;
				*) F_fail_entry ;;
			esac
			break
		done
	fi
	F_terminal_header ; F_terminal_warning ; printf "%b %bScript reset menu%b \n" "$tTERMHASH" "$tYEL" "$tCLR" ; F_terminal_padding
	F_terminal_show "This will remove all saved settings and records"
	F_terminal_show "And services-start/wan-event/cron entries" ; F_terminal_padding
	while true; do
		F_terminal_check "Are you sure you wish to reset? Y or N"
		read -rsn1 reset_wait
		case $reset_wait in
			y|Y) F_terminal_header ; F_terminal_check_ok "Ok received, resetting..." ;;
			n|N) F_terminal_check_ok "No received, exiting..." ; F_menu_exit ;;
			*) F_fail_entry ;;
		esac
		break
	done
	! F_reset_do && F_terminal_check_fail "Reset failed"
	! F_disable_autorun && F_terminal_check_fail "Auto run removal failed"
	[ -f "update_src" ] && rm -f "$update_src"
	F_terminal_padding ; F_terminal_check "Any key to continue" ; read -rsn1 donewait && F_clean_exit reload   # send fromreset to restart menu
} ### reset

F_opt_sample() {
	F_terminal_header ; F_terminal_show "Sample Email output:" ; F_terminal_padding
	current_wan_ip="x.x.x.x"   # fake for email
	passed_options='sample'   # for setup just fake running sample
	loop_run=1
	user_message_count=1
	test_mode_active="yes"
	F_email_message
	cat "$mail_file" ; F_terminal_padding
	rm -f "$mail_file"
	F_terminal_show "End of Email output"
	[ "$building_settings" != 'yes' ] && F_menu_exit
} ### sample

F_opt_script() {
	F_terminal_header ; printf "%b %bCustom Script Path Entry Menu%b \n" "$tTERMHASH" "$tYEL" "$tCLR" ; F_terminal_padding
	F_ready_check options
	if [ -z "$user_custom_script" ] ; then
		while true ; do
			F_terminal_show "Do you want your custom script to execute immediately on WAN IP"
			F_terminal_show "change detection, or wait till all Email messages configured"
			F_terminal_show "have finished sending" ; F_terminal_padding
			F_terminal_entry "w for wait    i for immediately : "
			read -rsn1 user_script_wait_entry
			case $user_script_wait_entry in
				w|W|I|i) if sed -i "1,/user_custom_script_time=.*/{s~user_custom_script_time=.*~user_custom_script_time='$user_script_wait_entry'~;}" "$config_src" ; then
						F_terminal_check_ok "Done writing custom script exec time to script" ; user_custom_script_time="$user_script_wait_entry"
						else
							F_terminal_check_fail "Error, sed failed writing custom script exec time to script" ; F_clean_exit
						fi ;;
				*) F_terminal_check_fail "Invalid entry, any key to retry" && read -rsn1 "invalidwait" && printf "%b" "$tBACK$tERASE$tBACK$tERASE$tBACK$tERASE$tBACK$tERASE$tBACK$tERASE" && continue ;;
			esac
			break
		done
		F_terminal_padding ; F_terminal_check "Any key to continue..." ; read -rsn1 waitscript
		F_terminal_header ; F_terminal_show "Custom Script Path Entry Menu" ; F_terminal_padding
		[ "$user_custom_script_time" = 'w' ] && custom_exec='wait' ; [ "$user_custom_script_time" = 'i' ] && custom_exec='immediate'
		printf "%b Script execution set to : %b \n" "$tTERMHASH" "$custom_exec" ; F_terminal_padding
		F_terminal_show "Enter the full path to your script"
		F_terminal_show "eg. /jffs/scripts/customscript.sh" ; F_terminal_padding
		F_terminal_entry "Path : "
		read -r user_custom_script_entry
		while true ; do
				F_terminal_padding
				printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$user_custom_script_entry" "$tCLR"
				read -rsn1 scriptyesorno
				case $scriptyesorno in
					y|Y) if [ ! -f "$user_custom_script_entry" ] ; then
							F_terminal_check_fail "Could not locate custom script"
							F_terminal_show "Any key to return to Main Menu"
							sed -i "1,/user_custom_script_time=.*/{s/user_custom_script_time=.*/user_custom_script_time=''/;}" "$config_src"
							read -rsn1 nofind
							F_clean_exit reload
						fi
						custom_script_encoded="$(echo "$user_custom_script_entry" | openssl base64 | tr -d '\n')"   # base64 no worries of sed conflicts
						if sed -i "1,/user_custom_script=.*/{s~user_custom_script=.*~user_custom_script='$custom_script_encoded'~;}" "$config_src" ; then
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
		F_terminal_show "Custom script path already set" ; F_terminal_padding
		F_terminal_show "$user_custom_script_decoded" ; F_terminal_padding
		while true ; do
			F_terminal_check "(Y)keep - (N)enter new - (R)remove current "
			read -rsn1 yesornowremove
			case $yesornowremove in
				y|Y) F_terminal_check_ok "Keeping currently saved custom script path" ;;
				n|N) user_custom_script='' ; return 1 ;;
				r|R) if sed -i "1,/user_custom_script=.*/{s/user_custom_script=.*/user_custom_script=''/;}" "$config_src" ; then
						sed -i "1,/user_custom_script_time=.*/{s/user_custom_script_time=.*/user_custom_script_time=''/;}" "$config_src"
						F_terminal_check_ok "Done, custom script path cleared" ; user_custom_script=''
					else
						F_terminal_check_fail "Error, sed failed to reset custom script path" ; F_clean_exit
					fi ;;
				*) F_terminal_check_fail "Invalid entry, Y/N/R - any to key to retry" ; read -rsn1 invalidwait ; printf "%b" "$tBACK$tERASE" ; continue ;;
			esac
			break
		done
	fi
} ### script

F_opt_subject() {
	F_terminal_header ; printf "%b %bCustom Subject Menu%b \n" "$tTERMHASH" "$tYEL" "$tCLR" ; F_terminal_padding
	F_ready_check options
	if [ -z "$user_custom_subject" ]; then
		F_terminal_show "Enter the text for a custom Subject line you wish to use"
		printf "%b Default Subject text is: %bWAN IP has changed on %s%b\n" "$tTERMHASH" "$tGRN" "$device_model" "$tCLR"
		F_terminal_padding ; F_terminal_show "If you wish to use the new or current WAN IP, add the var names"
		F_terminal_show "\$current_wan_ip and \$saved_wan_ip to your text (like shown)"
		F_terminal_show "Model of router var is \$device_model"
		F_terminal_padding ; F_terminal_entry "Subject: "
		read -r user_custom_subject_entry
		F_terminal_padding
		[ -z "$user_custom_subject_entry" ] && return 0
		while true; do
			printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$user_custom_subject_entry" "$tCLR"
			read -rsn1 subjectyesorno
			case $subjectyesorno in
				y|Y) custom_subject_encoded="$(echo "$user_custom_subject_entry" | openssl base64 | tr -d '\n')"
					if sed -i "1,/user_custom_subject=.*/{s~user_custom_subject=.*~user_custom_subject='$custom_subject_encoded'~;}" "$config_src" ; then
						user_custom_subject="$user_custom_subject_entry"
						F_terminal_check_ok "Done. user_custom_subject set to : $user_custom_subject_entry"
					else
						F_terminal_check_fail "Error, sed failed to write custom subject to script"
						F_clean_exit
					fi ;;
				n|N) return 1 ;;
				*) F_fail_entry ;;
			esac
			break
		done
	else
		F_terminal_show "Custom subject already set :" ; F_terminal_padding
		F_terminal_show "$user_custom_subject_decoded" ; F_terminal_padding
		while true; do
			F_terminal_check "(Y)keep - (N)enter new - (R)remove current "
			read -rsn1 yesornowremovesub
			case $yesornowremovesub in
				y|Y) F_terminal_check_ok "Keeping currently saved custom subject" ;;
				n|N) user_custom_subject=""
				     return 1 ;;
				r|R) if sed -i "1,/user_custom_subject=.*/{s/user_custom_subject=.*/user_custom_subject=''/;}" "$config_src" ; then
						F_terminal_check_ok "Custom subject cleared" ; user_custom_subject=
					else
						F_terminal_check_fail "Error, sed failed to clear custom subject" ; F_clean_exit
					fi ;;
				*) F_terminal_check_fail "Invalid entry, Y/N/R - any to key to retry" && read -rsn1 invalidwait && printf "%b" "$tBACK$tERASE" && continue ;;
			esac
			break
		done
	fi
} ### subject

F_opt_test() {
	test_mode_active="yes"
	F_ready_check
	user_message_count="1"
	F_log "Test mode started, sending test Email"
	current_wan_ip="x.x.x.x Test Mode"
	F_status
	printf "[%bFAIL%b] Current WAN IP is : %b%s%b --- %bNo Match%b\n" "$tRED" "$tCLR" "$tRED" "$current_wan_ip" "$tCLR" "$tRED" "$tCLR"
	F_send_mail   # return to menu or exit in F_send_mail
	test_mode_active=''   # reset for terminal header
} ### test

F_opt_uninstall() {
	F_uninstall_do() {
		if ! F_disable_autorun; then
			F_terminal_check_fail "Error, auto run removal failed"
			F_log "Error, auto run removal failed"
			F_log_show "Be sure to manually remove entries in"
			F_log_show "cru l using cru d command"
			F_log_show "/jffs/scripts/services-start wicens entry"
			F_log_show "/jffs/scripts/wan-event wicens entry"
		fi

		[ -f "$script_lock" ] && rm -f "$script_lock"
		[ -f "$script_mail_lock" ] && rm -f "$script_mail_lock"
		[ -f "$mail_log" ] && rm -f "$mail_log"
		[ -f "$mail_file" ] && rm -f "$mail_file"
		unalias wicens 2>/dev/null
		if [ -f "/jffs/configs/profile.add" ] ; then
			grep -q "alias wicens=$script_name_full" '/jffs/configs/profile.add' && sed -i "\| alias wicens=$script_name_full |d" '/jffs/configs/profile.add'
		fi
		[ ! -s '/jffs/configs/profile.add' ] && rm -f '/jffs/configs/profile.add'
		rm -r "$script_dir"
		rm -f "$script_name_full"
		F_terminal_check_ok "Done. Uninstalled" ; F_terminal_padding ; exit 0
	} # uninstall_do

	F_terminal_header ; F_terminal_warning ; F_terminal_show "This will remove the wicens script ENTIRELY from your system" 
	F_terminal_show "And any backup configs" ; F_terminal_padding
	while true; do
		F_terminal_check "Are you sure you wish to uninstall? Y or N"
		read -rsn1 uninstall_wait
		case $uninstall_wait in
			y|Y) F_terminal_check_ok "Uninstalling" ; F_terminal_padding ; F_uninstall_do ;;
			n|N) F_terminal_check_ok "No received, exiting..." ; F_menu_exit ;;
			*) F_fail_entry ;;
		esac
		break
	done
} ### uninstall


# BUILD USER SETTINGS FUNCTIONS ###################################################################

#requires being passed a line # for head to terminate on
F_terminal_entry_header() { F_status | head -n "$1" ; F_terminal_separator ; F_terminal_padding ;}

# all user entry functions called by until loops and return 1 for failed input and restart or return 0 with completed Y in while loop
F_send_to_addr() {
	F_terminal_entry_header 15
	F_terminal_show "Enter the Email address you wish to send notification Emails" ; F_terminal_show "to when your WAN IP changes"
	F_terminal_show "eg.  myrecipient@myemail.com"
	[ -n "$user_send_to_addr" ] && printf "%b Currently set to : %b%s%b \n" "$tTERMHASH" "$tGRN" "$user_send_to_addr" "$tCLR" && F_terminal_show "Leave entry blank to keep current"
	F_terminal_padding ;F_terminal_entry "Send to address : "
	read -r send_to_entry

	[ -z "$user_send_to_addr" ] && [ -z "$send_to_entry" ] && F_terminal_show "Error, Email send to address cannot be empty, any key to retry" && read -rsn1 waitsendto && return 1
	[ -z "$send_to_entry" ] && send_to_entry="$user_send_to_addr"
	F_terminal_padding
	while true; do   # loop for invalid entries
		printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$send_to_entry" "$tCLR"
		read -rsn1 addryesorno
		case $addryesorno in
			y|Y) [ ! -f "$config_src" ] && F_default > "$config_src" && chmod 0644 "$config_src"  # first run? create file
				sed -i "1,/user_send_to_addr=.*/{s/user_send_to_addr=.*/user_send_to_addr='$send_to_entry'/;}" "$config_src"
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
		printf "%b Second Email recipient already set to : %s \n\n" "$tTERMHASH" "$user_send_to_cc" ; F_terminal_padding
		while true; do
			F_terminal_check "(Y)keep (N)enter new (R)remove current & skip to server entry"   # for edits can remove 2nd email if wanted.
			read -rsn 1 ccmailwait2
			case $ccmailwait2 in
				y|Y) return 0 ;;
				n|N) user_send_to_cc="currently none" ; return 1 ;;
				r|R) sed -i "1,/user_send_to_cc=.*/{s/user_send_to_cc=.*/user_send_to_cc=''/;}" "$config_src" && user_send_to_cc="currently none" && return 0 ;;
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
		F_terminal_padding ; F_terminal_show "Leave entry blank to leave CC option blank and continue"
		F_terminal_padding ; F_terminal_entry "Send to CC address : "
		read -r send_to_cc_entry

		[ -z "$send_to_cc_entry" ] && return 0

		F_terminal_padding
		while true; do
			printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$send_to_cc_entry" "$tCLR"
			read -rsn1 ccyesorno in
			case $ccyesorno in
				y|Y) sed -i "1,/user_send_to_cc=.*/{s/user_send_to_cc=.*/user_send_to_cc='$send_to_cc_entry'/;}" "$config_src"
				     user_send_to_cc="$send_to_cc_entry" ;;
				n|N) user_send_to_cc= ; return 1 ;;
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
	F_terminal_padding ; F_terminal_entry "Server address/port : "
	read -r smtp_server_entry

	[ -z "$user_smtp_server" ] && [ -z "$smtp_server_entry" ] && F_terminal_show "Error, Server address cannot be empty, any key to retry" && read -rsn1 waitsmtpserv && return 1
	[ -z "$smtp_server_entry" ] && smtp_server_entry="$user_smtp_server"
	F_terminal_padding
	while true; do
		printf "%b Is %b%s%b correct? Y or N " "$tCHECK" "$tGRN" "$smtp_server_entry" "$tCLR"
		read -rsn1 smtpyesorno
		case $smtpyesorno in
			y|Y) sed -i "1,/user_smtp_server=.*/{s/user_smtp_server=.*/user_smtp_server='$smtp_server_entry'/;}" "$config_src"
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
	F_terminal_padding ; F_terminal_entry "Selection : "

	read -r send_type_entry
	case $send_type_entry in
		1|2|3|4|5) ;;
		"") if [ -n "$user_message_type" ]; then
				send_type_entry="$user_message_type"
			else
				F_terminal_check_fail "Invalid entry, 1,2,3,4,5 only - any key to retry" && read -rsn1 smtpinvalidwait && return 1
			fi ;;
		*) F_terminal_check_fail "Invalid Entry, 1,2,3,4,5 only - any key to retry" && read -rsn1 smtpinvalidwait && return 1 ;;
	esac

	F_terminal_padding
	while true; do
		printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$send_type_entry" "$tCLR"
		read -rsn1 smtptypeyesorno
		case $smtptypeyesorno in
			y|Y) ;;
			n|N) return 1 ;;
			*) F_fail_entry ;;
		esac
		break
	done

	[ "$send_type_entry" = "1" ] &&  sed -i "1,/user_message_type=.*/{s/user_message_type=.*/user_message_type='smtp_start_tls'/;}" "$config_src" && user_message_type="smtp_start_tls"
	[ "$send_type_entry" = "2" ] &&  sed -i "1,/user_message_type=.*/{s/user_message_type=.*/user_message_type='smtp_ssl'/;}" "$config_src" && user_message_type="smtp_ssl"
	[ "$send_type_entry" = "3" ] &&  sed -i "1,/user_message_type=.*/{s/user_message_type=.*/user_message_type='smtp_isp_nopswd'/;}" "$config_src" && user_message_type="smtp_isp_nopswd"
	[ "$send_type_entry" = "4" ] &&  sed -i "1,/user_message_type=.*/{s/user_message_type=.*/user_message_type='smtp_plain_auth'/;}" "$config_src" && user_message_type="smtp_plain_auth"
	[ "$send_type_entry" = "5" ] &&  sed -i "1,/user_message_type=.*/{s/user_message_type=.*/user_message_type='smtp_start_tls_v1'/;}" "$config_src" && user_message_type="smtp_start_tls_v1"

	if [ "$user_message_type" != 'smtp_isp_nopswd' ] && [ "$user_message_type" != 'smtp_plain_auth' ]; then
		F_terminal_padding ; F_terminal_padding
		F_terminal_show "If using GMail for your sending service"
		F_terminal_show "Insecure app access MUST be enabled in your GMail account settings"
		F_terminal_show "If you use 2-factor authentication"
		F_terminal_show "You must setup an app pswd for this script"
		F_terminal_show "Any key to continue" && read -rsn1 notify_wait
	fi
	return 0
} ### send_type

F_from_email_addr() {
	F_terminal_entry_header 19
	F_terminal_show "Enter the Email send from (login) address for your Email provider"
	F_terminal_show "eg.  myemail@myemailprovider.com"
	[ -n "$user_from_addr" ] && printf "%b Currently set to : %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_from_addr" "$tCLR" && F_terminal_show "Leave entry blank to keep current"
	F_terminal_padding ;F_terminal_entry "From Email addr : "
	read -r from_email_addr_entry

	[ -z "$user_from_addr" ] && [ -z "$from_email_addr_entry" ] && F_terminal_show "Error, from(login) address cannot be empty, any key to retry" && read -rsn1 waitfromemail && return 1
	[ -z "$from_email_addr_entry" ] && from_email_addr_entry="$user_from_addr"
	F_terminal_padding
	while true; do
		printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$from_email_addr_entry" "$tCLR"
		read -rsn1 fromyesorno
		case $fromyesorno in
			y|Y) sed -i "1,/user_from_addr=.*/{s/user_from_addr=.*/user_from_addr='$from_email_addr_entry'/;}" "$config_src"
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
	F_terminal_padding ; F_terminal_entry "Email from name : "
	read -r from_name_entry

	[ -z "$user_from_name" ] && [ -z "$from_name_entry" ] && F_terminal_show "Error, Script could not auto-fill from name, cannot be blank, any key to retry" && read -rsn1 waitfromname && return 1
	[ -z "$from_name_entry" ] && from_name_entry="$user_from_name"
	F_terminal_padding
	while true; do
		printf "%b Is %b%s%b correct? Y or N" "$tCHECK" "$tGRN" "$from_name_entry" "$tCLR"
		read -rsn1 nameyesorno
		case $nameyesorno in
			y|Y) sed -i "1,/user_from_name=.*/{s/user_from_name=.*/user_from_name='$from_name_entry'/;}" "$config_src"
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
	[ -f "$cred_loc" ] && F_terminal_padding && F_terminal_show "Saved password exists, leave blank to use saved"
	F_terminal_padding ; F_terminal_entry "Password  : "
	F_pswd_entry
	password_entry_1="$passwordentry"

	[ -f "$cred_loc" ] && [ -z "$passwordentry" ] && printf "%b" "$tBACK$tERASE" && F_terminal_check_ok "Keeping saved" && return 0   # keep saved password

	if [ ! -f "$cred_loc" ] && [ -z "$passwordentry" ] ; then
		F_terminal_show "Error - Password cannot be empty, Retry(any key) Main Menu(M)"
		read -rsn1 waitsmtppswd
		case $waitsmtppswd in
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
		read -rsn1 nomatchwait
		return 1
	fi

	# encrypt remove new lines so no sed errors
	user_pswd_encrypt="$(echo "$password_entry_1" | openssl enc -md sha512 -pbkdf2 -aes-256-cbc -a -salt -pass pass:"$(nvram get boardnum | sed 's/://g')" | tr -d '\n')"
	if echo "$user_pswd_encrypt" > "$cred_loc" ; then
		chmod 0644 "$cred_loc"
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
	if [ "$user_message_count" = '1' ] || [ -z "$user_message_count" ] || [ "$user_message_count" = '0' ] ; then
		F_terminal_entry_header 21
	elif [ "$user_message_count" = '2' ]; then
		F_terminal_entry_header 22
	elif [ "$user_message_count" = '3' ]; then
		F_terminal_entry_header 23
	elif [ "$user_message_count" = '4' ]; then
		F_terminal_entry_header 24
	fi
}

F_message_config() {
	if [ -n "$user_message_count" ] && [ "$user_message_count" != '0' ] ; then
		if [ "$user_message_count" -gt '1' ] ; then
			F_term_show_msgcount
			F_terminal_show "Total notification Email count and intervals"
			F_terminal_padding ;printf "%b Message count already set to %b%s%b \n" "$tTERMHASH" "$tGRN" "$user_message_count" "$tCLR"
			[ -n "$user_message_interval_1" ] && printf "%b Email 1/2 interval) %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_message_interval_1" "$tCLR"
			[ -n "$user_message_interval_2" ] && printf "%b Email 2/3 interval) %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_message_interval_2" "$tCLR"
			[ -n "$user_message_interval_3" ] && printf "%b Email 3/4 interval) %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_message_interval_3" "$tCLR"
			F_terminal_padding
			while true; do
				F_terminal_check "Keep this setting? Y or N"
				read -rsn1 messageexist
				case $messageexist in
					y|Y) return 0 ;;
					n|N) ;;
					*) F_fail_entry ;;
				esac
				break
			done

		else   # message count only set to 1
			F_term_show_msgcount
			F_terminal_show "Total notification Email count (and intervals)" ; F_terminal_padding
			while true; do
				printf "%b Message count already set to %b%s%b, keep this setting? Y or N" "$tCHECK" "$tGRN" "$user_message_count" "$tCLR"
				read -rsn1 messageexist2
				case $messageexist2 in
					y|Y) email_send_count_entry=1 && return 0 ;;   # set email send count for build_settings
					n|N) ;;
					*) F_fail_entry ;;
				esac
				break
			done
		fi
	fi

	user_message_count=   # empty var for term_show_msg_count incase overwriting old (ans:no to keep old settings), doesnt show old entry
	F_term_show_msgcount
	F_terminal_show "Enter the number of notification Emails (1-4) you wish to send"
	F_terminal_show "with variable intervals you will set in-between each notification"
	F_terminal_show "in the next step"
	F_terminal_padding ; F_terminal_entry "Number of notification Emails (1-4) : "
	read -r email_send_count_entry
	case $email_send_count_entry in
		[1-4]) ;;
		*) F_terminal_check_fail "Invalid Entry, must be 1,2,3,4 - any key to retry" && read -rsn1 invalidwaitcount && return 1 ;;
	esac
	F_terminal_padding
	while true; do
		printf "%b Is %b%s%b correct? Y or N " "$tCHECK" "$tGRN" "$email_send_count_entry" "$tCLR"
		read -rsn1 msgyesorno
		case $msgyesorno in
			y|Y) sed -i "1,/user_message_count=.*/{s/user_message_count=.*/user_message_count='$email_send_count_entry'/;}" "$config_src"
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

					while true; do
						printf "%b Is %b correct? Y or N" "$tCHECK" "$tGRN$message_period_entry $message_selection$tCLR"
						read -rsn1 msgyesorno
						case $msgyesorno in
							y|Y) ;;
							n|N) return 1 ;;
							*) F_fail_entry ;;
						esac
						break
					done
					message_interval_complete="$message_period_entry$message_interval_entry"
					sed -i "1,/user_message_interval_$message_entry_loop=.*/{s/user_message_interval_$message_entry_loop=.*/user_message_interval_$message_entry_loop='$message_interval_complete'/;}" "$config_src"
					eval "user_message_interval_$message_entry_loop=$message_interval_complete"   # set vars for terminal show (setup)
				else
					F_terminal_check_fail "Not a valid number, any key to retry" && read -rsn 1 nonumwait && return 1
				fi
				message_entry_loop=$((message_entry_loop + 1))
				email2count=$((email2count + 1))
				;;
			*) F_terminal_check_fail "Invalid entry. s/m/h/d only, any key to retry" && read -rsn1 timewait && return 1 ;;
		esac
	done
} ### message_intervals_entry

F_default() {
	echo "#!/bin/sh
# wicens user config file
build_settings_version='1.0'
###########################################################
saved_wan_ip=''
saved_wan_date=''
saved_wan_epoch=''
###########################################################
# User config settings ####################################
user_from_name=''
user_smtp_server=''
user_from_addr=''
user_send_to_addr=''
user_send_to_cc=''
user_message_type=''
user_message_count='0'
user_message_interval_1=''
user_message_interval_2=''
user_message_interval_3=''
user_custom_subject=''
user_custom_text=''
user_custom_script=''
user_custom_script_time=''
###########################################################
cron_run_count=0
last_cron_run=''
last_wancall_run=''
wancall_run_count=0
last_ip_change='never'
ip_change_count=0
created_date=''
last_wancall_log_count=0
opt_color='yes'
log_cron_msg=0
###########################################################
Created : $(date +%c)"
} ### default

F_default_update() {
	echo "#!/bin/sh
# wicens update conf file
update_auto_check_epoch=''
update_auto_check_avail='none'
###########################################################
Created : $(date +%c)"
}

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
	created_on="$run_date"   # get current date for setting vars if needed
	if [ -z "$created_date" ]; then
		sed -i "1,/created_date=.*/{s/created_date=.*/created_date='$created_on'/;}" "$config_src"
		created_date="$created_on"
	else
		while true; do
			F_status ; F_terminal_padding
			F_terminal_check "Upate script with new install date $run_date? Y or N"
			read -rsn1 updatewait
			case $updatewait in
				y|Y) sed -i "1,/created_date=.*/{s/created_date=.*/created_date='$created_on'/;}" "$config_src"
				     F_terminal_check_ok "Updated script with current date/time as install date"
				     created_date="$created_on" ;;   # for terminal show in setup
				n|N) F_terminal_check_ok "Leaving original install date" ;;
				*) F_fail_entry ;;
			esac
			break
		done
	fi

	chmod 0644 "$config_src"
	F_status ; F_terminal_show "Adding entries in cron(cru)/services-start/wan-event for wicens"
	F_auto_run_check
	F_terminal_check_ok "Done, entries added in cron(cru)/services-start/wan-event for wicens"
	F_terminal_padding ; F_terminal_check "Any key to continue" ; read -rsn 1 check_wait

	if [ -z "$saved_wan_ip" ]; then
		F_saved_wan_ip_create
		F_terminal_check "Any key to continue to view sample Email output"
		read -rsn1 continuewanwait
	fi

	F_opt_sample
	[ "$user_send_to_cc" = "currently none" ] && user_send_to_cc=''
	F_terminal_padding ; F_terminal_check_ok "Congratulations, you've completed the wicens setup."
	F_terminal_padding ; F_terminal_check "Hit t to send a test Email, m for main menu, any key to exit"
	read -rsn1 setupwait
	case $setupwait in
		t|T) rm -f "$script_lock" && exec sh "$script_name_full" test ;;
		m|M) F_clean_exit reload ;;
		*) F_clean_exit ;;
	esac

	printf "\r%b" "$tERASE"
	F_terminal_check_ok "Congratulations, this script is now configured"
	F_terminal_show "Run wicens on the command line to run script manually with set config"
	F_clean_exit
} ### build_settings

F_saved_wan_ip_create() {
	saved_wan_date="$run_date"
	F_terminal_header
	F_log_show "No saved WAN IP found, attempting to write current to this script"
	internet_check_count=0
	until F_internet_check ; do : ; done
	F_nvram_wan_ip_get
	F_script_wan_update
	saved_wan_ip="$current_wan_ip"
	rm -f "$mail_file" 2> /dev/null
} ### saved_wan_ip_check

# MAIL ############################################################################################

F_email_message() {
	if [ -n "$user_custom_subject" ];then   # needs to be here as current_wan_ip isnt set till right before this runs
		formatted_custom_subject="$(echo "$user_custom_subject_decoded" | sed "s~\$device_model~$device_model~g" | sed "s~\$current_wan_ip~$current_wan_ip~g" | sed "s~\$saved_wan_ip~$saved_wan_ip~g" )"
	fi

	[ -f "$mail_file" ] && rm -f "$mail_file"
	touch "$mail_file"

	{  # start of message output part 1/2
		[ -n "$user_send_to_cc" ] && echo "Cc: $user_send_to_cc"
		[ -z "$user_custom_subject" ] && echo "Subject: WAN IP has changed on $device_model" || echo "Subject: $formatted_custom_subject"
		echo "From: $user_from_name <$user_from_addr>"
		echo "Date: $(/bin/date +%c)"
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
	} >> "$mail_file" # end of output 1/2
	if [ "$user_message_count" -gt 1 ]; then
		if [ "$loop_run" = 1 ]; then
			echo "Message 1 of $user_message_count, you will receive another reminder in $user_message_interval_1" >> "$mail_file"
		else
			echo "Message $loop_run of $user_message_count" >> "$mail_file"
			echo "" >> "$mail_file"
			if [ "$loop_run" = "$user_message_count" ]; then
				echo "No more notifications, update your devices" >> "$mail_file"
				[ "$test_mode_active" != 'yes' ] && echo "" >> "$mail_file" && F_script_wan_update   # test mode dont update script
			else
				if [ "$loop_run" = '2' ]; then
					echo "You will receive another reminder in $user_message_interval_2" >> "$mail_file"
				fi
				if [ "$loop_run" = '3' ]; then
					echo "You will receive another reminder in $user_message_interval_3" >> "$mail_file"
				fi
			fi
		fi
	else
		echo "Message 1 of $user_message_count - No more notifications, update your devices" >> "$mail_file"
		[ "$test_mode_active" != 'yes' ] && F_script_wan_update   # test mode dont update script, update script outputs to mail message as well
	fi
	{ # start of message output 2/2
		echo ""
		echo "Message sent : $(/bin/date +%c)"
		echo ""
		echo "A message from wicens script on your $device_model"
		if [ "$passed_options" != 'sample' ] ; then   # padding incase emails contain footer info
			echo ""
			echo ""
		fi
	} >> "$mail_file"  # end of message output 2/2

	loop_run="$((loop_run + 1))"
} ### email_message

F_send_format_isp() {
	/usr/sbin/sendmail > "$mail_log" 2>&1 < "$mail_file" \
	-S "$user_smtp_server" -f "$user_from_addr" -t "$user_send_to_addr" -v
} ### message_format_isp

F_send_format_start_tls() {
	# -CAfile /jffs/configs/Equifax_Secure_Certificate_Authority.pem
	/usr/sbin/sendmail >> "$mail_log" 2>&1 < "$mail_file" \
	-H "exec openssl s_client -quiet \
	-starttls smtp \
	-connect $user_smtp_server  \
	-no_ssl3 -no_tls1" \
	-t \
	-f "$user_from_name" -au"$user_from_addr" -ap"$user_pswd" "$user_send_to_addr" -v
} ### message_format_tls

F_send_format_tls_v1() {
	# -CAfile /jffs/configs/Equifax_Secure_Certificate_Authority.pem
	sendmail >> "$mail_log" 2>&1 < "$mail_file" \
	-H "exec openssl s_client -quiet \
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
	if [ -z "$user_send_to_cc" ]; then
		curl >> "$mail_log" 2>&1 \
		--url smtps://"$user_smtp_server" \
		--mail-from "$user_from_name" --mail-rcpt "$user_send_to_addr" \
		--upload-file "$mail_file" \
		--ssl-reqd \
		--user "$user_from_addr:$user_pswd" \
		-v
	else
		curl >> "$mail_log" 2>&1 \
		--url smtps://"$user_smtp_server" \
		--mail-from "$user_from_name" --mail-rcpt "$user_send_to_addr" \
		--mail-rcpt "$user_send_to_cc" \
		--upload-file "$mail_file" \
		--ssl-reqd \
		--user "$user_from_addr:$user_pswd" \
		-v
	fi
} ### message_format_ssl

F_send_message() {
	touch "$mail_log"
	echo "Created by PID $$ on $(date +%c), ran by $passed_options" >> "$mail_log"
	[ -f "$cred_loc" ] && user_pswd="$(cat "$cred_loc" | openssl enc -md sha512 -pbkdf2 -aes-256-cbc -d -a -pass pass:"$(nvram get boardnum | sed 's/://g')" )"
	if [ "$user_message_type" = 'smtp_isp_nopswd' ]; then
		if F_send_format_isp ; then return 0 ; else return 1 ; fi
	elif [ "$user_message_type" = 'smtp_plain_auth' ]; then
		if F_send_format_plain_auth ; then return 0 ; else return 1 ; fi
	elif [ "$user_message_type" = 'smtp_start_tls' ]; then
		if F_send_format_start_tls ; then return 0 ; else return 1 ; fi
	elif [ "$user_message_type" = 'smtp_start_tls_v1' ]; then
		if F_send_format_tls_v1 ; then return 0 ; else return 1 ; fi
	elif [ "$user_message_type" = 'smtp_ssl' ]; then
		if F_send_format_ssl ; then return 0 ;else return 1 ; fi
	fi
} ### send_message

F_send_mail() {
	internet_check_count=0
	until F_internet_check ; do : ; done   # monitors/runs F_google_ping (attempts 5mins/30s interval)
	rm -f "$mail_log" 2> /dev/null
	touch "$script_mail_lock" # temp lockfile#2
	echo "Sending mail for $script_name_full on : $(/bin/date +%c)" >> "$script_mail_lock"
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
			F_log_show "Main Menu - option 6 for errors - p to re-enter password"
			rm -f "$mail_file"
			F_log_show "Resetting WAN IP to old WAN IP to attempt again in 10 minutes"
			sed -i "1,/saved_wan_date=.*/{s/saved_wan_date=.*/saved_wan_date='$original_wan_date'/;}" "$config_src"
			sed -i "1,/saved_wan_epoch=.*/{s/saved_wan_epoch=.*/saved_wan_epoch='$original_wan_epoch'/;}" "$config_src"
			sed -i "1,/saved_wan_ip=.*/{s/saved_wan_ip=.*/saved_wan_ip='$original_wan_ip'/;}" "$config_src"
			if [ "$from_menu" = 'yes' ] ; then
				F_menu_exit
			else
				F_clean_exit
			fi
		fi
		user_pswd=''
		printf "\r%b Done sending message %s of %s\n" "$tERASE$tCHECKOK" "$((loop_run - 1))" "$user_message_count"
		rm -f "$mail_file"
		F_log "Done sending Email $((loop_run - 1)) of $user_message_count update your clients to $current_wan_ip"

		if [ "$loop_run" -le "$user_message_count" ]; then
			if [ "$loop_run" = '2' ]; then
				printf "%b Sleeping %s before sending next Email" "$tCHECK" "$user_message_interval_1"
				F_log "Sleeping $user_message_interval_1 before sending next Email"
				sleep "$user_message_interval_1"
			fi
			if [ "$loop_run" = '3' ]; then
				printf "%b Sleeping %s before sending next Email" "$tCHECK" "$user_message_interval_2"
				F_log "Sleeping $user_message_interval_2 before sending next Email"
				sleep "$user_message_interval_2"
			fi
			if [ "$loop_run" = '4' ]; then
				printf "%b Sleeping %s before sending next email" "$tCHECK" "$user_message_interval_3"
				F_log "Sleeping $user_message_interval_3 before sending next Email"
				sleep "$user_message_interval_3"
			fi
		fi
	done
	# user_custom_script 'wait' call
	if [ -n "$user_custom_script" ] && [ "$user_custom_script_time" = 'w' ] && [ "$passed_options" != 'test' ] ; then
		nohup sh "$user_custom_script_decoded" > "${script_dir}/user_script.log" & custom_script_pid=$!	
		F_log "Executed custom script $user_custom_script_decoded and put in background with PID $custom_script_pid"
		F_terminal_check_ok "Started user custom script and put in background"
	fi
	
	if [ "$passed_options" != 'test' ] ; then
		[ -f '/tmp/wicens_user_script_i.tmp' ] && rm -f '/tmp/wicens_user_script_i.tmp'   # immediate call lock file remove after success
		ip_change_count=$((ip_change_count + 1))   # update script IP changes after success
		sed -i "1,/ip_change_count=.*/{s/ip_change_count=.*/ip_change_count='$ip_change_count'/;}" "$config_src"
	fi
	rm -f "$script_mail_lock"
	F_terminal_check_ok "Script completed."
	if [ "$from_menu" = 'yes' ] ; then
		F_menu_exit
	else
		F_clean_exit
	fi
} ### send_mail

# AUTO RUN ########################################################################################

F_cru() {
	if [ "$1" = 'check' ] ; then
		if cru l | grep -q "\*/10 \* \* \* \* $script_name_full cron" ; then
			printf "\r%b Cron(cru) : %s... %bexists%b\n" "$tERASE$tCHECKOK" "$(cru l | grep "$script_name_full cron" | cut -c -47)" "$tGRN" "$tCLR"
			return 0
		else
			F_terminal_check_fail "No wicens entry found in cron(cru)"
			return 1
		fi
	elif [ "$1" = 'add' ] ; then
		printf "%b Adding entry for wicens in cron(cru) with 10m interval" "$tCHECK"
		if cru a wicens "*/10 * * * * $script_name_full cron" ; then
			F_log_terminal_ok "ADDED entry for wicens in cron(cru) with 10m interval"
		else
			F_log_terminal_fail "Failed to add cron(cru) entry for wicens"
		fi
	fi
} # cru_check

F_serv_start() {
	if [ "$1" = 'check' ] ; then
		F_terminal_check "Checking for wicens entry"
		if grep -q "\*/10 \* \* \* \* $script_name_full cron" '/jffs/scripts/services-start' 2>/dev/null ; then
			printf "\r%b %s... %bexists%b\n" "$tERASE$tCHECKOK" "$(grep "$script_name_full" '/jffs/scripts/services-start' | cut -c -59)" "$tGRN" "$tCLR"
			return 0
		else
			F_terminal_check_fail "No wicens entry found in /jffs/scripts/services-start for cron(cru)"
			return 1
		fi
	elif [ "$1" = 'add' ] ; then 
		if [ -f '/jffs/scripts/services-start' ]; then
			if grep -q $'\x0D' '/jffs/scripts/services-start' ; then dos2unix /jffs/scripts/services-start ; fi 
			[ ! -x '/jffs/scripts/services-start' ] && chmod a+rx "/jffs/scripts/services-start"
			# cleanup if somehow different entry exists
			#grep -q "cru a wicens" '/jffs/scripts/services-start' && sed -i "/cru a wicens/d' '/jffs/scripts/services-start'
			F_terminal_check "Adding cron(cru) to /jffs/scripts/services-start"
			if ! grep -q '#!/bin/sh' '/jffs/scripts/services-start' ; then
				F_log "Your services-start does not contain a '#!/bin/sh', please investigate and run again"
				F_terminal_check_fail "Your services-start does not contain a '#!/bin/sh', please investigate and run again"
				F_clean_exit
			fi
			if echo "cru a wicens \"*/10 * * * * $script_name_full cron\"   # added by wicens" >> '/jffs/scripts/services-start' ; then
				F_log_terminal_ok "ADDED a cron(cru) entry for wicens to /jffs/scripts/services-start"
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
				if echo "cru a wicens \"*/10 * * * * $script_name_full cron\"   # added by wicens" >> /jffs/scripts/services-start ; then
					chmod a+rx "/jffs/scripts/services-start"
					F_log_terminal_ok "ADDED cron entry for wicens cron call in /jffs/scripts/services-start"
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
	fi
} # serv_start_check

F_wan_event() {
	if [ "$1" = 'check' ] ; then
		F_terminal_check "Checking for wicens entry"
		if grep -q "sh $script_name_full wancall" '/jffs/scripts/wan-event' ; then
			printf "\r%b %s... %bexists%b\n" "$tERASE$tCHECKOK" "$(grep "$script_name_full wancall" '/jffs/scripts/wan-event' | cut -c -59)" "$tGRN" "$tCLR"
			return 0
		else
			if [ -f '/jffs/scripts/wan-event' ]; then
				F_terminal_check_fail "No wicens entry found in /jffs/scripts/wan-event script"
			else
				F_terminal_check_fail "/jffs/scripts/wan-event does not exist"
			fi
			return 1
		fi
	elif [ "$1" = 'add' ] ; then
		if [ -f '/jffs/scripts/wan-event' ]; then
			if grep -q $'\x0D' '/jffs/scripts/wan-event' ; then dos2unix /jffs/scripts/wan-event ; fi
			[ ! -x '/jffs/scripts/wan-event' ] && chmod a+rx '/jffs/scripts/wan-event'
			F_terminal_check "Adding wicens to wan-event script on connected event"
			if ! grep -q '#!/bin/sh' '/jffs/scripts/wan-event' ; then
				F_terminal_check_fail "Your wan-event does not contain a '#!/bin/sh', please investigate and run again"
				F_log "Your wan-event does not contain a '#!/bin/sh', please investigate and run again"
				F_clean_exit
			fi
			if echo "[ \"\$2\" = 'connected' ] && sh $script_name_full wancall &   # added by wicens" >> /jffs/scripts/wan-event ; then
				F_log_terminal_ok "ADDED wicens to wan-event with connected event trigger"
			else
				F_terminal_check_fail "Error, failed writing wicens wancall entry to wan-event"
				F_clean_exit
			fi
		else
			F_terminal_check_fail "/jffs/scripts/wan-event does not exist"
			F_log "/jffs/scripts/wan-event does not exist, attempting to create"
			F_terminal_check "Creating /jffs/scripts/wan-event"
			touch '/jffs/scripts/wan-event'
			F_terminal_check_ok "Created wan-event in /jffs/scripts/"
			if echo '#!/bin/sh' >> /jffs/scripts/wan-event ; then
				if echo "[ \"\$2\" = 'connected' ] && sh $script_name_full wancall &   # added by wicens" >> /jffs/scripts/wan-event ; then
					chmod a+rx '/jffs/scripts/wan-event'
					F_terminal_check_ok "ADDED connected event entry for wicens wancall in /jffs/scripts/wan-event"
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
	fi
} # wan_event_check

F_auto_run_check() {
	F_terminal_check "cron(cru) check" && if ! F_cru check ; then F_cru add ;fi
	F_terminal_check "services-start check" && if ! F_serv_start check ; then F_serv_start add ;fi
	F_terminal_check "wan-event check" && if ! F_wan_event check ; then F_wan_event add ; fi
} ### auto_run_check

F_disable_autorun() {
	F_terminal_check "Removing cron entry for wicens"
	if cru l | grep -q "$script_name cron" ; then
		if cru d wicens ; then
			F_log_terminal_ok "Removed cron entry for wicens"
		else
			F_terminal_check_fail "Error, failed removing cron entry for wicens"
			F_log "Error, failed removing cron entry for wicens"
		fi
	else
		F_terminal_check_ok "No entry found for wicens in cron(cru) to remove"
	fi
	F_terminal_check "Removing services-start entry for wicens"
	if [ -f '/jffs/scripts/services-start' ]; then
		if grep -q "$script_name_full cron" '/jffs/scripts/services-start' 2> /dev/null; then
			if sed -i "\| $script_name_full |d" '/jffs/scripts/services-start' ; then
				F_log_terminal_ok "Removed services-start entry for wicens"
			else
				F_terminal_check_fail "Error, could not remove wicens entry in /jffs/scripts/services-start"
				F_log "Error, could not remove wicens entry in services-start"
			fi
		else
			F_terminal_check_ok "No entry found for wicens in /jffs/scripts/services-start to remove"
		fi
		if [ "$(wc -l < /jffs/scripts/services-start )" -eq 1 ]; then
			if grep -q "#!/bin/sh" "/jffs/scripts/services-start"; then
				F_log_terminal_ok "/jffs/scripts/services-start appears empty, removing file"
				rm -f /jffs/scripts/services-start
			fi
		fi
	else
		F_terminal_check_ok "/jffs/scripts/services-start is already removed"
	fi
	F_terminal_check "Removing wan-event entry for wicens"
	if [ -f '/jffs/scripts/wan-event' ]; then
		if grep -q "$script_name_full wancall" '/jffs/scripts/wan-event' 2> /dev/null; then
			sed -i "\| $script_name_full |d" '/jffs/scripts/wan-event'
			F_log_terminal_ok "Removed wan-event entry for wicens"
		else
			F_terminal_check_ok "No entry found for wicens in /jffs/scripts/wan-event to remove"
		fi

		if [ "$(wc -l < /jffs/scripts/wan-event)" -eq 1 ]; then
			if grep -q "#!/bin/sh" "/jffs/scripts/wan-event"; then
				F_log_terminal_ok "/jffs/scripts/wan-event appears empty, removing file"
				rm -f /jffs/scripts/wan-event
			fi
		fi
	else
		F_terminal_check_ok "/jffs/scripts/wan-event is already removed"
	fi
	return 0
} ### disable_autorun

# CORE ############################################################################################

F_script_wan_update() {
	[ "$ip_match" = 'no' ] && sed -i "1,/last_ip_change=.*/{s/last_ip_change=.*/last_ip_change='$run_date'/;}" "$config_src" # only write on change
	[ "$building_settings" = 'yes' ] && F_terminal_check_ok "IP successfully retrieved"
	printf "%b Updating wicens script with new WAN IP %b%s%b" "$tCHECK" "$tYEL" "$current_wan_ip" "$tCLR"

	if sed -i "1,/saved_wan_ip=.*/{s/saved_wan_ip=.*/saved_wan_ip='$current_wan_ip'/;}" "$config_src"; then
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
		sed -i "1,/saved_wan_date=.*/{s/saved_wan_date=.*/saved_wan_date='$run_date'/;}" "$config_src"
		sed -i "1,/saved_wan_epoch=.*/{s/saved_wan_epoch=.*/saved_wan_epoch='$run_epoch'/;}" "$config_src"
	else
		F_terminal_check_fail "Updating wicens with new WAN IP : sed failed"
		F_log "FAILED (sed) updating wicens with new WAN IP"
		echo "Updating WICENS script with new WAN IP $current_wan_ip : sed Failed" >> "$mail_file"
	fi
} ### update_script

F_private_ip() {
	grep -qE "(^127\.)|(^(0)?10\.)|(^172\.(0)?1[6-9]\.)|(^172\.(0)?2[0-9]\.)|(^172\.(0)?3[0-1]\.)|(^169\.254\.)|(^192\.168\.)"
} # private_ip
	
F_nvram_wan_ip_get() {
	F_terminal_check "Checking WAN IP stored in nvram..."
	current_wan_ip="$(nvram get wan0_ipaddr)"
	if [ "$current_wan_ip" = '0.0.0.0' ] || [ -z "$current_wan_ip" ] ; then
		F_log_terminal_fail "No valid IP found in NVRAM, attempting to force update"
		internet_check_count=0
		until F_internet_check ; do : ; done   # monitors/runs F_google_ping (attempts 5mins/30s interval)
		F_current_wan_ip_get
	elif echo "$current_wan_ip" | F_private_ip ; then
		printf "\r%b WAN IP %s is a private IP, something is wrong" "$tERASE$tCHECKFAIL" "$current_wan_ip"
		F_log "Error - WAN IP $current_wan_ip is a private IP, something is wrong"
		F_clean_exit
	fi
	if [ "$current_wan_ip" = "$saved_wan_ip" ] ; then
		return 0
	else
		return 1   # WAN IP is valid, doesnt match saved
	fi
} ### nvram_wan_ip_get

F_current_wan_ip_get() {
	getrealip_call_count=3   # max tries to get WAN IP

	F_getrealip() {   # watcher for getrealip.sh so if it hangs it doesnt sit around forever
		sleep_wait=5
		( sh /usr/sbin/getrealip.sh | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" ) & command_pid=$!
		( sleep "$sleep_wait" && kill -HUP "$command_pid" 2> /dev/null && rm -f /tmp/wicenswanipget.tmp && F_log "NOTICE - Killed hung getrealip.sh process after 5 secs" ) & watcher_pid=$!
		wait "$command_pid" && kill -HUP "$watcher_pid" 2> /dev/null
		getrealip_call_count=$((getrealip_call_count - 1))
	} # getrealip

	while [ "$getrealip_call_count" != '0' ]; do   #  check for WAN IP 3 times
		F_terminal_check "Retrieving WAN IP using getrealip.sh"

		F_getrealip > /tmp/wicenswanipget.tmp   # output to file or watcher doesnt function properly when var=
		current_wan_ip="$(grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}" /tmp/wicenswanipget.tmp 2>/dev/null )"
		[ -f '/tmp/wicenswanipget.tmp' ] && rm -f /tmp/wicenswanipget.tmp

		if [ -z "$current_wan_ip" ] || [ "$current_wan_ip" = '0.0.0.0' ] ; then
			if [ "$getrealip_call_count" -eq 0 ]; then
				F_terminal_check_fail "Error retrieving WAN IP 3 times... aborting...."
				F_log "Error retrieving WAN IP 3 times... aborting...."
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

	if echo "$current_wan_ip" | F_private_ip ; then
		printf "\r%b WAN IP %s is a private IP, something is wrong" "$tERASE$tCHECKFAIL" "$current_wan_ip"
		F_log "ERROR - WAN IP $current_wan_ip is a private IP, something is wrong"
		F_clean_exit
	fi
} ### current_wan_ip_get

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
	wan_lease_secs="$epoch_diff"   			# secs

	# output for Email in F_email_message
	echo ''
	printf "Old WAN IP recorded in script on : %s \n" "$saved_wan_date"
	printf "WAN IP Lease time observed       : "
	[ "$wan_lease_years" -gt 0 ] && printf "%s yr(s) " "$wan_lease_years"
	[ "$wan_lease_days" -gt 0 ] && printf "%s day(s) " "$wan_lease_days"
	[ "$wan_lease_hours" -gt 0 ] && printf "%s hr(s) " "$wan_lease_hours"
	[ "$wan_lease_mins" -gt 0 ] && printf "%s min(s) " "$wan_lease_mins"
	printf "%s sec(s) \n" "$wan_lease_secs"
} ### calc_lease

F_reset_do() {
	printf "\r%b Resetting script to default" "$tERASE$tCHECK"
	[ -f "$cred_loc" ] && rm -f "$cred_loc"
	[ -f "$config_src" ] && rm -f "$config_src"
	printf '%b' "$tBACK$tERASE" ; F_log_terminal_ok "Done, script user settings reset to default"
	[ -f "$mail_log" ] && rm -f "$mail_log"
	return 0
} ### reset_do

F_reset_count() {
	F_terminal_check "Resetting script wancall count/install date"
	sed -i "1,/cron_run_count=.*/{s/cron_run_count=.*/cron_run_count=0/;}" "$config_src"
	sed -i "1,/last_cron_run=.*/{s/last_cron_run=.*/last_cron_run=''/;}" "$config_src"
	sed -i "1,/wancall_run_count=.*/{s/wancall_run_count=.*/wancall_run_count=0/;}" "$config_src"
	sed -i "1,/last_wancall_run=.*/{s/last_wancall_run=.*/last_wancall_run=''/;}" "$config_src"
	sed -i "1,/last_wancall_log_count=.*/{s/last_wancall_log_count=.*/last_wancall_log_count=0/;}" "$config_src"
	sed -i "1,/created_date=.*/{s/created_date=.*/created_date=''/;}" "$config_src"
	F_log_terminal_ok "Reset cron/wancall counts, install date to default"

	if [ "$last_ip_change" != 'never' ] ; then
		while true; do
			F_terminal_check "Do you want to reset last recorded WAN IP change date and count - Y or N?"
			read -rsn1 reset_wait		
			case $reset_wait in
				y|Y) sed -i "1,/last_ip_change=.*/{s/last_ip_change=.*/last_ip_change='never'/;}" "$config_src"
					 sed -i "1,/ip_change_count=.*/{s/ip_change_count=.*/ip_change_count=0/;}" "$config_src"
					F_log_terminal_ok "Reset last recorded WAN IP change date"
					return 0 ;;
				n|N) F_terminal_check_ok "Leaving WAN IP change records"
					return 0 ;;
				*) F_fail_entry ;;
			esac
			break
		done
	fi
	return 0
} # counts_reset

F_settings_test() {
	settings_test='OK'
	if [ -z "$user_from_addr" ] || [ -z "$user_message_type" ] || [ -z "$user_send_to_addr" ] || [ -z "$user_smtp_server" ]; then
		return 1
	fi
	[ "$user_message_count" -eq 0 ] && settings_test='FAIL'
	if [ "$user_message_count" -ge 2 ] && [ -z "$user_message_interval_1" ]; then
		printf "[%bFAIL%b] Email notifications set to %s, missing interval 1/2 value \n" "$tRED" "$tCLR" "$user_message_count"
		F_log "Email notifications set to $user_message_count, missing interval 1/2 value"
		settings_test='FAIL'
	fi

	if [ "$user_message_count" -ge 3 ] && [ -z "$user_message_interval_2" ]; then
		printf "[%bFAIL%b] Email notifications set to %s, missing interval 2/3 value \n" "$tRED" "$tCLR" "$user_message_count"
		F_log "Email notifications set to $user_message_count, missing interval 2/3 value"
		settings_test='FAIL'
	fi

	if [ "$user_message_count" -eq 4 ] && [ -z "$user_message_interval_3" ]; then
		printf "[%bFAIL%b] Email notifications set to %s, missing interval 3/4 value \n" "$tRED" "$tCLR" "$user_message_count"
		F_log "Email notifications set to $user_message_count, missing interval 3/4 value"
		settings_test='FAIL'
	fi

	if [ ! -f "$cred_loc" ] && [ "$user_message_type" != 'smtp_isp_nopswd' ]; then
		printf "[%bFAIL%b] Email send type set to %s but missing required password \n" "$tRED" "$tCLR" "$user_message_type"
		F_log "Email send type set to $user_message_type but missing required password"
		settings_test='FAIL'
	fi

	# CLEAN UP
	# clean old user_pswd if setup was edited
	[ -f "$cred_loc" ] && [ "$user_message_type" = 'smtp_isp_nopswd' ] && rm -f "$cred_loc"
	
	# if old intervals exist but message count changed to 1, reset intervals
	if [ -n "$user_message_interval_1" ] || [ -n "$user_message_interval_2" ] || [ -n "$user_message_interval_3" ] ; then
		if [ "$user_message_count" = '1' ] ; then
			sed -i "1,/user_message_interval_1=.*/{s/user_message_interval_1=.*/user_message_interval_1=''/;}" "$config_src"
			sed -i "1,/user_message_interval_2=.*/{s/user_message_interval_2=.*/user_message_interval_2=''/;}" "$config_src"
			sed -i "1,/user_message_interval_3=.*/{s/user_message_interval_3=.*/user_message_interval_3=''/;}" "$config_src"
		fi
	fi

	# only if someone manually deletes saved WAN IP
	if [ -z "$saved_wan_ip" ] ; then
		F_saved_wan_ip_create
		F_log_show "Missing WAN IP"
		F_clean_exit reload
	fi

	# incase ran reset count but didnt rerun setup
	if [ -z "$created_date" ]; then
		created_on="$(/bin/date +%c)" && sed -i "1,/created_date=.*/{s/created_date=.*/created_date='$created_on'/;}" "$config_src"
		created_date="$created_on"   # for terminal show
	fi

	if [ "$settings_test" = 'OK' ]; then
		return 0
	else
		return 1
	fi
} ### settings_test

F_google_ping() {
	F_test_sites() { 
		echo "google.com" ;echo "bing.com" ;echo "yahoo.com" ;echo "github.com" ;echo "asus.com"
	}
	good_ping=0
	for tested_site in $(F_test_sites) ; do
		ping_try_count=1
		site_ping=0
		while [ "$ping_try_count" != '4' ]
		do
			if ping -q -w1 -c1 "$tested_site" > /dev/null 2>&1 ; then
				good_ping=$((good_ping + 1))
				site_ping=$((site_ping + 1))
				[ "$good_ping" -ge 5 ] && return 0
				[ "$site_ping" -ge 2 ] && break
			fi
			ping_try_count=$((ping_try_count + 1))
		done
	done
	return 1
} ### google_ping

F_internet_check() {
	internet_check_count=$((internet_check_count + 1))
	if [ "$internet_check_count" = '10' ]; then
		F_terminal_check_fail "Could not ping Google/Bing/Yahoo/Github/Asus for the last 5 mins, exiting. Run again with next cron"
		F_log "Could not ping Google/Bing/Yahoo/Github/Asus for the last 5 mins, exiting. Run again with next cron"
		F_clean_exit
	fi

	F_terminal_check "Checking Internet status"
	if F_google_ping; then
		printf "\r%b Internet check      : %s successful pings, appears up \n" "$tCHECKOK" "$good_ping"
		return 0
	else
		F_terminal_check_fail "Failed pinging Google/Bing/Yahoo/Github/Asus 3 times each"
		wait_secs=30
		while [ "$wait_secs" != '0' ]; do
			printf "%b %b%s%b seconds before next attempt \r" "$tERASE$tCHECK" "$tGRN" "$wait_secs" "$tCLR"
			sleep 1
			wait_secs=$((wait_secs - 1))
		done
		return 1
	fi
} ### internet_check  called with until loop

F_local_script_update() {
	F_terminal_header
	if F_settings_test && [ ! -f "$script_backup_file" ] ; then
		F_terminal_warning
		F_terminal_check_fail "No backup file exists for your config." ; F_terminal_padding
		F_terminal_show "Recommended to create a backup before upgrading" ; F_terminal_padding
		F_terminal_check "C to continue, any key to return to main menu"
		read -rsn1 updatebackupwait
		case $updatebackupwait in
			c|C) printf '\r%b' "$tERASE$tBACK$tERASE$tBACK$tERASE" ;;
			*) F_clean_exit reload ;;
		esac
	fi
	
	F_terminal_show "Starting script update to ver: $update_auto_check_avail" ; F_terminal_padding
	F_terminal_check "Dowloading...."
	sleep 1
	if /usr/sbin/curl -fsL --retry 3 --connect-timeout 15 "$script_git_src" -o /jffs/scripts/wicens.sh ; then
		[ ! -x "$script_name_full" ] && chmod a+rx "$script_name_full"
		F_terminal_check_ok "Success, new script ver $update_auto_check_avail installed" ; F_terminal_padding
		sed -i "1,/update_auto_check_avail=.*/{s/update_auto_check_avail=.*/update_auto_check_avail='none'/;}" "$update_src"
		sed -i "1,/update_auto_check_epoch=.*/{s/update_auto_check_epoch=.*/update_auto_check_epoch='$(/bin/date +%s)'/;}" "$update_src"
	else
		F_terminal_check_fail "Error, failed downloading/saving new script version" ; F_terminal_padding
	fi
	F_terminal_check "Any key to restart script"
	read -rsn1 restartupdatewait
	F_clean_exit reload
}

F_web_update_check() {
	if [ "$update_diff" -ge "$update_check_period" ] || [ "$1" = 'force' ] ; then   # update period is longer than specified do check otherwise ignore function
		F_terminal_header ; F_terminal_padding ; printf "%bScript update check%b \n" "$tTERMHASH $tYEL" "$tCLR" ; F_terminal_padding
		# download wait timer
		wait_update_time=15
		F_time() {
			while [ "$wait_update_time" != '0' ] ; do
				printf "%b Checking for update %b%s%b secs - Auto update check disabled for %b%s%b secs " \
				"$tCHECK" "$tGRN" "$wait_update_time" "$tCLR" "$tRED" "$update_check_period" "$tCLR"
				wait_update_time=$((wait_update_time - 1))
				update_check_period=$((update_check_period - 1))
				sleep 1
				printf '\r%b' "$tERASE"
			done
		}
		# menu timer
		menu_time=2
		F_menu_countdown() {
			while [ "$menu_time" != '0' ] ; do
				printf "%b Loading menu in %s secs... " "$tCHECK" "$menu_time"
				menu_time=$((menu_time - 1))
				sleep 1
				printf '\r%b' "$tERASE"
			done
		}
		F_time & time_pid=$!   # start timer wait for vars to be set then kill
		sleep 2   # pretty terminal wait
		git_get="/usr/sbin/curl -fsL --retry 3 --connect-timeout 15 $script_git_src"
		git_version="$($git_get | grep 'script_version' | head -n1 | cut -d"=" -f2 | sed "s/'//g")"
		local_md5="$(md5sum "$script_name_full" | awk '{print $1}')"
		server_md5="$($git_get | md5sum | awk '{print $1}')"
		if [ -z "$git_version" ] ; then
			kill "$time_pid" >/dev/null 2>&1
			printf '%b' "$tERASE$tBACK$tERASE"
			printf "\r%b Failed, could not read server script version... aborting update check \n" "$tERASE$tCHECKFAIL"   # stays displayed
			sleep 3   # terminal display
			return 1   # skip everything below
		fi
		kill "$time_pid" >/dev/null 2>&1
		[ ! -f "$update_src" ] && F_default_update > "$update_src"
		sed -i "1,/update_auto_check_epoch=.*/{s/update_auto_check_epoch=.*/update_auto_check_epoch='$(/bin/date +%s)'/;}" "$update_src"
		if [ "$script_version" = "$git_version" ] ; then
			if [ "$local_md5" != "$server_md5" ] ; then
				sed -i "1,/update_auto_check_avail=.*/{s/update_auto_check_avail=.*/update_auto_check_avail='hotfix'/;}" "$update_src"
				printf '\r%b Success%b checking for update %bhotfix%b available \n' "$tERASE$tCHECKOK$tGRN" "$tCLR" "$tRED" "$tCLR"
			else
				printf '\r%b Success%b checking for update none available \n' "$tERASE$tCHECKOK$tGRN" "$tCLR"
			fi
		else
			sed -i "1,/update_auto_check_avail=.*/{s/update_auto_check_avail=.*/update_auto_check_avail='$git_version'/;}" "$update_src"
			printf '\r%b Success%b checking for update... Ver: %b%s%b available \n' "$tERASE$tCHECKOK$tGRN" "$tCLR" "$tGRN" "$git_version" "$tCLR"
		fi
		. "$update_src"   # resource config to update vars in current session
	else
		printf '\r%b Update check recently, %s secs since last check \n' "$tERASE$tTERMHASH" "$update_diff"   # debug msg
	fi
	[ "$1" = 'force' ] && F_menu_exit || F_terminal_padding && F_menu_countdown
} ### web_update_check

F_clean_exit() {
	[ "$passed_options" = 'remove' ] && F_terminal_check_ok "Exiting." && F_terminal_padding && exit 0
	F_terminal_check "Exiting, removing $script_lock file"
	[ -f "$script_lock" ] && rm -f "$script_lock"
	[ -f "$script_mail_lock" ] && rm -f "$script_mail_lock"
	[ -f "$ntp_lock" ] && rm -f "$ntp_lock"
	[ -d "/proc/${time_pid}" ] && kill "$time_pid" >/dev/null 2>&1   # update check time countdown
	if [ ! -f "$script_lock" ]; then
		F_terminal_check_ok "Removed $script_lock file"
		[ "$1" = 'reload' ] && exec sh "$script_name_full"
		printf "%b Goodbye%b \n\n" "$tERASE$tCHECKOK$tYEL" "$tCLR"
		exit 0
	else
		if [ "$$" != "$(sed -n '2p' "$script_lock")" ]; then
			F_terminal_check_ok "Exiting, removing $script_lock file"
			F_terminal_show "Lock file still present but not from this process..."
			F_terminal_show "likely another process started while this one was exiting"
			exit 0
		else
			F_terminal_check_fail "CRITICAL ERROR - Failed to remove lock file"
			F_log "CRITICAL ERROR - Failed to remove lock file"
			exit 1
		fi
	fi
} ### clean_exit

F_ready_check() {
	if ! F_settings_test; then
		if [ "$from_menu" = 'yes' ] ; then
			[ "$1" = 'pswdset' ] && return 0
			[ "$1" != 'options' ] && F_terminal_header   # not sent here from a menu option, displayed already
			F_terminal_check_fail "Error, no Email settings have been setup"
			F_terminal_padding; F_terminal_show "Use menu option 1 to add settings"
			F_menu_exit
		else
			[ "$passed_options" != 'manual' ] && F_log "CRITICAL ERROR, no/incorrect Email config found in this script"
			[ "$passed_options" != 'manual' ] && F_log "Run $script_name_full to add a config to this script"
			F_clean_exit
		fi
	else # passes test but trying to establish pswd with isp_type or incomplete settings
		if [ "$1" = 'pswdset' ] ; then
			if [ "$user_message_type" = 'smtp_isp_nopswd' ] || [ -z "$user_message_type" ] ; then
				F_terminal_check_fail "Cannot add password, SMTP type is either empty or set to ISP type"
				F_terminal_padding ;F_terminal_show "Use menu option 1 to edit settings"
				F_menu_exit
			fi
		fi
	fi
} ### ready_check   runs F_settings test and allows or not

F_do_compare() {
	if F_nvram_wan_ip_get ; then
		printf "\r%b WAN IP lookup       : Current WAN IP is %b%s%b \n" "$tERASE$tCHECKOK" "$tGRN" "$current_wan_ip" "$tCLR"
		printf "%b WAN IP compare      : %bMatch%b - Current saved WAN IP %b%s%b\n" "$tCHECKOK" "$tGRN" "$tCLR" "$tGRN" "$saved_wan_ip" "$tCLR"
		F_terminal_check_ok "Done."
		if [ "$from_menu" = 'yes' ] ; then F_menu_exit ; else F_clean_exit ; fi
	else
		printf "\r%b WAN IP compare      : No Match - Current saved WAN IP %b%s%b \n" "$tERASE$tCHECKFAIL" "$tPUR" "$saved_wan_ip" "$tCLR"
		F_log "WAN IP has changed to $current_wan_ip "
		ip_match='no'
		# user_custom_script 'immediate' call
		if [ -n "$user_custom_script" ] && [ "$user_custom_script_time" = 'i' ] && [ "$passed_options" != 'test' ] && [ ! -f '/tmp/wicens_user_script_i.tmp' ] ; then
			nohup sh "$user_custom_script_decoded" > "${script_dir}/user_script.log" 2>&1 & custom_script_pid=$!
			F_log "Executed custom script $user_custom_script_decoded and put in background with PID $custom_script_pid"
			F_terminal_check_ok "Started user custom script and put in background"
			touch /tmp/wicens_user_script_i.tmp   # prevent duplicate runs if email fails on first detection as this will run
		fi
		return 1
	fi
} ### do_compare   does wan ip compare and returns

# STATUS/TERMINAL #################################################################################

F_terminal_header() {
	clear
	sed -n '2,11p' "$script_name_full"
	printf "%5s%b%s%b -- %bver: %s%b -- %b%s%b FW ver: %b%s.%s_%s%b\n" "" "$tGRN" "$(/bin/date +%c)" "$tCLR" "$tYEL" "$script_version" "$tCLR" "$tGRN" "$device_model" "$tCLR" "$tGRN" "$build_no" "$build_sub" "$build_extend" "$tCLR"
	[ "$test_mode_active" = 'yes' ] && printf "%b %b###  Test Mode - Sending $user_message_count message(s) ### %b\n" "$tTERMHASH" "$tYEL" "$tCLR"
	F_terminal_separator
} ### terminal_header

F_status() {
	F_terminal_header
	[ "$building_settings" = 'yes' ] && printf '%b %bWelcome to the WICENS setup %b \n' "$tTERMHASH" "$tGRN" "$tCLR" && F_terminal_padding
	printf "%b Current saved WAN IP             :  %b%s%b\n" "$tTERMHASH" "$tGRN" "$saved_wan_ip" "$tCLR"
	F_terminal_header_print "Current Email send to address    : " "$user_send_to_addr"
	[ -n "$user_send_to_cc" ] && F_terminal_header_print "Current Email send to CC address : " "$user_send_to_cc"
	F_terminal_header_print "Current Email server addr:port   : " "$user_smtp_server"
	F_terminal_header_print "Current Email send format type   : " "$user_message_type"
	[ -f "$cred_loc" ] && F_terminal_header_print "Current Email password           : " "Pswd saved"
	F_terminal_header_print "Current Email send from address  : " "$user_from_addr"
	F_terminal_header_print "Current Email message from name  : " "$user_from_name"
	F_terminal_header_print "Total # Email notifications set  : " "$user_message_count"
	[ "$user_message_count" -gt 1 ] 2>/dev/null && F_terminal_header_print "Interval between Email 1/2       : " "$user_message_interval_1"
	[ "$user_message_count" -gt 2 ] 2>/dev/null && F_terminal_header_print "Interval between Email 2/3       : " "$user_message_interval_2"
	[ "$user_message_count" -gt 3 ] 2>/dev/null && F_terminal_header_print "Interval between Email 3/4       : " "$user_message_interval_3"
	F_terminal_header_print "Cron run interval                : " "10 minutes"
	if [ -n "$user_custom_subject" ] ; then
		user_custom_subject_show="$user_custom_subject_decoded"
		[ ${#user_custom_subject_show} -gt 31 ] && user_custom_subject_show="$(echo "$user_custom_subject_decoded" | cut -c -28 | sed 's/$/.../g')"
		F_terminal_header_print "Custom Subject line set          : " "$user_custom_subject_show"
	fi
	if [ -n "$user_custom_text" ] ; then
		user_custom_text_show="$user_custom_text_decoded"
		[ ${#user_custom_text_show} -gt 31 ] && user_custom_text_show="$(echo "$user_custom_text_decoded" | cut -c -28 | sed 's/$/.../g')"
		F_terminal_header_print "Custom message text is set       : " "$user_custom_text_show"
	fi
	if [ -n "$user_custom_script_decoded" ] ; then
		user_custom_script_show="$user_custom_script_decoded"
		[ ${#user_custom_script_show} -gt 31 ] && user_custom_script_show="$(echo "$user_custom_script_decoded" | cut -c 28- | sed 's/^/.../g')"
		F_terminal_header_print "Custom script path               : " "$user_custom_script_show"
	fi
	[ -n "$user_script_call_time" ] && F_terminal_header_print "Custom script call time          : " "$user_script_call_time"
	F_terminal_header_print "Number of cron checks            : " "$cron_run_count"
	F_terminal_header_print "Number of wan-event checks       : " "$wancall_run_count"
	[ -n "$last_cron_run" ] && F_terminal_header_print "Last monitored with cron         : " "$last_cron_run"
	[ -n "$last_wancall_run" ] && F_terminal_header_print "Last ran with wan-event          : " "$last_wancall_run"
	F_terminal_header_print "Last IP change                   : " "$last_ip_change"
	F_terminal_header_print "Total IP changes since install   : " "$ip_change_count"
	F_terminal_header_print "Script installed on              : " "$created_date"
	if [ "$update_diff" -le "$update_check_period" ] ; then
		F_terminal_header_print "Secs to next update check w/run  : " "$update_rem"
	else
		F_terminal_header_print "Secs to next update check w/run  : " "Ready to check"
	fi
	F_terminal_show '---------------------------------------------------------------------'
	if [ "$1" = 'view' ] ; then
		F_cru check ;F_serv_start check ;F_wan_event check
		return 0
	fi
} ### status

# Menu ############################################################################################

F_menu_exit() {
	F_terminal_padding
	printf "%b Any key to return to main menu, E to exit" "$tCHECK"
	read -rsn1 exitwait
	printf '\r%b' "$tERASE"
	case $exitwait in
		e|E) F_terminal_check_ok "Exiting."
		     F_clean_exit ;;
		*) F_clean_exit reload ;;
	esac
} ### menu_exit

F_main_menu() {
	[ "$from_menu" != 'yes' ] && F_web_update_check
	F_terminal_header
	from_menu='yes'
	update_auto_check_epoch="$run_epoch"   # reset var within session so it doesnt re calc in until loop
	printf  "       Auto Run                             Status \n" ;F_terminal_separator
	printf "%b Cron(cru) entry--------------:       " "$tTERMHASH"
	cru l | grep -q "\*/10 \* \* \* \* $script_name_full cron" && printf "%bActive%b\n" "$tGRN" "$tCLR" || printf "%bDisabled%b\n" "$tRED" "$tCLR"
	printf "%b services-start entry---------:       " "$tTERMHASH"
	grep -q "cru a wicens \"\*/10 \* \* \* \* $script_name_full cron" 2> /dev/null '/jffs/scripts/services-start' && printf "%bActive%b\n" "$tGRN" "$tCLR" || printf "%bDisabled%b\n" "$tRED" "$tCLR"
	printf "%b wan-event connected entry----:       " "$tTERMHASH"
	grep -q "$script_name_full wancall" 2> /dev/null '/jffs/scripts/wan-event' && printf "%bActive%b\n" "$tGRN" "$tCLR" || printf "%bDisabled%b\n" "$tRED" "$tCLR"
	F_terminal_separator; printf "       Option                      Select   Status \n" ;F_terminal_separator

	if F_settings_test ; then
		printf "%b Enable autorun/manual check--: m%b     Ready%b\n" "$tTERMHASH" "$tGRN" "$tCLR"
		printf "%b Create/edit settings---------: 1%b     Exists%b\n" "$tTERMHASH" "$tGRN" "$tCLR"
	else
		printf "%b Enable autorun/manual check--: m%b     Not Ready%b\n" "$tTERMHASH" "$tRED" "$tCLR"
		printf "%b Create/edit settings---------: 1%b     Missing/incomplete settings %b\n" "$tTERMHASH" "$tRED" "$tCLR"
		[ -f "$script_backup_file" ] && printf "%b Found backup config file-----:       %bExists%b - opt b to restore \n" "$tTERMHASH" "$tGRN" "$tCLR"
	fi
	printf "%b Custom Email msg text--------: 2" "$tTERMHASH" ;[ -n "$user_custom_text" ] && printf "%b     Exists%b\n" "$tGRN" "$tCLR" || printf "%b     Unused%b\n" "$tPUR" "$tCLR"
	printf "%b Custom Email msg subject-----: 3" "$tTERMHASH" ;[ -n "$user_custom_subject" ] && printf "%b     Exists%b\n" "$tGRN" "$tCLR" || printf "%b     Unused%b\n" "$tPUR" "$tCLR"
	printf "%b Custom script execution------: s" "$tTERMHASH" ;[ -n "$user_custom_script" ] && printf "%b     Exists%b   -   Action:%b %s%b \n" "$tGRN" "$tCLR" "$tGRN" "$user_script_call_time" "$tCLR" || printf "%b     Unused%b\n" "$tPUR" "$tCLR"
	F_terminal_separator ;F_terminal_show "Show sample Email------------: 4"
	F_terminal_show "Send a test Email------------: 5"
	F_terminal_show "Show Email send log----------: 6"
	F_terminal_show "Reset cron/wan-event counts--: 7"
	F_terminal_show "View current status/settings-: v"
	F_terminal_show "Email password update entry--: p"
	F_terminal_show "Reset script to default------: r"
	F_terminal_show "Disable script---------------: d"
	F_terminal_show "Toggle terminal color on/off-: c"
	F_terminal_show "Uninstall script-------------: i"
	F_terminal_show "Backup/Restore settings menu-: b"
	if [ "$update_auto_check_avail" != 'none' ] && [ "$update_auto_check_avail" != 'hotfix' ] ; then
			printf "%b Update script----------------: u %b   Update available to version $update_auto_check_avail %b\n" "$tTERMHASH" "$tGRN" "$tCLR"
	elif [ "$update_auto_check_avail" != 'none' ] && [ "$update_auto_check_avail" = 'hotfix' ] ; then
		printf "%b Update script----------------: u %b   Hotfix available! %b\n" "$tTERMHASH" "$tGRN" "$tCLR"
	else
		F_terminal_show "Force update check-----------: f"
	fi
	F_terminal_show "About script-----------------: a"
	F_terminal_show "Exit-------------------------: e"
	F_terminal_padding ;F_terminal_check "Selection : " ; read -r selection
	printf "%b" "$tBACK$tERASE"
	case $selection in
		1) F_build_settings ;;
		2) until F_opt_custom ; do : ; done ; F_menu_exit ;;
		3) until F_opt_subject ; do : ; done ; F_menu_exit ;;
		s|S) until F_opt_script ; do : ; done ; F_menu_exit ;;
		4) F_opt_sample ;;
		5) passed_options='test' ;;   #  fall through to settings test then check arg
		6) F_opt_error ;;
		7) F_opt_count ;;
		a|A) F_opt_about ;;
		b|B) F_opt_backup_restore ;;
		c|C) F_opt_color ;;
		d|D) F_opt_disable ;;
		e|E) F_clean_exit ;;
		f|F) F_web_update_check force ;;
		#i|I) F_opt_uninstall ;;
		m|M) F_opt_manual ;;
		p|P) until F_opt_pswd ; do : ; done ; F_menu_exit ;;
		r|R) F_opt_reset ;;
		u|U) if [ "$update_auto_check_avail" != 'none' ] ; then   # option only avail if we found an update
				F_local_script_update
			else
				printf "%b %s is an invalid entry, any key to retry" "$tCHECKFAIL" "$selection"
				read -rsn1 invalidwait ;return 1
			fi ;;
		v|V) F_status view && F_menu_exit ;;
		*) [ -n "$selection" ] && printf "%b %s is an invalid entry, any key to retry" "$tCHECKFAIL" "$selection" && read -rsn1 invalidwait && return 1 ;;
	esac
}   ### main menu

###################################################################################################
################### Start - check ntp/time set/lock check/options check/lock create ###############
###################################################################################################
F_lock_create() {
	touch "$script_lock"
	{
	echo "wicens lock file"
	echo "$$"
	echo "$(/bin/date +%s)"
	echo "Lockfile for $script_name_full to prevent duplication"
	echo "Created $run_date"
	echo "Option : $passed_options "
	} >> "$script_lock"
} ### lock_create

# first script commands ###########################################################################
# ntp time wait
ntp_lock='/tmp/wicens_ntp.lock'
[ -f "$ntp_lock" ] && exit 0   # script already running waiting on NTP sync
if [ "$(nvram get ntp_ready)" -ne 1 ] ; then
	echo "$$" > "$ntp_lock" ; echo "wicens ntp lock" >> "$ntp_lock"
	ntp_wait_time=0
	F_log_show "NTP is not synced, waiting upto 600 seconds (10min) checking every second for NTP sync...   CTRL+C to exit"
	while [ "$(nvram get ntp_ready)" -ne 1 ] && [ "$ntp_wait_time" -lt 600 ] ; do
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
run_date="$(/bin/date +%c)"
run_epoch="$(/bin/date +%s)"
[ -n "$update_auto_check_epoch" ] && update_diff=$((run_epoch - update_auto_check_epoch)) || update_diff="$update_check_period"
update_rem=$((update_check_period - update_diff))

# lock check
script_lock='/tmp/wicens.lock'
script_mail_lock='/tmp/wicenssendmail.lock'
if [ -f "$script_lock" ] ; then
	locked_process="$(sed -n '2p' $script_lock)"   # pid
	process_created="$(sed -n '5p' $script_lock)"   # started on
	process_calledby="$(sed -n '6p' $script_lock)"  # created by
	process_time="$(sed -n '3p' $script_lock)"   # started seconds time
	lock1_diff_time="$(($(/bin/date +%s) - process_time))"
	F_terminal_header
	F_terminal_show "wicens failed to start"
	F_terminal_padding

	if [ -f "$script_mail_lock" ] ; then   # if wicens.lock doesnt exist neither should this, so only check this if first lock exists
		# calculate wicenssendmail.lock age limit
		loop_count_run=3		# check user_message_intervals and convert to seconds to check lock file age limits
		while [ "$loop_count_run" != '0' ] ; do
			newval="$(eval 'echo "${user_message_interval_'"$loop_count_run"'}"')"   # reading variable user_message_interval_1/2/3
			interval_type="$(echo "$newval" | sed -e "s/^.*\(.\)$/\1/")"	# strip second,minute,hour,day
			time_period="$(echo "$newval" | sed 's/[a-z]$//')"	# strip time value
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
		if [ "$(($(/bin/date +%s) - $(sed -n '4p' $script_mail_lock)))" -gt "$check_lock_count" ] ; then
			rm -f "$script_mail_lock"
			printf "%b from %s on %s\n" "$tTERMHASH" "$process_calledby" "$process_created"
			F_terminal_show "Removed stale wicenssendmail.lock file, any key to continue"
			F_log "NOTICE - Removed stale wicenssendmail.lock file started by $process_calledby on $process_created"
			[ "$passed_options" = 'manual' ] && read -rsn1 "staleremove"
		else
			if [ ! -d "/proc/$locked_process" ] ; then # process that created doesnt exist
				F_log_show "CRITICAL ERROR - wicens.lock and wicenssendmail.lock exist"
				F_log "CRITICAL ERROR - files $process_created by $process_calledby"
				printf "%b created %s by %s\n" "$tTERMHASH" "$process_created" "$process_calledby"
				F_log_show "Process that created doesn't exist, script was killed during Email send"
				rm -f "$script_lock"
				rm -f "$script_mail_lock"
				F_log_show "CRITICAL ERROR - Removed dead wicens.lock and wicenssendmail.lock files"
				[ "$passed_options" = 'manual' ] && F_terminal_check "Any key to continue" && read -rsn1 "staleremove"
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
			[ "$passed_options" = 'manual' ] && read -rsn1 "lock_notify_wait"
	else
		if [ "$lock1_diff_time" -gt 330 ] ; then   # based on if internet is down google attempts is 5 mins
			F_log_show "Lock file exists for running process older than 5 mins but not sending Email"
			printf "%b Killing process %s and deleting lock file %s" "$tTERMHASH" "$locked_process" "$process_created"
			F_log "Killing old process $locked_process started by $process_calledby and deleting lock file $process_created"
			kill "$locked_process"
			rm -f "$script_lock"
			F_log_show "Done, killed stale process, removed lock file"
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

# check args start run create locks
case $passed_options in
	'cron'|'wancall'|'test') F_lock_create ;;   # create lock and fall through to auto run
	'remove') F_opt_remove ;;   # manually remove lock files
	'manual') F_lock_create ; from_menu='no' ; until F_main_menu ; do : ; done ;;   # run from command line, from_menu prevents until loop recheck for update
	*) printf "\n%b wicens.sh %b is an invalid option\n\n" "$tTERMHASH" "$tRED$passed_options$tCLR" && exit 0 ;;
esac

###################################################################################################
# configured script auto run below ################################################################
# cleanup
[ -f "$mail_file" ] && rm -f "$mail_file"   # if email message still exists somehow, cleanup
[ -f "$script_mail_lock" ] && rm -f "$script_mail_lock"   # if mail lock exists somehow, cleanup

F_ready_check   # check if settings are valid before continuing to test/cron/wancall

if [ "$passed_options" = 'test' ] ; then
	F_opt_test
elif [ "$passed_options" = 'cron' ]; then
	new_cron_count="$((cron_run_count + 1))"
	sed -i "1,/cron_run_count=.*/{s/cron_run_count=.*/cron_run_count=$new_cron_count/;}" "$config_src"
	sed -i "1,/last_cron_run=.*/{s/last_cron_run=.*/last_cron_run='$run_date'/;}" "$config_src"
	# below is all Sunday logging
	weekly_wancall_total=$((wancall_run_count - last_wancall_log_count))   # log msg count
	if [ "$(/bin/date +%u)" = '7' ] && [ "$log_cron_msg" = '0' ] ; then
		F_log "Started successfully by wan-event connected $weekly_wancall_total times in the last week, $wancall_run_count times since install"
		[ -n "$last_Wancall_run" ] && F_log "Last wan-event connected trigger $last_wancall_run"
		F_log "Recorded $ip_change_count IP change(s) since install"
		sed -i "1,/last_wancall_log_count=.*/{s/last_wancall_log_count=.*/last_wancall_log_count=$wancall_run_count/;}" "$config_src"
		sed -i "1,/log_cron_msg=.*/{s/log_cron_msg=.*/log_cron_msg=1/;}" "$config_src"  # set to not log every cron
	fi
	if [ "$(/bin/date +%u)" = '1' ] && [ "$log_cron_msg" = '1' ] ; then
		sed -i "1,/log_cron_msg=.*/{s/log_cron_msg=.*/log_cron_msg=0/;}" "$config_src"  # monday reset to log again sunday
	fi
	# end of Sunday logging
	if ! F_do_compare ; then
		F_send_mail
	fi
elif [ "$passed_options" = 'wancall' ] ; then
	new_wancall_count="$((wancall_run_count + 1))"
	F_log "Started by 'wan-event connected' trigger... sleeping 30secs before running IP compare"
	sed -i "1,/wancall_run_count=.*/{s/wancall_run_count=.*/wancall_run_count=$new_wancall_count/;}" "$config_src"
	sed -i "1,/last_wancall_run=.*/{s/last_wancall_run=.*/last_wancall_run='$run_date'/;}" "$config_src"
	sleep 30
	if ! F_do_compare ; then
		F_send_mail
	fi
fi
