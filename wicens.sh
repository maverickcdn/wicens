#!/bin/sh
################################################################################
#                                 _                                            #
#                      _      __ (_)_____ ___   ____   _____                   #
#                     | | /| / // // ___// _ \ / __ \ / ___/                   #
#                     | |/ |/ // // /__ /  __// / / /(__  )                    #
#                     |__/|__//_/ \___/ \___//_/ /_//____/                     #
#                                                                              #
#                    WAN IP Change Email Notification Script                   #
#                                                                              #
################################################################################
# Thanks to all who contribute(d) at SNBforums, pieces of your code are here ;)
# written by maverickcdn
# github.com/maverickcdn/wicens
# SNBforums thread https://www.snbforums.com/threads/wicens-wan-ip-change-email-notification-script.69294/
# found in amtm thanks to @thelonelycoder
# shellcheck disable=SC2039,SC2183,SC2104,SC1090,SC2154,SC2034
# hex expr   menuprintf   continuefunc   constantsource   unassvar   unusedvar

[ "$1" = 'debug' ] && shift && set -x
export PATH="/sbin:/bin:/usr/sbin:/usr/bin:$PATH"
start_time="$(awk '{print $1}' < /proc/uptime)"   # for calc menu load time in ms
printf '\033[?7l'   # disable terminal word wrap

# START ###############################################################################################################
script_version='4.13'
script_ver_date='Dec 4 2025'
current_core_config='4.3'   # version of core config (F_default_update_create)
current_user_config='4.1'   # version of user config (F_default_user_create)

script_name="$(basename "$0")"
script_name_full="/jffs/scripts/$script_name"
script_dir='/jffs/addons/wicens'
script_git_src='https://raw.githubusercontent.com/maverickcdn/wicens/master/'
run_option="$1"
[ -z "$1" ] && run_option='tty'   # used to show tty vs cron/test/wancall/fwupdate/send run
config_src="${script_dir}/wicens_user_config.wic"   # user settings
update_src="${script_dir}/wicens_update_conf.wic"   # core config file
history_src="${script_dir}/wicens_wan_history.wic"   # historical wan ip change file
script_backup_file="${script_dir}/wicens_user_config.backup"   # user settings backup
history_src_backup="${script_dir}/wicens_history_src.backup"   # historical wan ip change file backup
reboot_email='/tmp/wicens_rebootmail.txt'   # reboot notification mail text
fw_email='/tmp/wicens_fwmail.txt'   # firmware update notification mail text
update_email='/tmp/wicens_updatemail.txt'   # script update notification mail text
wanip_email='/tmp/wicens_wanipemail.txt'   # wanip change notification mail text
mail_log="${script_dir}/wicens_email.log"   # log file for sendmail/curl
script_lock="/tmp/wicens_lock.$run_option"   # script temp lock file by argument
internet_lock="/tmp/wicens_internetlock.$run_option"   # internet check lock, prevents killing processes waiting for internet
wicens_send_retry='/tmp/wicens_send.retry'   # retry count file for send option
wicens_send_copy='/tmp/wicens_user_email.txt'   # backup of email for send option in retries
wicens_update_retry='/tmp/wicens_update.retry'   # retry count file for script update notification
wicens_fw_retry='/tmp/wicens_fw.retry'   # retry count file for fw update notification
wicens_wanip_retry='/tmp/wicens_wanip.retry'   # retry count file for wan ip change notification
wicens_reboot_retry='/tmp/wicens_reboot.retry'   # retry count file for reboot notification
cred_loc="${script_dir}/.wicens_cred.enc"
cred_loc_bak="${cred_loc}bak"
amtm_email_conf='/jffs/addons/amtm/mail/email.conf'
amtm_cred_loc='/jffs/addons/amtm/mail/emailpw.enc'
amtm_d='L3Vzci9zYmluL29wZW5zc2wgMj4vZGV2L251bGwgYWVzLTI1Ni1jYmMgLXBia2RmMiAtZCAtaW4gL2pmZnMvYWRkb25zL2FtdG0vbWFpbC9lbWFpbHB3LmVuYyAtcGFzcyBwYXNzOmRpdGJhYm90LGlzb2kK'
user_d='L3Vzci9zYmluL29wZW5zc2wgZW5jIC1tZCBzaGE1MTIgLXBia2RmMiAtYWVzLTI1Ni1jYmMgLWQgLWEgLXBhc3MgcGFzczoiJChGX252cmFtIGJvYXJkbnVtIHwgL2Jpbi9zZWQgcy86Ly9nKSIK'
user_e='L3Vzci9zYmluL29wZW5zc2wgZW5jIC1tZCBzaGE1MTIgLXBia2RmMiAtYWVzLTI1Ni1jYmMgLWEgLXNhbHQgLXBhc3MgcGFzczoiJChGX252cmFtIGJvYXJkbnVtIHwgL2Jpbi9zZWQgcy86Ly9nKSIgfCB0ciAtZCAiXG4iCg=='
ip_regex='([0-9]{1,3}[\.]){3}[0-9]{1,3}'
current_wan_ip=''
building_settings=0
test_mode=0
sample_email=0
from_menu=0
config_updated=0
# in script and user configs 0=disabled 1=enabled

# SCRIPT MISC #########################################################################################################
F_git_get() {
	case "$1" in
		'file') curl -fsL --retry 2 --retry-delay 3 --connect-timeout 3 ${script_git_src}${script_name} ;;
		'download') if curl -fsL --retry 2 --retry-delay 3 --connect-timeout 3 ${script_git_src}${script_name} -o /jffs/scripts/wicens.sh ; then F_chmod "$script_name_full" ; else return 1 ; fi ;;
		'changelog') curl -fsL --retry 2 --retry-delay 3 --connect-timeout 3 ${script_git_src}CHANGELOG.md ;;
		'hotfix') F_git_get changelog | sed -n "/^## $git_version/,/^## /p" | head -n -1 | sed 's/## //g' ;;
		'update') F_git_get changelog | sed -n "/^## $git_version/,/^## $script_version/p" | head -n -1 | sed 's/## //g' ;;
	esac
	return 0
} # git_get

F_ctrlc() {
	F_terminal_check_fail "Script interrupted..."
	run_option='interrupt'
	F_clean_exit
} # CTRL+C catch with trap

trap F_ctrlc INT HUP   # trap ctrl+c exit clean

F_replace_var() { sed -i "1,/${1}=.*/{s/${1}=.*/${1}=\'${2}\'/;}" "$3" ;}   # 1=var to change 2=new var string 3=file
F_chmod() { [ ! -x "$1" ] && chmod a+rx "$1" ;}   # file permissions
F_crlf() { if grep -q $'\x0D' "$1" 2> /dev/null ; then dos2unix "$1" && F_log_terminal_ok "$(F_printfstr "$1" | awk -F/ '{print $(NF)}') contained CRLF, executed dos2unix" ; fi ;}   # crlf
F_nvram() { nvram get "$1" ;}
F_printf() { printf '%b\n' "$1" ;}   # printf recognize escape strings
F_printfstr() { printf '%s\n' "$1" ;}   # printf raw string
F_printfp() { F_printfstr "$1" | /bin/sed 's@.*@<p style="color: black; font-family: monospace; font-size: 13px; line-height: 1.5;">&</p>@' ;}   # HTML email msg encapsulate line
F_printfpre() { F_printfstr "$1" | /bin/sed 's@.*@<pre style="color: black; font-family: monospace; font-size: 13px; line-height: 1.5;">&</pre>@' ;}   # HTML email msg encapsulate line preserve whitespace
F_date() {
	case "$1" in
		'r') date -R ;;   # RFC
		's') date +'%s' ;;  # seconds
		'f') date +'%b %d %Y %T' ;;   # abbr.mnth day year h:m:s
	esac
} # date

# TERMINAL/LOGGING ####################################################################################################
F_terminal_show() { F_printf "$tTERMHASH $1" ;}   # [~~~~]
F_terminal_padding() { F_printfstr '' ;}   # blank line
F_terminal_separator() { F_printfstr '--------------------------------------------------------------------------------' ;}   # 80 column
F_terminal_erase() { printf '%b' "$tBACK$tERASE" ;}   # erase previous line
F_terminal_entry() { printf '%b' "$tTERMHASH $1" ;}   # [~~~~] no new line
F_terminal_check() { printf '%b' "$tCHECK $1" ;}   # [WAIT] no new line
F_terminal_check_ok() { F_printf "\r${tERASE}${tCHECKOK} $1" ;}   # [ OK ]
F_terminal_check_fail() { F_printf "\r${tERASE}${tCHECKFAIL} $1" ;}   # [FAIL]
F_term_waitdel() { printf '%b' "${tERASE}${tCHECK} $1 \r" ;}   # used in countdowns (line re-write)
F_status_grn() { F_terminal_show "$(printf "%s%s|\n" "$1" "$(printf '%*s' "$((35 - ${#1}))" | tr ' ' '-')") ${tGRN}${2}${tCLR}" ;}   # status enabled custom text
F_status_enabled() { F_terminal_show "$(printf "%s%s|\n" "$1" "$(printf '%*s' "$((35 - ${#1}))" | tr ' ' '-')") ${tGRN}Enabled${tCLR}" ;}   # status Enabled
F_status_pass() { F_terminal_show "$(printf "%s%s|\n" "$1" "$(printf '%*s' "$((35 - ${#1}))" | tr ' ' '-')") ${tGRN}Passed${tCLR}" ;}   # status pass
F_status_fail() { F_terminal_show "$(printf "%s%s|\n" "$1" "$(printf '%*s' "$((35 - ${#1}))" | tr ' ' '-')") ${tRED}Failed${tCLR}"  ;}   # status fail
F_status_disabled() { F_terminal_show "$(printf "%s%s|\n" "$1" "$(printf '%*s' "$((35 - ${#1}))" | tr ' ' '-')") ${tRED}Disabled${tCLR}"  ;}   # status Disabled
F_menu_enabled() { F_terminal_show "$1 ${tGRN}Enabled${tCLR}" ;}   # menu enabled
F_menu_disabled() { F_terminal_show "$1 ${tRED}Disabled${tCLR}" ;}   # menu disabled
F_edit() { F_terminal_show "$1 ${tGRN}${2}${tCLR}" ;}   # edit menu
F_terminal_warning() { printf '%b%48s\n%48s\n%48s%b\n\n' "$tRED" "#################" "#    WARNING    #" "#################" "$tCLR" ;}   # terminal warning
F_fail_entry() { F_terminal_check_fail "Invalid entry, any key to retry" && read -rsn1 && F_terminal_erase && continue ;}   # terminal input invalid entry
F_log() {
	case "$script_log" in
		'1')
			printf '%s' "$(F_date f) " >> "$script_log_loc"
			logger -st "wicens[$$]" "$(F_printfstr "${run_option} : $1" )" 2>> "$script_log_loc"
		;;
		*) logger -t "wicens[$$]" "$(F_printfstr "${run_option} : $1" )"
		;;
	esac
} # logging
F_log_show() { F_log "$1" ; F_terminal_show "$1" ;}   # log and print formatted
F_log_terminal_ok() { F_terminal_check_ok "$1" ; F_log "$1" ;}   # log [ OK ]
F_log_terminal_fail() { F_terminal_check_fail "$1" ; F_log "$1" ;}   # log [FAIL]
F_email_seperator() {
	if [ "$sample_email" = 0 ]
	then F_printfstr "<hr style='border: none; border-top: 2px dashed black;'>"
	else F_printfstr '----------------------------------------------------------'   # 58 column
	fi
} # email_seperator

#requires being passed a line # for head to terminate on
F_terminal_entry_header() {
	build_entry=1   # for F_status
	cut_line=$((${1} + 2))   # add to passed line to account for top 2 lines of status page
	F_terminal_header
	F_status | head -n "$cut_line" | tail -n "$((cut_line - 2))"   # remove top two lines of status page
	F_terminal_separator
	F_terminal_padding
} # terminal_entry_header

F_terminal_color() {
	case "$opt_color" in
		0)
			tGRN=''
			tRED=''
			tPUR=''
			tYEL=''
			tCLR=''
		;;

		1)
			tGRN="\033[1;32m"
			tRED="\033[1;31m"
			tPUR="\033[1;95m"
			tYEL="\033[1;93m"
			tCLR="\033[0m"
		;;
	esac

	tERASE="\033[2K"
	tBACK="\033[1A"
	tCHECK="[${tYEL}WAIT${tCLR}]"
	tCHECKOK="[${tGRN} OK ${tCLR}]"
	tCHECKFAIL="[${tRED}FAIL${tCLR}]"
	tTERMHASH="[${tPUR}~~~~${tCLR}]"
} # terminal_color

F_confirm() {
	F_terminal_padding
	while true ; do
		case "$1" in
			'correct') F_terminal_check "Is ${tGRN}${2}${tCLR} correct? | Y||y or N||n " ;;
			*) F_terminal_check "$1 | Y||y or N||n " ;;
		esac

		read -rsn1 ynentry
		case "$ynentry" in
			Y|y) return 0 ;;
			N|n) return 1 ;;
			E|e) F_terminal_check_fail "Cancelled, exit selected" ; F_menu_exit ;;
			*) F_fail_entry ;;
		esac
		break
	done
} # confirm

F_wait() {
	F_terminal_padding
	wait_time="$1"
	while [ "$wait_time" -ne '0' ] ; do
		F_term_waitdel "Loading menu in $wait_time secs... any key to skip "
		wait_time=$((wait_time - 1))
		waiting=zzz
		read -rsn1 -t1 waiting
		[ ${#waiting} -le 1 ] && break
	done
} # menu_wait

# MISC ################################################################################################################

F_random_num() {
	if [ -z "$1" ] ; then random_max='30' ; else random_max="$1" ; fi
	# pull uptime (w/ millisecond) as seed # for rng
	awk -v min=1 -v max="$random_max" -v seed="$(awk '{print $1}' < /proc/uptime | tr -d '.')" 'BEGIN{srand(seed); print int(min+rand()*(max-min+1))}'
} # random_num

F_private_ip() {
    # RFC 1918 defines private IP address ranges
    # 10.0.0.0/8
    # 172.16.0.0/12
    # 192.168.0.0/16
    # Also including 169.254.0.0/16 (used for Automatic Private IP Addressing)
	grep -Eq '^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\.|^169\.254\.'
} # private_ip  as per ChatGPT

F_cgnat_ip(){
	# test if the input is a RFC 6598 address for CGNAT
	grep -Eq '^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
} # cgnat as per ChatGPT

F_uptime() {
	router_uptime="$(awk '{print $1}' < /proc/uptime | cut -d'.' -f1)"
	uptime_pretty="$(printf '%3dd %2dh %2dm %2dsec\n' $((router_uptime/86400)) $((router_uptime%86400/3600)) $((router_uptime%3600/60)) $((router_uptime%60)))"
} # uptime

# SCRIPT CONTROL ######################################################################################################

F_clean_exit() {
	# reset terminal word wrap
	printf '\033[?7h'

	# if ctrlc kill any child process put in background (F_time-F_web_update_check)
	[ "$run_option" = 'interrupt' ] && [ -n "$child_pid" ] && { for pid in $child_pid ; do kill "$child_pid" 2>/dev/null ; done ; }

	# save last seen uptime
	F_uptime
	if [ "$router_uptime" -gt 600 ] && [ -f "$update_src" ] ; then
		F_replace_var router_reboot_uptime "$router_uptime" "$update_src"   # wait 10mins before saving uptime, if reboot notify enabled need to capture last known uptime
		F_replace_var router_reboot_downtime "$(F_date s)" "$update_src"   # save last seen current time to compare after reboot to estimate down time
	fi

	# pre lock removal restarts
	[ "$1" = 'reload' ] && exec sh "$script_name_full" reload

	# amtm style exit
	if [ "$run_option" = 'tty' ] ; then
		if [ "$1" != 'error' ] && [ "$1" != 'reset' ] ; then
			F_terminal_header exit  # amtm style exit, prevent other call types having terminal messages cleared
		fi
	fi

	# remove all potential locks
	for lock_to_remove in "$script_lock" "$ntp_lock" "$internet_lock" ; do
		[ -f "$lock_to_remove" ] && rm -f "$lock_to_remove" && [ "$1" != 'reset' ] &&  F_terminal_check_ok "Removed ${lock_to_remove} lock file"
	done

	if [ -f "$script_lock" ] ; then
		if [ "$$" != "$(sed -n '2p' "$script_lock")" ] ; then
			F_log_terminal_ok "Lock file still present but not from this process..."
		else
			F_log_terminal_fail "Critical error - Failed to remove lock file"
			exit 1
		fi
	fi

	if [ "$1" = 'reset' ] ; then
		exec sh "$script_name_full"   # restart the script completely
	elif [ "$1" = 'fail' ] || [ "$1" = 'error' ] ; then
		exit 1   # for forwarder calls from other scripts
	fi

	F_printf "[${tGRN}EXIT${tCLR}] ${tYEL}Goodbye :) ${tCLR}"
	F_terminal_padding
	exit 0
} # clean_exit

F_menu_exit() {
	F_terminal_padding
	F_terminal_check "Any key to return to the Main Menu - E||e to exit to prompt"

	read -rsn1 exitwait
	case "$exitwait" in
		E|e) F_terminal_check_ok "Exiting." ; F_clean_exit ;;
		*) F_clean_exit reload ;;
	esac
} # menu_exit

# FIRMWARE CHECK ######################################################################################################

F_firmware_check() {
	F_fw_valid_version() {
		if [ -z "$build_full" ] ; then
			F_terminal_header
			F_log_terminal_fail "Could not determine your firmware version from nvram"
			rm -r "$script_dir" 2> /dev/null
			F_terminal_check "Any key to exit..."
			read -rsn 1
			F_clean_exit
		fi

		[ "$(F_nvram firmver)" = '3.0.0.6' ] && return 0

		case "$build_no" in
			'386'|'388') return 0 ;;
			'384') [ "$build_sub" -ge 15 ] && return 0 ;;
			'374') [ "$john_sub" -ge 48 ] && return 0 ;;
			*)
				F_terminal_header
				F_log_terminal_fail "Sorry this version of firmware is not compatible, please update to 384.15 or newer, or 374 LTS release 48 or newer to utilize this script"
				F_terminal_padding
				rm -r "$script_dir" 2> /dev/null
				F_clean_exit
			;;
		esac
	} # fw_valid_version

	F_fw_write() {
		pulled_device_name="$(F_nvram lan_hostname)"
		pulled_lan_name="$(F_nvram lan_domain)"
		device_model="$(F_nvram odmpid)"
		lan_addr="$(F_nvram lan_ipaddr)"
		[ -z "$device_model" ] && device_model="$(F_nvram productid)"

		case "$build_no" in
			'374') F_replace_var fw_build_sub "$john_sub" "$update_src" ;;
			*) F_replace_var fw_build_sub "$build_sub" "$update_src" ;;
		esac

		F_replace_var fw_build_full "${build_no}.${build_sub}_${build_extend}" "$update_src"
		F_replace_var fw_pulled_device_name "$pulled_device_name" "$update_src"
		F_replace_var fw_pulled_lan_name "$pulled_lan_name" "$update_src"
		F_replace_var fw_device_model "$device_model" "$update_src"
		F_replace_var fw_build_no "$build_no" "$update_src"
		F_replace_var fw_build_extend "$build_extend" "$update_src"
		F_replace_var fw_lan_addr "$lan_addr" "$update_src"
		F_replace_var fw_sw_mode "$software_mode" "$update_src"
		source "$update_src"

		case "$1" in
			'fwupdate')
				from_menu=1
				F_terminal_header
				F_log_show "Found new firmware version installed on router"
				F_log_terminal_ok "core config v${update_settings_version} updated for new fw version ${build_full}_${build_extend}"
				F_replace_var fw_notify_state 0 "$config_src"   # reset Email notification after upgrading
				F_menu_exit
			;;

			*)
				case "$config_updated" in
					1)
						# for integrity_check updates
						F_log_terminal_ok "core config v${update_settings_version} updated with router firmware information"
					;;

					*)
						from_menu=1
						installer=1
						F_terminal_header
						F_log "HI - wicens the WAN IP change EMAIL notification script has been installed"
						F_printf "[ ${tGRN}HI${tCLR} ] ${tYEL}===== Welcome to wicens the WAN IP change Email notification script =====${tCLR}"
						F_terminal_padding
						F_terminal_check_ok "Created $script_dir directory"
						F_terminal_check_ok "Created default user config v${current_user_config} for script v$script_version in $script_dir"
						F_terminal_check_ok "Created default core config v$current_core_config for script v$script_version in $script_dir"
						F_log_terminal_ok "Updated core config v${update_settings_version} with router firmware information"
						F_alias
						F_terminal_padding
						F_terminal_check "Any key to continue to Main Menu"
						read -rsn1
						F_clean_exit reset
					;;
				esac
			;;
		esac
	} # fw_write

	# only if we havent checked fw already in the last 10 mins
	if [ "$fw_nvram_check_diff" -gt "$max_fw_nvram_check" ] ; then
		# start of fw check
		# set fw vars check if written, check for update ##################################################################
		F_replace_var fw_nvram_check_epoch "$(F_date s)" "$update_src"
		build_full="$(F_nvram buildno)"
		build_no="$(F_printf "$build_full" | cut -f1 -d '.')"
		build_sub="$(F_printf "$build_full" | cut -f2 -d '.')"
		build_extend="$(F_nvram extendno)"
		software_mode="$(F_nvram sw_mode)"

		# initial firmware compatibility check, first run will be unpopulated
		if [ -z "$fw_build_no" ] || [ -z "$fw_build_sub" ] || [ -z "$fw_build_extend" ] || [ -z "$fw_build_full" ] ; then
			if F_fw_valid_version ; then
				# new install set install date
				[ -z "$install_date" ] && F_replace_var install_date "$(F_date f)" "$config_src"
				F_fw_write
				fw_init=1
			fi
		fi

		case "$fw_build_no" in
			'374')
				john_sub=${build_extend:0:2}
				[ "$johnsub" != "$fw_build_sub" ] && F_fw_write fwupdate
			;;

			# check if user has upgraded firmware and update config, saving to config avoids numerous nvram calls every run not from terminal
			*)
				[ "$build_no" != "$fw_build_no" ] || [ "$build_sub" != "$fw_build_sub" ] || [ "$build_extend" != "$fw_build_extend" ] && F_fw_write fwupdate
				[ "$fw_sw_mode" != "$software_mode" ] && F_replace_var fw_sw_mode "$software_mode" "$update_src"
			;;
		esac
	fi
	[ "$config_updated" = 1 ] && [ "$fw_init" != 1 ] && F_terminal_check_ok "core config firmware/router information current"
	return 0
} # firmware_check

# ALIAS ###############################################################################################################

F_alias() {
	case "$1" in
		'remove')
			if [ -f /jffs/configs/profile.add ] ; then
				if grep -Fq "alias wicens=" /jffs/configs/profile.add ; then
					sed -i "/alias wicens=/d" /jffs/configs/profile.add
					[ ! -s /jffs/configs/profile.add ] && rm -f /jffs/configs/profile.add
					F_log_terminal_ok "Removed alias from /jffs/configs/profile.add"
				else
					F_log_terminal_ok "No alias found in /jffs/configs/profile.add to remove"
				fi
			else
				F_log_terminal_ok "No alias found in /jffs/configs/profile.add to remove"
			fi
			return 0
		;;
	esac

	if [ ! -f /jffs/configs/profile.add ] ; then
		F_printfstr "alias wicens=\"/bin/sh ${script_name_full}\"   # added by wicens $(F_date r)" > /jffs/configs/profile.add
		F_log_terminal_ok "Created /jffs/configs/profile.add and added entry for wicens"
	elif ! grep -Fq "alias wicens=" /jffs/configs/profile.add ; then
		F_printfstr "alias wicens=\"/bin/sh ${script_name_full}\"   # added by wicens $(F_date r)" >> /jffs/configs/profile.add
		F_log_terminal_ok "Added alias in /jffs/configs/profile.add for wicens"
	fi
	return 0
} # alias   only checked on tty runs

# USER SETTINGS #######################################################################################################
#######################################################################################################################

F_default_user_create() {
	{
		F_printfstr "#!/bin/sh"
		F_printfstr "# wicens user config file"
		F_printfstr "build_settings_version='${current_user_config}'"
		F_printfstr "###########################################################"
		F_printfstr "saved_wan_ip="
		F_printfstr "saved_wan_date='never'"
		F_printfstr "saved_wan_epoch="
		F_printfstr "###########################################################"
		F_printfstr "# User config settings ####################################"
		F_printfstr "user_login_addr="
		F_printfstr "user_smtp_server="
		F_printfstr "user_from_addr="
		F_printfstr "user_send_to_addr="
		F_printfstr "user_send_to_cc="
		F_printfstr "user_msg_to='wicens user'"
		F_printfstr "user_email_from='wicens script'"
		F_printfstr "user_message_type="
		F_printfstr "user_custom_subject="
		F_printfstr "user_custom_subject_r="
		F_printfstr "user_custom_subject_f="
		F_printfstr "user_custom_subject_s="
		F_printfstr "user_custom_text="
		F_printfstr "user_custom_text_r="
		F_printfstr "user_custom_text_f="
		F_printfstr "user_custom_text_s="
		F_printfstr "user_custom_script="
		F_printfstr "user_custom_script_time="
		F_printfstr "###########################################################"
		F_printfstr "user_update_notification=0"
		F_printfstr "user_fw_update_notification=0"
		F_printfstr "user_reboot_notification=0"
		F_printfstr "user_wanip_notification=0"
		F_printfstr "user_wanip_monitor=0"
		F_printfstr "###########################################################"
		F_printfstr "last_cron_run='never'"
		F_printfstr "cron_run_count=0"
		F_printfstr "last_wancall_run='never'"
		F_printfstr "wancall_run_count=0"
		F_printfstr "last_wancall_log_count=0"
		F_printfstr "last_ip_change='never'"
		F_printfstr "ip_change_count=0"
		F_printfstr "install_date="
		F_printfstr "update_date='never'"
		F_printfstr "created_date='never'"
		F_printfstr "opt_color=1"
		F_printfstr "log_cron_msg=1"
		F_printfstr "amtm_import=0"
		F_printfstr "protocol='smtps'"
		F_printfstr "ssl_flag="
		F_printfstr "###########################################################"
		F_printfstr "# Created : $(F_date r)"
	} > "$config_src"

	F_log "Created default user config v${current_user_config} for v${script_version} in ${script_dir}"
} # create user config

F_default_update_create() {
	{
		F_printfstr "#!/bin/sh"
		F_printfstr "# wicens core config file"
		F_printfstr "update_settings_version='${current_core_config}'"
		F_printfstr "###########################################################"
		F_printfstr "fw_build_no="
		F_printfstr "fw_build_sub="
		F_printfstr "fw_build_extend="
		F_printfstr "fw_pulled_device_name="
		F_printfstr "fw_pulled_lan_name="
		F_printfstr "fw_device_model="
		F_printfstr "fw_build_full="
		F_printfstr "fw_lan_addr="
		F_printfstr "fw_sw_mode="
		F_printfstr "###########################################################"
		F_printfstr "update_avail='none'"
		F_printfstr "update_cron_epoch=0"
		F_printfstr "update_notify_state=0"
		F_printfstr "fw_notify_state=0"
		F_printfstr "reboot_notify_state=0"
		F_printfstr "router_reboot_uptime="
		F_printfstr "router_reboot_downtime="
		F_printfstr "fw_nvram_check_epoch=0"
		F_printfstr "# USER CAN EDIT BELOW SETTINGS ###########################"
		F_printfstr "stun_max=3   # max number of stun lookup retries"
		F_printfstr "getrealip_max=3   # max number of getrealip.sh retries"
		F_printfstr "update_period=172800   # period between script update checks  default:172800 (48 hrs)"
		F_printfstr "wan_history_count=5   # number of historcal IPs in Email message  default:5"
		F_printfstr "retry_wait_period=14400   # period between failed email retries  default:14400 (4 hrs)"
		F_printfstr "max_email_retry=3   # max cron run retries before waiting for retry_period  default:3"
		F_printfstr "cron_check_freq=11   # minutes between cron checks  default:11 (mins)"
		F_printfstr "cron_string=\"*/\${cron_check_freq} * * * * ${script_name_full} cron\""
		F_printfstr "cron_option=1   # run cron  default:1 (on)"
		F_printfstr "script_log=1   # independent wicens logging  default:1 (on)"
		F_printfstr "script_log_loc=\"${script_dir}/wicens.log\"   # script independent log  default:/jffs/addons/wicens/wicens.log"
		F_printfstr "user_script_log=\"${script_dir}/user_script.log\"   # user custom script log location"
		F_printfstr "wan_event_wait=40   # sleep before compare after wan-event call  default:40"
		F_printfstr "reboot_notify_wait=20   # sleep before reboot notify services-start call  default:20 (secs)"
		F_printfstr "max_fw_nvram_check=600   # fw checks to nvram only every 10 minutes with tty  default:600"
		F_printfstr "dual_wan_check=1   # getrealip abort if dual wan enabled  default:1"
		F_printfstr "###########################################################"
		F_printfstr "# add or change list of test sites in below function for internet test (9 max)"
		F_printfstr "F_test_sites() {"
		F_printfstr "	F_printfstr \"google.com\""
		F_printfstr "	F_printfstr \"bing.com\""
		F_printfstr "	F_printfstr \"yahoo.com\""
		F_printfstr "	F_printfstr \"github.com\""
		F_printfstr "	F_printfstr \"asus.com\""
		F_printfstr "	F_printfstr \"sourceforge.net\""
		F_printfstr "	F_printfstr \"snbforums.com\""
		F_printfstr "	F_printfstr \"wikipedia.org\""
		F_printfstr "}"
		F_printfstr "###########################################################"
		F_printfstr "F_stun_servers() {"
		F_printfstr "    F_printfstr \"stun.l.google.com:19302\""
		F_printfstr "    F_printfstr \"stun1.l.google.com:19302\""
		F_printfstr "    F_printfstr \"stun2.l.google.com:19302\""
		F_printfstr "    F_printfstr \"stun3.l.google.com:19302\""
		F_printfstr "    F_printfstr \"stun4.l.google.com:19302\""
		F_printfstr "}"
		F_printfstr "###########################################################"
		F_printfstr "# use wicens main menu for editing email subject lines"
		F_printfstr "wan_subject=\"WAN IP has changed on ASUS router \${fw_device_model} \${fw_pulled_device_name}\""
		F_printfstr "reboot_subject=\"ASUS router \${fw_device_model} \${fw_pulled_device_name} has rebooted\""
		F_printfstr "firmware_subject=\"ASUS router \${fw_device_model} \${fw_pulled_device_name} has Firmware Update available, version \${new_fw_ver_pretty}\""
		F_printfstr "script_subject=\"Update available for wicens script on ASUS router \${fw_device_model} \${fw_pulled_device_name}\""
		F_printfstr "###########################################################"
		F_printfstr "# Created : $(F_date r)"
	} > "$update_src"

	F_log "Created default core config v${current_core_config} for v${script_version} in ${script_dir}"
} # create current_core

F_user_settings() {
	[ ! -d "$script_dir" ] && mkdir "$script_dir" && F_log "Welcome to wicens - created $script_dir directory"
	[ ! -f "$update_src" ] && F_default_update_create && F_chmod "$update_src"
	[ ! -f "$config_src" ] && F_default_user_create && F_chmod "$config_src"

	source "$config_src"   # source user config file
	source "$update_src"   # source script config file

	[ -n "$user_custom_subject" ] && user_custom_subject_decoded="$(F_printfstr "$user_custom_subject" | /usr/sbin/openssl base64 -d)"
	[ -n "$user_custom_subject_r" ] && user_custom_subject_decoded_r="$(F_printfstr "$user_custom_subject_r" | /usr/sbin/openssl base64 -d)"
	[ -n "$user_custom_subject_f" ] && user_custom_subject_decoded_f="$(F_printfstr "$user_custom_subject_f" | /usr/sbin/openssl base64 -d)"
	[ -n "$user_custom_subject_s" ] && user_custom_subject_decoded_s="$(F_printfstr "$user_custom_subject_s" | /usr/sbin/openssl base64 -d)"
	[ -n "$user_custom_text" ] && user_custom_text_decoded="$(F_printfstr "$user_custom_text" | /usr/sbin/openssl base64 -d)"
	[ -n "$user_custom_text_r" ] && user_custom_text_r_decoded="$(F_printfstr "$user_custom_text_r" | /usr/sbin/openssl base64 -d)"
	[ -n "$user_custom_text_f" ] && user_custom_text_f_decoded="$(F_printfstr "$user_custom_text_f" | /usr/sbin/openssl base64 -d)"
	[ -n "$user_custom_text_s" ] && user_custom_text_s_decoded="$(F_printfstr "$user_custom_text_s" | /usr/sbin/openssl base64 -d)"
	[ -n "$user_custom_script" ] && user_custom_script_decoded="$(F_printfstr "$user_custom_script" | /usr/sbin/openssl base64 -d)"

	case "$user_custom_script_time" in
		i) user_script_call_time='immediate' ;;
		w) user_script_call_time='wait' ;;
	esac

	case "$run_option" in
		'tty')
			fw_nvram_check_diff="$(($(F_date s) - fw_nvram_check_epoch))"
			F_terminal_color   # load user terminal settings
			F_integrity_check   # check config file status
		;;
	esac

	F_settings_test   # sets vars for valid config, enabled options etc

	original_wan_ip="$(grep -F 'saved_wan_ip' 2> /dev/null < "$config_src" | grep -Eo "$ip_regex")"
	original_wan_date="$(grep -F 'saved_wan_date' 2> /dev/null < "$config_src" | cut -d'=' -f2 | tr -d "'")"
	original_wan_epoch="$(grep -F 'saved_wan_epoch' 2> /dev/null < "$config_src" | cut -d'=' -f2 | tr -d "'")"

	# update_cron_epoch comes from core config (default=0) update_diff used in status and (time remaining to sched check) if enabled script updates
	if [ "$update_cron_epoch" -gt 0 ]
	then update_diff=$((run_epoch - update_cron_epoch))
	else update_diff=$((update_period + 1))
	fi
} # user settings

# MENU OPTIONS ########################################################################################################
#######################################################################################################################

F_opt_about() {
	clear
	{   # start of | more
		F_printfstr "	WICENS - WAN IP Change Email Notification Script                          " ; F_printfstr ''

		F_printfstr "This script when configured has the ability to send Email notifications for  "
		F_printfstr "Option 3 - WAN IP Change (IPv4 only,DualWAN disabled)                        "
		F_printfstr "Option 4 - Router reboot events                                              "
		F_printfstr "Option 5 - Firmware Updates (runs with built-in firmware notification check) "
		F_printfstr "Option 6 - Script Updates (checks every 48hrs when enabled)                  "
		F_printfstr "Script can call your own script when WAN IP change occurs (Option 7)         "
		F_printfstr "WAN IP change monitoring only Option 1 (auto enabled with Option 3)          "
		F_printfstr "Script can also be used to send your own generated Email files see           "
		F_printfstr "forwarder instructions further below                                         " ; F_printfstr ''

		F_printfstr "Supports GMail, Hotmail, Outlook, ISP based Email                            " ; F_printfstr ''

		F_printfstr "Supports AsusWRT-Merlin built-in amtm Email configuration import             " ; F_printfstr ''

		F_printfstr "Script will function in Double NAT scenarios but does not support Dual WAN   "
		F_printfstr "Dual WAN check can be on/off by entering option dwd (default: on)            " ; F_printfstr ''

		F_printfstr "Script supports AP mode (non router), in this mode wan-event entries         "
		F_printfstr "are not created. Uses random google STUN server to retrieve WAN IP           "

		F_printfstr "SMTP Email send formats available:                                           "
		F_printfstr "curl     - SSL (eg GMail port 465) # amtm default                            "
		F_printfstr "sendmail - StartTLS v1.1 higher                                              "
		F_printfstr "sendmail - StartTLS v1 only                                                  "
		F_printfstr "sendmail - SMTP plain auth (no encryption)                                   "
		F_printfstr "sendmail - ISP based (no password reqd, generally port 25)                   " ; F_printfstr ''

		F_printfstr "IMPORTANT - If using GMail/Outlook you must use 2 factor authentication and  "
		F_printfstr "setup an assigned App password for this script to use.                       " ; F_printfstr ''

		F_printfstr "IMPORTANT - Your Email address(es) are stored as plain text within this      "
		F_printfstr "script.  Your Email password is encrypted and saved to router storage.       "
		F_printfstr "If you dont practice good security habits around your router ssh access,     "
		F_printfstr "this script might not be for you.                                            " ; F_printfstr ''

		F_printfstr "Script compares IP in nvram for wan0 to saved IP with wan-event connected    "
		F_printfstr "events and cron, cron is also a watchdog and monitors for failed Email       "
		F_printfstr "attempts. Should the nvram IP be invalid/private IP script will use firmware "
		F_printfstr "built in ministun to retrieve your WAN IP using Google STUN server.          " ; F_printfstr ''

		F_printfstr "Router reboot Email contains last known uptime prior to reboot (saved w/cron)"
		F_printfstr "and down time between power loss (last check with cron) and power up time    " ; F_printfstr ''

		F_printfstr "All cron/wan-event/services-start/update-notification entries needed for this"
		F_printfstr "script are automatically created and removed with enable and disable options." ; F_printfstr ''

		F_printfstr "NTP sync must occur on boot for proper script function                       " ; F_printfstr ''

		F_printfstr "### Technical ###                                                            " ; F_printfstr ''

		F_printfstr "Supports being used as an Email forwarder for other scripts, in your         "
		F_printfstr "script call /jffs/scripts/wicens.sh send {your email.txt path here}          "
		F_printfstr "ie. /jffs/scripts/wicens.sh send /tmp/email.txt                              "
		F_printfstr "Use option fe (unlisted) in the menu to view a sample Email .txt file        " ; F_printfstr ''

		F_printfstr "When using wicens as an Email forwarder you can pass a second argument after "
		F_printfstr "the Email text path as an alternate send to address different from what is   "
		F_printfstr "saved in the config ie. wicens send /path/email.txt myadd@mail.com           " ; F_printfstr ''

		F_printfstr "Should Email sending fail the script will retry 4 more times with cron       "
		F_printfstr "1/${cron_check_freq}mins) in ${update_period} second intervals.              " ; F_printfstr ''

		F_printfstr "Script generates a lock file /tmp/wicens_lock.\${run_option} to prevent      "
		F_printfstr "duplicate runs as well as /tmp/wicens_internet_lock.\${run_option}           "
		F_printfstr "when sending Email notifications. Script will automatically remove stale     "
		F_printfstr "lock files if original starting process no longer exists or lock file are    "
		F_printfstr "over age limit.                                                              " ; F_printfstr ''

		F_printfstr "Sendmail/Curl output for Emails is saved to ${mail_log} for                  "
		F_printfstr "debugging if needed.  This file can be viewed by running this script and     "
		F_printfstr "select option L||l                                                           " ; F_printfstr ''

		F_printfstr "Sendmail doesnt always return an error code on a misconfiguration so false   "
		F_printfstr "send success can occur.  If script says Email has sent but no Email received "
		F_printfstr "use option L||l from the Main Menu to read sendmail output for errors.       " ; F_printfstr ''

		F_printfstr "All messages sent to syslog are duplicated in ${script_log}                  "
		F_printfstr "Including failed Email curl logs - Use option Z||z to view wicens.log        " ; F_printfstr ''

		F_printfstr "The script does not update its saved WAN IP until the script has completed   "
		F_printfstr "sending the notification so in the event of message failure it should run    "
		F_printfstr "again with next cron run and attempt to send again.                          " ; F_printfstr ''

		F_printfstr "Using option 7 you can call your own script either immediately upon WAN IP   "
		F_printfstr "change detection, or wait until the Email message has been successfully sent."
		F_printfstr "Script will be put in background as to not block this script. Your script    "
		F_printfstr "is called with the current WAN IP as an argument.                            " ; F_printfstr ''

		F_printfstr "Output from a custom script set to run on WAN IP change is saved to          "
		F_printfstr "${user_script_log}                                                           " ; F_printfstr ''

		F_printfstr "Hidden menu options                                                          "
		F_printfstr "1f - forces build_settings menu (if amtm enabled)                            "
		F_printfstr "fl - remove mail log file                                                    "
		F_printfstr "vv - list out all settings from config files                                 "
		F_printfstr "fr - remove any found update                                                 "
		F_printfstr "fe - show example Email text file for using wicens as Email forwarder        "
		F_printfstr "ul - show log from user script output when calling script on WAN IP change   "
		F_printfstr "rc - reset core config for notification controls, not user config            "
		F_printfstr "dw - disable/enable Dual WAN check                                           " ; F_printfstr ''

		F_printfstr "Every Sunday@6pm the script will log the # of times it ran with wan-event.   " ; F_printfstr ''

		F_printfstr "Thank you for using this script.                                             " ; F_printfstr ''

		F_printfstr "SNBforums thread https://www.snbforums.com/threads/wicens-wan-ip-change-email-notification-script.69294/" ; F_printfstr ''

		F_printfstr "GitHub source https://github.com/maverickcdn/wicens                          "
	} | more
} # about

F_opt_backup_restore() {

	F_backup() {
		if [ -f "$script_backup_file" ] ; then
			while true ; do
				F_terminal_warning
				F_terminal_check "Backup file exists, Y||y to overwrite - Any key to return to Main Menu"
				read -rsn1 configremove
				case "$configremove" in
					y|Y) rm -f "$script_backup_file" ; F_terminal_erase ;;
					*) F_clean_exit reload ;;
				esac
				break
			done
		fi

		F_terminal_check "Starting backup"
		if cp "$config_src" "$script_backup_file" ; then
			F_terminal_check_ok "Backup successful, saved to $script_backup_file"
			F_printfstr "# Backup  : by v${script_version} created $(F_date r)" >> "$script_backup_file"
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
					case "$amtm_import" in
						0) F_terminal_check_fail "Couldn't find password to backup" ;;
						1) F_terminal_check_ok "amtm import enabled, skipping password backup" ;;
					esac
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

		[ "$1" = 'resetbackup' ] && F_terminal_check "Any key to continue..." && read -rsn1
	} # backup

	F_restore() {
		source "$script_backup_file"
		[ "$(F_printfstr "$build_settings_version" | cut -d'.' -f1)" -le 3 ] && [ "$amtm_import" = 0 ] && amtm_import=1    # v3-v4
		restore=1
		F_status | sed -n '1,/Script install/p'
		F_terminal_show "File history:"
		sed -n "/# Created/,/&/p" "$script_backup_file"

		if ! F_confirm "Do you wish to restore this config?" ; then
			F_terminal_check_ok "No received, exiting..."
			F_menu_exit
		fi

		F_terminal_check_ok "Ok received"
		F_terminal_check "Restoring backup"
		if cp -f "$script_backup_file" "$config_src" ; then
			F_printfstr "# Restored: by v${script_version} from backup on $(F_date r)" >> "$config_src"

			if [ -f "$history_src_backup" ] ; then
				cp "$history_src_backup" "$history_src"
			fi

			F_user_settings   # reload
			F_replace_var created_date "$(F_date f)" "$config_src"

			if [ "$user_fw_update_notification" = 1 ] ; then
				! F_notify_firmware check status && F_notify_firmware create
			fi

			if [ "$user_reboot_notification" = 1 ] ; then
				! F_notify_reboot check status && F_notify_reboot create
			fi

			if [ "$user_update_notification" = 1 ] ; then
				! F_notify_update check && F_notify_update create
			fi

			if [ "$user_wanip_notification" = 1 ] ; then
				if [ "$status_cru" = 0 ] || [ "$status_srvstrt" = 0 ] || [ "$status_wanevent" = 0 ] ; then F_notify_wanip create ; fi
			fi

			F_settings_test

			if [ "$user_message_type" != 'smtp_isp_nopswd' ] ; then
				if [ -f "$cred_loc_bak" ] ; then
					if cp -f "$cred_loc_bak" "$cred_loc" ; then
						F_terminal_check_ok "Successfully restored backed up password"
					else
						F_terminal_check_fail "Error restoring backed up password"
					fi
				else
					F_terminal_check_fail "Error, no backed up password found"
				fi
			fi
		else
			F_terminal_check_fail "Critical error copying backup to script"
		fi

		F_terminal_check_ok "Done restoring backup settings to script"
	} # restore

	# from F_reset, if valid config backup before reset
	[ "$1" = 'resetbackup' ] && F_backup resetbackup && return 0
	F_terminal_header
	F_terminal_show "${tYEL}===== Backup/Restore Settings Menu =====${tCLR}   E||e to exit"
	F_terminal_padding

	# no valid settings/backup
	if [ "$status_email_cfg" = 0 ] && [ ! -f "$script_backup_file" ] ; then
		F_terminal_warning
		F_terminal_check_fail "Error invalid current settings and no backup found to restore"
		F_terminal_padding
		F_terminal_show "Use Menu option 1 to edit settings"
		F_menu_exit
	fi

	while true ; do
		if [ -f "$script_backup_file" ] ; then
			F_terminal_check_ok "Backup found!        R||r to restore settings   D||d to delete backup"
		else
			F_terminal_check_fail "No backup found to restore"
		fi

		if [ "$status_email_cfg" = 1 ] ; then
			F_terminal_check_ok "Valid config found!  B||b to backup current config"
		else
			F_terminal_check_fail "No valid config to backup, Main Menu option 1 to add a config"
		fi

		F_terminal_padding
		F_terminal_check "Selection : "

		read -r bandrwait
		case "$bandrwait" in
			D|d)
				F_terminal_erase
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
					F_terminal_check_fail "Error, no saved backup to delete"
					F_terminal_padding
					F_terminal_check "Any key to return to the Main Menu"
					read -rsn1
					F_clean_exit reload
				fi
			;;

			B|b)
				if [ "$status_email_cfg" = 0 ] ; then
					F_terminal_check_fail "Error, no valid config found to backup"
					F_terminal_padding
					F_terminal_check "Any key to return to the Main Menu"
					read -rsn1
					F_clean_exit reload
				else
					F_terminal_erase
					F_terminal_check_ok "B selected for backup"
					F_backup
					F_menu_exit
				fi
			;;

			R|r)
				if  [ -f "$script_backup_file" ] ; then
					F_terminal_erase
					F_terminal_check_ok "R selected for restore"
					F_restore
					F_printf "Any key to continue"
					read -rsn 1
					F_clean_exit reset
				else
					F_terminal_erase
					F_terminal_check_fail "Invalid entry, no valid backup exists, any key to continue"
					read -rsn1
					F_opt_backup_restore
				fi
			;;

			E|e) F_clean_exit reload ;;

			*)
				F_terminal_check_fail "Invalid entry, B/R/D - any key to retry, E return to Main Menu"
				read -rsn1
				case "$brinvalid" in
					E|e) F_clean_exit reload ;;
					*) F_opt_backup_restore ;;
				esac
			;;
		esac
		break
	done
} # backup_restore

F_opt_color() {
	case "$opt_color" in
		1)
			F_terminal_erase
			F_terminal_padding
			F_terminal_check "Setting script to no color mode"
			F_replace_var opt_color '0' "$config_src"
			F_terminal_check_ok "Set to no color mode, return to the Main Menu to view changes"
		;;

		0)
			F_terminal_erase
			F_terminal_padding
			F_terminal_check "Setting script to color mode"
			F_replace_var opt_color '1' "$config_src"
			F_terminal_check_ok "Set to color mode, return to the Main Menu to view changes"
		;;
	esac

	F_menu_exit
} # color

F_opt_count() {
	count_entry=1
	F_terminal_header
	F_terminal_show "${tYEL}===== Counts Reset Menu =====${tCLR}   E||e to Exit"
	F_terminal_padding
	F_status count | sed -n '/Cron run/,/Script configured/p'
	F_terminal_separator
	F_terminal_warning
	F_terminal_show "This will reset cron/wan-event check counts and configured date"
	F_terminal_show "as well as the option to reset WAN IP change records"

	if F_confirm "Are you sure you wish to reset counts/dates?" ; then
		F_terminal_check_ok "Ok received, resetting counts and configured date..."
		F_replace_var cron_run_count 0 "$config_src"
		F_replace_var last_cron_run 'never' "$config_src"
		F_replace_var wancall_run_count 0 "$config_src"
		F_replace_var last_wancall_run 'never' "$config_src"
		F_replace_var last_wancall_log_count 0 "$config_src"
		F_replace_var created_date "$(F_date f)" "$config_src"
		F_log_terminal_ok "Reset cron count, wan-event count and configured date"

		if [ "$last_ip_change" != 'never' ] ; then
			if F_confirm "Reset last recorded WAN IP change date and total change count? " ; then
				F_replace_var last_ip_change 'never' "$config_src"
				F_replace_var ip_change_count 0 "$config_src"
				F_log_terminal_ok "Reset last recorded WAN IP change date"
			else
				F_terminal_check_ok "Keeping WAN IP change records"
			fi
		else
			F_terminal_check_ok "No IP change records to remove"
		fi

		if [ -f "$history_src" ] ; then
			if F_confirm "Remove historical WAN IP change records?" ; then
				rm -f "$history_src"
				F_log_terminal_ok "Removed historical WAN IP change records"
			else
				F_terminal_check_ok "Keeping historical WAN IP change records"
			fi
		else
			F_terminal_check_ok "No historical WAN IP change file found"
		fi
	else
		F_terminal_check_ok "No received, exiting..."
	fi

	F_menu_exit
} # count

F_opt_forward() {
	[ -n "$fwd_send_addr" ] && user_send_to_addr="$fwd_send_addr"

	if [ ! -f "$wicens_send_retry" ] ; then
		{
			F_printfstr "#!/bin/sh"
			F_printfstr "fwd_send_msg='${wicens_send_copy}'"
			F_printfstr "fwd_send_addr='${user_send_to_addr}'"
			F_printfstr "wicens_send_retry_time='${run_epoch}'"
			F_printfstr "# Attempting to send $fwd_send_msg to $user_send_to_addr $(F_date r)"
		} > "$wicens_send_retry"
		F_chmod "$wicens_send_retry"
		cp "$fwd_send_msg" "$wicens_send_copy" 2> /dev/null   # copy incase send fails and user has email removed in their script
	else
		F_printfstr "# Attempting to send $fwd_send_msg to $user_send_to_addr $(F_date r)" >> "$wicens_send_retry"
	fi

	mail_file="$fwd_send_msg"
	[ -f "$mail_log" ] && rm -f "$mail_log"

	F_internet_check send

	if ! F_send_email ; then
		F_log_terminal_fail "Error, failed to send $fwd_send_msg Email to $user_send_to_addr"
		user_pswd=''
		rm -f "$mail_file"
		return 1
	fi

	user_pswd=''
	rm -f "$mail_file"
	rm -f "$wicens_send_retry"
	rm -f "$wicens_send_copy"
	F_log_terminal_ok "Success, finished sending $fwd_send_msg Email to $user_send_to_addr"
	return 0
} # forward

F_opt_mail_log() {
	if [ -f "$mail_log" ] ; then
		more < "$mail_log"
		F_terminal_padding
		F_terminal_check_ok "End of contents."
		F_menu_exit
	else
		F_terminal_check_fail "No log file found"
		F_menu_exit
	fi
} # mail_log

F_opt_reset() {
	F_terminal_header
	F_terminal_show "${tYEL}===== Script Reset Menu =====${tCLR}   E||e to Exit"
	F_terminal_padding
	F_terminal_warning

	if [ "$status_email_cfg" = 1 ] && [ "$backup_skip" != "1" ] ; then
		F_terminal_check_ok "Found valid config"
		F_terminal_padding
		F_terminal_show "You're about to reset, would you like to make a backup?"
		F_terminal_padding

		while true ; do
			F_terminal_check "B||b to create a backup   R||r to reset without backup   E||e to exit"

			read -rsn1 backup_wait
			case "$backup_wait" in
				B|b) F_terminal_header ; F_terminal_check_ok "Creating backup" ; F_opt_backup_restore resetbackup ;;
				R|r) break ;;
				E|e) F_clean_exit reload ;;
				*) F_fail_entry ;;
			esac
			break
		done
		backup_skip=1
		F_opt_reset
	fi

	F_terminal_show "This will reset wicens to default and remove all saved settings and "
	F_terminal_show "records including entires in services-start, wan-event, cron"
	F_terminal_show "and update-notification"

	if F_confirm "Are you sure you wish to reset?" ; then
		F_terminal_check_ok "Ok received, resetting..."
	else
		F_terminal_check_ok "No received, exiting..."
		F_menu_exit
	fi

	F_notify_firmware remove un
	F_notify_reboot remove un
	F_auto_run removeall

	[ -f "$cred_loc" ] && rm -f "$cred_loc" && F_log_terminal_ok "Removed saved password"
	[ -f "$config_src" ] && rm -f "$config_src" && F_log_terminal_ok "Reset user config to default"
	[ -f "$update_src" ] && rm -f "$update_src" && F_log_terminal_ok "Reset core config to default"
	[ -f "$history_src" ] && rm -f "$history_src" && F_log_terminal_ok "Removed WAN IP change history"
	F_log_terminal_ok "Done, script reset to default"
	[ -f "$mail_log" ] && rm -f "$mail_log"

	F_terminal_padding
	F_terminal_check "Any key to continue"
	read -rsn1
	F_clean_exit reset
} # reset

F_opt_sample() {
	if [ -n "$1" ] ; then
		sample_email=1
		run_option='sample'
		clear
		F_terminal_show "Sample Email output:"
		F_terminal_padding

		if [ "$1" = 'reboot' ] ; then
			F_reboot_email_msg
		elif [ "$1" = 'wanip' ] ; then
			current_wan_ip='111.222.33.44'   # fake for email
			test_mode=1
			F_wanip_email_msg
			test_mode=0
		elif [ "$1" = 'firmware' ] ; then
			new_fw_ver_pretty='xxx.xx_x'
			firmware_subject="Asus router ${fw_device_model} ${fw_pulled_device_name} has Firmware Update available, version ${new_fw_ver_pretty}"
			F_fw_update_email_msg
		fi

		sed '1,2!s/<[^>]*>//g' < "$mail_file"  | awk '{ while (length($0) > 58) { print substr($0, 1, 58); $0 = substr($0, 59) } print $0 }'
		sample_email=0
		run_option='tty'
		rm -f "$mail_file"
		F_terminal_show "End of Email output"
		if [ "$building_settings" = 0 ]
		then F_menu_exit
		else return 0
		fi
	else
		[ "$building_settings" = 1 ] && F_opt_sample wanip && return 0
		F_terminal_header
		F_terminal_show "${tYEL}===== Sample Email Menu =====${tCLR}   E||e to exit"
		F_terminal_padding
		F_terminal_show "Which sample Email would you like to view?"
		F_terminal_padding
		F_terminal_show "  1) WAN IP   2) Reboot   3) Firmware"
		F_terminal_padding
		F_terminal_check "Selection: "
		while true ; do
			read -r sampleselect
			case "$sampleselect" in
				1) F_opt_sample wanip ;;
				2) F_opt_sample reboot ;;
				3) F_opt_sample firmware ;;
				E|e) F_clean_exit reload ;;
				*)
					F_terminal_erase
					F_terminal_check_fail "Invalid Entry, any key to retry"
					read -rsn1
					F_opt_sample
				;;
			esac
			return 1
		done
	fi
} # sample

F_opt_script() {
	if [ "$1" = 'remove' ] ; then
		F_replace_var user_custom_script '' "$config_src"
		F_replace_var user_custom_script_time '' "$config_src"
		user_custom_script_decoded=
		user_script_call_time=
		user_custom_script=
		user_custom_script_time=
		return 0
	fi

	F_terminal_header
	F_terminal_show "${tYEL}===== Custom Script Path Entry Menu =====${tCLR}   E||e to exit"
	F_terminal_padding
	if [ "$status_wanipmon" = 0 ] ; then
		F_terminal_check_fail "WAN IP monitoring or WAN IP notifications are not enabled"
		F_terminal_padding
		F_terminal_show "Please enable either to add WAN IP change script"
		F_menu_exit
	fi

	F_ready_check options

	if [ -z "$user_custom_script" ] ; then
		while true ; do
			F_terminal_show "Do you want your custom script to execute immediately on detection"
			F_terminal_show "of WAN IP change or wait until notification message has been sent"
			F_terminal_show "If only WAN IP monitoring is enabled (not WAN IP Email) use immediate"
			F_terminal_padding
			F_terminal_show "${tGRN}w${tCLR} for wait  -  ${tGRN}i${tCLR} for immediately "
			F_terminal_padding
			F_terminal_entry "Selection: "

			read -r user_script_wait_entry
			F_terminal_padding
			case "$user_script_wait_entry" in
				w|i)
					case "$user_script_wait_entry" in
						i) user_script_call_time='immediate' ;;
						w)
							if [ "$user_wanip_notification" != '1' ] ; then
								F_terminal_check_fail "Error, WAN IP notifications are not enabled, any key to return"
								read -rsn1
								F_opt_script
							fi
							user_script_call_time='wait'
						;;
					esac
					F_replace_var user_custom_script_time "$user_script_wait_entry" "$config_src"
					F_terminal_check_ok "Done writing custom script execute time $user_script_wait_entry to script"
					user_custom_script_time="$user_script_wait_entry"
				;;

				E|e) F_clean_exit reload ;;

				*)
					F_terminal_check_fail "Invalid entry, any key to retry"
					read -rsn1
					F_opt_script
				;;
			esac
			break
		done

		F_terminal_padding
		F_terminal_check "Any key to continue..."
		read -rsn1

		F_terminal_header
		F_terminal_show "${tYEL}--- Custom Script Path Entry Menu ---${tCLR}   E||e to exit"
		F_terminal_padding
		F_terminal_show "Script execution set to : ${tGRN}$user_custom_script_time${tCLR}"
		F_terminal_padding
		F_terminal_show "Enter the full path to your script to be called"
		F_terminal_show "eg. /jffs/scripts/customscript.sh"
		F_terminal_padding
		F_terminal_entry "Path : "

		read -r user_custom_script_entry

		case "$user_custom_script_entry" in
			E|e)
				F_replace_var user_custom_script_time '' "$config_src"
				user_script_call_time=
				F_menu_exit
			;;

			"")
				F_terminal_check_fail "Script path cannot be empty - Any key to retry"
				read -rsn1
				F_opt_script
			;;
		esac

		if F_confirm correct "$user_custom_script_entry" ; then
			if [ ! -f "$user_custom_script_entry" ] ; then
				F_terminal_check_fail "Error - could not locate custom script $user_custom_script_entry"
				F_terminal_padding
				F_terminal_show "Any key to return to the Main Menu"
				F_replace_var user_custom_script_time '' "$config_src"
				user_script_call_time=
				read -rsn1
				F_clean_exit reload
			else
				F_terminal_check_ok "Success - found file, saving custom script path to execute"
			fi

			custom_script_encoded="$(F_printfstr "$user_custom_script_entry" | /usr/sbin/openssl base64 | tr -d '\n')"   # base64 no worries of sed conflicts

			if F_replace_var user_custom_script "$custom_script_encoded" "$config_src" ; then
				F_terminal_check_ok "Done writing custom script path to wicens"
				user_custom_script="$user_custom_script_entry"
				F_crlf "$user_custom_script"
				F_chmod "$user_custom_script"
			else
				F_terminal_check_fail "Error, sed failed writing custom script path to wicens script"
			fi
			return 0
		else
			F_replace_var user_custom_script_time '' "$config_src"
			return 1
		fi
	else
		F_terminal_show "Custom script path already set"
		F_terminal_padding
		F_terminal_show "${tGRN}${user_custom_script_decoded}${tCLR}"
		F_terminal_padding

		while true ; do
			F_terminal_check "Y||y keep - N||n enter new - R||r remove current "

			read -rsn1 yesornowremove
			case "$yesornowremove" in
				Y|y) F_terminal_check_ok "Keeping currently saved custom script path" ;;

				N|n) user_custom_script='' ; return 1 ;;

				R|r) F_opt_script remove ;;

				E|e) F_clean_exit reload ;;

				*)
					F_terminal_check_fail "Invalid entry, Y||y N||n R||r - Any to key to retry"
					read -rsn1
					F_terminal_erase
					continue
				;;
			esac
			break
		done
	fi
} # script

F_opt_subject_select() {
	F_terminal_header
	F_terminal_show "${tYEL}===== Custom Subject Menu =====${tCLR}   E||e to exit"
	F_terminal_padding
	F_ready_check options
	F_terminal_show "Enter which Email subject line you wish to customize"
	F_terminal_padding
	[ -n "$user_custom_subject_decoded" ] && sw="${tGRN}"
	[ -n "$user_custom_subject_decoded_r" ] && sr="${tGRN}"
	[ -n "$user_custom_subject_decoded_f" ] && sf="${tGRN}"
	[ -n "$user_custom_subject_decoded_s" ] && ss="${tGRN}"
	F_terminal_show " 1) ${sw}WAN IP${tCLR}  2) ${sr}Reboot${tCLR}  3) ${sf}Firmware${tCLR}  4) ${ss}Script${tCLR}"
	F_terminal_padding
	subject_select=

	while true ; do
		F_terminal_check "Selection: "
		read -r subject_pick
		case "$subject_pick" in
			1|2|3|4) break ;;
			e|E) F_clean_exit reload ;;
			*) F_terminal_erase ; F_fail_entry ;;
		esac
	done

	if [ "$subject_pick" = 1 ] ; then
		subject_select=user_custom_subject
		sub_dec="$user_custom_subject_decoded"
		current_sub="$wan_subject"  # var name for subjects
		subject_id='WAN IP'
	elif [ "$subject_pick" = 2 ] ; then
		subject_select=user_custom_subject_r
		sub_dec="$user_custom_subject_decoded_r"
		current_sub="$reboot_subject"
		subject_id='Reboot'
	elif [ "$subject_pick" = 3 ] ; then
		subject_select=user_custom_subject_f
		sub_dec="$user_custom_subject_decoded_f"
		current_sub="$firmware_subject"
		subject_id='Firmware'
	elif [ "$subject_pick" = 4 ] ; then
		subject_select=user_custom_subject_s
		sub_dec="$user_custom_subject_decoded_s"
		current_sub="$script_subject"
		subject_id='Script update'
	fi
	F_opt_subject
}

F_opt_subject() {
	F_terminal_header
	F_terminal_show "${tYEL}===== Custom Subject Menu =====${tCLR}   E||e to exit"
	F_terminal_padding
	F_ready_check options
	F_terminal_show "Custom Subject msg type : ${tGRN}$subject_id${tCLR}"
	F_terminal_padding
	if eval "[ -z \"\${$subject_select}\" ]" ; then
		F_terminal_show "Enter the text for a custom Email Subject line you wish to use"
		F_terminal_padding
		F_terminal_show "Current subject: ${tGRN}${current_sub}${tCLR}"
		F_terminal_padding
		if [ "$subject_pick" = 1 ] ; then
			F_terminal_show "If you wish to use the new or old WAN IP, add the variable names"
			F_terminal_show "\$current_wan_ip and \$saved_wan_ip to your text (like shown)"
			F_terminal_show "Model of router is \$fw_device_model"
			F_terminal_show "Router device name is \$fw_pulled_device_name"
			F_terminal_show "Router domain name is \$fw_pulled_lan_name"
			F_terminal_show "LAN IP is \$fw_lan_addr"
			F_terminal_padding
		fi

		F_terminal_entry "Subject: "

		read -r user_custom_subject_entry
		[ -z "$user_custom_subject_entry" ] && return 1
		case "$user_custom_subject_entry" in
			E|e) F_clean_exit reload ;;
		esac

		if F_confirm correct "$user_custom_subject_entry" ; then
			custom_subject_encoded="$(F_printfstr "$user_custom_subject_entry" | /usr/sbin/openssl base64 | tr -d '\n')"
			if F_replace_var "$subject_select" "$custom_subject_encoded" "$config_src" ; then
				#user_custom_subject="$user_custom_subject_entry"
				F_terminal_check_ok "Done, ${subject_select} set to : ${user_custom_subject_entry}"
			else
				F_terminal_check_fail "Error, sed failed to write custom subject to script"
				F_menu_exit
			fi
		else
			return 1
		fi

	else
		F_terminal_show "Custom subject already set :"
		F_terminal_padding
		F_terminal_show "${tYEL}${sub_dec}${tCLR}"
		F_terminal_padding

		while true; do
			F_terminal_check "Y||y keep - N||n enter new - R||r remove current "

			read -rsn1 yesornowremovesub
			case "$yesornowremovesub" in
				Y|y) F_terminal_check_ok "Keeping currently saved custom Email subject text" ;;
				N|n) eval "$subject_select=\"\"" ; return 1 ;;
				R|r)
					if F_replace_var "$subject_select" '' "$config_src" ; then
						F_terminal_check_ok "Custom subject text cleared"
						eval "$subject_select="
					else
						F_terminal_check_fail "Error, sed failed to clear custom subject text"
						F_menu_exit
					fi
				;;

				E|e) F_clean_exit reload ;;

				*)
					F_terminal_check_fail "Invalid entry, Y||y N||n R||r - Any to key to retry"
					read -rsn1
					F_terminal_erase
					continue
				;;
			esac
			break
		done
	fi
} # subject

F_opt_test() {
	F_terminal_header
	F_terminal_show "${tYEL}===== Test Email Menu =====${tCLR}   E||e to exit"
	F_terminal_padding
	F_terminal_show "Choose the Email message type you'd like to receive"
	F_terminal_padding
	F_terminal_show "1) WAN IP 2) Router Reboot 3) Firmware"
	F_terminal_padding
	F_terminal_check "Selection (1/2/3) : "
	read -r emailtesttype
	case "$emailtesttype" in
		1|2|3)
			F_terminal_header
			F_ready_check options
			F_terminal_check_ok "Started Email Test message to ${user_send_to_addr}"
			test_mode=1
			run_option='test'
			case "$emailtesttype" in
				1)
					current_wan_ip='x.x.x.x TEST'
					F_wanip_email_msg  # return to menu or exit in F_wanip_email
				;;
				2) F_reboot_email_msg ; F_menu_exit ;;
				3) F_fw_update_email_msg ; F_menu_exit ;;
			esac
		;;
		e|E) F_clean_exit reload ;;
		*) F_fail_entry ;;
	esac
} # test

F_opt_text_select() {
	F_terminal_header
	F_terminal_show "${tYEL}===== Custom Email Text Entry Menu =====${tCLR}   E||e to exit"
	F_terminal_padding
	F_ready_check options
	F_terminal_show "Enter which Email you wish to add custom text to"
	F_terminal_padding
	[ -n "$user_custom_text_decoded" ] && sw="${tGRN}"
	[ -n "$user_custom_text_r_decoded" ] && sr="${tGRN}"
	[ -n "$user_custom_text_f_decoded" ] && sf="${tGRN}"
	[ -n "$user_custom_text_s_decoded" ] && ss="${tGRN}"
	F_terminal_show " 1) ${sw}WAN IP${tCLR}  2) ${sr}Reboot${tCLR}  3) ${sf}Firmware${tCLR}  4) ${ss}Script${tCLR}"
	F_terminal_padding
	text_select=

	while true ; do
		F_terminal_check "Selection: "
		read -r text_pick
		case "$text_pick" in
			1|2|3|4) break ;;
			e|E) F_clean_exit reload ;;
			*) F_terminal_erase ; F_fail_entry ;;
		esac
	done

	if [ "$text_pick" = 1 ] ; then
		text_select=user_custom_text
		text_dec="$user_custom_text_decoded"
		text_id='WAN IP'
	elif [ "$text_pick" = 2 ] ; then
		text_select=user_custom_text_r
		text_dec="$user_custom_text_r_decoded"
		text_id='Reboot'
	elif [ "$text_pick" = 3 ] ; then
		text_select=user_custom_text_f
		text_dec="$user_custom_text_f_decoded"
		text_id='Firmware'
	elif [ "$text_pick" = 4 ] ; then
		text_select=user_custom_text_s
		text_dec="$user_custom_text_s_decoded"
		text_id='Script update'
	fi

	F_opt_text
}

F_opt_text() {
	F_terminal_header
	F_terminal_show "${tYEL}===== Custom Text Entry Menu =====${tCLR}   E||e to exit"
	F_terminal_padding
	F_terminal_show "Current text msg type: ${tGRN}${text_id}${tCLR}"
	F_terminal_padding

	if eval "[ -z \"\${$text_select}\" ]" ; then
	#if [ -z "$user_custom_text" ] ; then
		F_terminal_show "Enter your line of custom plain text to add to the Email message"
		F_terminal_show "eg.  Router hidden in moms closet, 2 vpn clients to update"
		F_terminal_show "Entry must be one line, can use \\\n to create new line in Email msg"
		F_terminal_padding
		F_terminal_entry "Text : "

		read -r user_custom_text_entry
		F_terminal_padding
		# ensure we empty any saved vars if brought here by N new entry but left entry blank
		[ -z "$user_custom_text_entry" ] && F_replace_var user_custom_text '' "$config_src" && return 1
		case "$user_custom_text_entry" in
			E|e) F_clean_exit reload ;;
		esac

		if F_confirm correct "$user_custom_text_entry" ; then
			custom_text_encoded="$(F_printfstr "$user_custom_text_entry" | /usr/sbin/openssl base64 | tr -d '\n')"   # base64 no worries of sed conflicts
			F_replace_var "$text_select" "$custom_text_encoded" "$config_src"
			F_terminal_check_ok "Done writing custom text to script"
		else
			return 1
		fi

	else
		F_terminal_show "Custom text already set :"
		F_terminal_padding
		F_terminal_show "${tYEL}${text_dec}${tCLR}"
		F_terminal_padding

		while true ; do
			F_terminal_check "Y||y keep - N||n enter new - R||r remove current "
			read -rsn1 yesornowremove
			case "$yesornowremove" in
				Y|y) F_terminal_check_ok "Keeping currently saved custom text" ;;
				N|n) eval "$text_select=\"\"" ; return 1 ;;
				R|r)
					F_replace_var "$text_select" '' "$config_src"
					F_terminal_check_ok "Done, custom text cleared"
					user_custom_text=''
				;;
				E|e) F_clean_exit reload ;;
				*)
					F_terminal_check_fail "Invalid entry, Y||y N||n R||r - Any to key to retry"
					read -rsn1
					F_terminal_erase
					continue
				;;
			esac
			break
		done
	fi
} # custom_text

F_opt_uninstall() {
	F_terminal_header
	F_terminal_warning
	F_terminal_show "This will remove the wicens script ENTIRELY from your system"
	F_terminal_show "And any backup configs"
	F_terminal_padding

	while true ; do
		F_terminal_show "Are you sure you wish to uninstall? Type DELETE || delete"
		F_terminal_padding
		F_terminal_check "Confirm : "

		read -r uninstall_wait
		case "$uninstall_wait" in
			'DELETE'|'delete')
				F_terminal_header exit
				F_terminal_check_ok "Uninstalling..."
				F_notify_firmware remove un
				F_notify_reboot remove un
				F_auto_run removeall
				F_alias remove
				rm -f /tmp/wicens*
				rm -f "$script_name_full"
				[ -f "$script_log_loc" ] && rm -f "$script_log_loc"   # non default location
				F_log_terminal_ok "Removed wicens files from RAM (/tmp)"
				F_log_terminal_ok "Removed /jffs/addons/wicens directory and /jffs/scripts/wicens.sh"
				F_log_terminal_ok "Done, wicens has been uninstalled completely"
				F_printf "[${tGRN}EXIT${tCLR}] Goodbye"
				rm -r "$script_dir"
				F_terminal_padding
				exit 0
			;;

			*)
				F_terminal_erase
				F_terminal_check_fail "Must type DELETE to uninstall"
				F_menu_exit
			;;
		esac
		break
	done
} # uninstall

# NOTIFY OPTIONS ######################################################################################################
#######################################################################################################################

F_notify_firmware() {
	case "$1" in
		'check')
			status_fw=0
			if grep -Fq "$script_name_full fwupdate" /jffs/scripts/update-notification 2> /dev/null ; then
				[ "$status_email_cfg" = 1 ] && [ "$user_fw_update_notification" = 1 ] && \
				[ "$status_cru" = 1 ] && [ "$status_srvstrt" = 1 ] && status_fw=1
				return 0
			fi
			return 1
		;;

		'create')
			if [ -f /jffs/scripts/update-notification ] ; then
				F_crlf '/jffs/scripts/update-notification'
				F_chmod '/jffs/scripts/update-notification'

				if ! grep -Fq '#!/bin/sh' /jffs/scripts/update-notification ; then
					sed -i '1 i\#!/bin/sh' /jffs/scripts/update-notification
					F_log_terminal_fail "Your update-notification does not contain a '#!/bin/sh'"
					F_log_terminal_ok "Added #!/bin/sh to top of update-notification file"
				fi

				{
					F_printfstr "nohup sh ${script_name_full} fwupdate & wicenspid=\$!   # added by wicens $(F_date r)"
					F_printfstr "/usr/bin/logger -t \"update-notification[\$\$]\" \"Started wicens with pid \${wicenspid}\"   # added by wicens $(F_date r)"
				} >> /jffs/scripts/update-notification

				F_log_terminal_ok "Created entry in /jffs/scripts/update-notification for fw update"
			else
				{
					F_printfstr '#!/bin/sh'
					F_printfstr "# Created by $script_name_full for WAN IP change notification   # added by wicens $(F_date r)"
					F_printfstr "nohup sh ${script_name_full} fwupdate & wicenspid=\$!  # added by wicens $(F_date r)"
					F_printfstr "/usr/bin/logger -t \"update-notification[\$\$]\" \"Started wicens with pid \${wicenspid}\"   # added by wicens $(F_date r)"
				} > /jffs/scripts/update-notification

				F_chmod '/jffs/scripts/update-notification'
				F_log_terminal_ok "Created /jffs/scripts/update-notification and added entry for fw update"
			fi

			F_replace_var user_fw_update_notification 1 "$config_src"
			F_auto_run create2
			F_log_terminal_ok "Enabled Firmware update Email notification"
			return 0
		;;

		'remove')
			if [ -f /jffs/scripts/update-notification ] ; then
				if grep -Fq "$script_name_full fwupdate" /jffs/scripts/update-notification ; then
					sed -i '/added by wicens/d' /jffs/scripts/update-notification
					F_log_terminal_ok "Removed entry in update-notification for firmware updates"
				else
					F_log_terminal_ok "No entry in /jffs/scripts/update-notification for fw to remove"
				fi

				if [ "$(wc -l < /jffs/scripts/update-notification)" -eq 1 ] ; then
					if grep -Fq '#!/bin/sh' /jffs/scripts/update-notification ; then
						rm -f /jffs/scripts/update-notification
						F_log_terminal_ok "/jffs/scripts/update-notification appears empty, removed file"
					fi
				fi
			else
				F_terminal_check_ok "No entry in /jffs/scripts/update-notification for fwupdate - file doesn't exist"
			fi

			F_replace_var user_fw_update_notification 0 "$config_src"
			user_fw_update_notification=0
			[ "$2" != 'un' ] && F_log_terminal_ok "Disabled Firmware update Email notifcation"

			if [ "$user_wanip_notification" = 0 ] && [ "$user_reboot_notification" = 0 ] && [ "$user_update_notification" = 0 ] && [ "$user_wanip_monitor" = 0 ] ; then
				if [ "$2" != 'un' ] ; then
					F_auto_run remove2
				fi
			fi
			return 0
		;;
	esac

	F_terminal_show "${tYEL}===== Firmware update notification enable/disable =====${tCLR}"

	if [ "$fw_build_no" -eq 374 ] ; then
		F_terminal_show "Sorry, this version of firmware is not compatible"
		F_menu_exit
	fi

	if [ "$status_email_cfg" -eq 1 ] && [ "$user_fw_update_notification" -eq 0 ] ; then
		F_notify_firmware create
	elif [ "$user_fw_update_notification" -eq 1 ] ; then
		F_notify_firmware remove
	else
		F_terminal_padding
		F_terminal_check_fail "Error - invalid Email settings, use Main Menu to add settings"
	fi
	F_menu_exit
} # notify_firmware

F_notify_reboot() {
	case "$1" in
		'check')
			status_reboot=0
			if grep -Fq "$script_name_full reboot" /jffs/scripts/services-start 2> /dev/null ; then
				[ "$status_email_cfg" = 1 ] && [ "$user_reboot_notification" = 1 ] && \
				[ "$status_cru" = 1 ] && [ "$status_srvstrt" = 1 ] && status_reboot=1
				return 0
			fi
			return 1
		;;

		'create')
			if [ -f /jffs/scripts/services-start ] ; then
				F_crlf '/jffs/scripts/services-start'
				F_chmod '/jffs/scripts/services-start'

				if ! grep -Fq '#!/bin/sh' /jffs/scripts/services-start ; then
					sed -i '1 i\#!/bin/sh' /jffs/scripts/services-start
					F_log_terminal_fail "Your services-start does not contain a '#!/bin/sh'"
					F_log_terminal_ok "Added #!/bin/sh to top of services-start file"
				fi

				{
					F_printfstr "nohup sh ${script_name_full} reboot & wicenspid=\$!   # added by reboot wicens $(F_date r)"
					F_printfstr "/usr/bin/logger -t \"services-start[\$\$]\" \"Started wicens for reboot notification with pid \${wicenspid}\"   # added by reboot wicens $(F_date r)"
				} >> /jffs/scripts/services-start

				F_log_terminal_ok "Added entry to /jffs/scripts/services-start for reboot"
			else
				{
					F_printfstr "#!/bin/sh"
					F_printfstr "# Created by ${script_name_full} for router reboot notification   # added by reboot wicens $(F_date r)"
					F_printfstr "nohup sh ${script_name_full} reboot & wicenspid=\$!   # added by reboot wicens $(F_date r)"
					F_printfstr "/usr/bin/logger -t \"services-start[\$\$]\" \"Started wicens for reboot notification with pid \${wicenspid}\"   # added by reboot wicens $(F_date r)"
				} > /jffs/scripts/services-start

				F_chmod '/jffs/scripts/services-start'
				F_log_terminal_ok "Created /jffs/scripts/services-start and added entry for reboot"
			fi

			F_replace_var user_reboot_notification 1 "$config_src"
			user_reboot_notification=1
			F_auto_run create2
			F_log_terminal_ok "Enabled router reboot Email notification"
			return 0
		;;

		'remove')
			if [ -f /jffs/scripts/services-start ] ; then
				if grep -Fq "${script_name_full} reboot" /jffs/scripts/services-start ; then
					sed -i '/added by reboot wicens/d' /jffs/scripts/services-start
					F_log_terminal_ok "Removed entry in /jffs/scripts/services-start for reboot"
				else
					F_terminal_check_ok "No entry in /jffs/scripts/services-start for reboot"
				fi

				if [ "$(wc -l < /jffs/scripts/services-start )" -eq 1 ] ; then
					if grep -Fq '#!/bin/sh' /jffs/scripts/services-start ; then
						F_log_terminal_ok "/jffs/scripts/services-start appears empty, removing file"
						rm -f /jffs/scripts/services-start
					fi
				fi
			else
				F_terminal_check_ok "No entry in /jffs/scripts/services-start for reboot, file doesn't exist"
			fi
			F_replace_var user_reboot_notification 0 "$config_src"
			user_reboot_notification=0
			[ "$2" != 'un' ] && F_log_terminal_ok "Disabled router reboot Email notification"

			if [ "$user_wanip_notification" = 0 ] && [ "$user_fw_update_notification" = 0 ] && [ "$user_update_notification" = 0 ] && [ "$user_wanip_monitor" = 0 ] ; then
				if [ "$2" != 'un' ] ; then
					F_auto_run remove2
				fi
			fi
			return 0
		;;
	esac

	F_terminal_show "${tYEL}===== Router reboot notification enable/disable =====${tCLR}"
	if [ "$status_email_cfg" = 1 ] && [ "$user_reboot_notification" = 0 ] ; then
		F_notify_reboot create
	elif [ "$user_reboot_notification" = 1 ] ; then
		F_notify_reboot remove
	else
		F_terminal_padding
		F_terminal_check_fail "Error - invalid Email settings, use Main Menu to add settings"
	fi
	F_menu_exit
} # notify_reboot

F_notify_update() {
	case "$1" in
		'check')
			status_update=0
			[ "$status_email_cfg" = 1 ] && [ "$user_update_notification" = 1 ] && \
			[ "$status_cru" = 1 ] && [ "$status_srvstrt" = 1 ] && status_update=1 && return 0
			return 1
		;;

		'create')
			F_auto_run create2
			F_replace_var update_cron_epoch 0 "$update_src"
			F_replace_var user_update_notification 1 "$config_src"
			user_update_notification=1
			F_log_terminal_ok "Enabled script update Email notification"
			return 0
		;;

		'remove')
			if [ "$user_wanip_notification" = 0 ] && [ "$user_fw_update_notification" = 0 ] && [ "$user_reboot_notification" = 0 ] && [ "$user_wanip_monitor" = 0 ] ; then
				F_auto_run remove2
			fi
			F_replace_var user_update_notification 0 "$config_src"
			user_update_notification=0
			F_log_terminal_ok "Disabled script update Email notification"
			return 0
		;;
	esac

	F_terminal_show "${tYEL}===== Script update notification enable/disable =====${tCLR}"

	if [ "$status_email_cfg" = 1 ] && [ "$user_update_notification" = 0 ] ; then
		F_notify_update create
	elif [ "$user_update_notification" = 1 ] ; then
		F_notify_update remove
	else
		F_terminal_padding
		F_terminal_check_fail "Error - invalid Email settings, use Main Menu to edit settings"
	fi
	F_menu_exit
} # notify_update

F_notify_wanip() {
	case "$1" in
		'check')
			status_wanip=0
			if [ "$status_email_cfg" = 1 ] && [ "$user_wanip_notification" = 1 ] && [ "$status_cru" = 1 ] && [ "$status_srvstrt" = 1 ] && [ "$user_wanip_monitor" = 1 ] ; then
				[ "$fw_sw_mode" = 1 ] && [ "$status_wanevent" = 0 ] && return 1
				status_wanip=1
				return 0
			fi
			return 1
		;;

		'create')
			F_replace_var user_wanip_notification 1 "$config_src"
			! F_wanip_monitor check && F_wanip_monitor create
			F_log_terminal_ok "Enabled WAN IP change Email notification"
			user_wanip_notification=1
			return 0
		;;

		'remove')
			if [ "$2" != 'nouser' ] ; then
				F_terminal_header
				[ "$2" = 'mon' ] && F_terminal_show "${tYEL}===== WAN IP change monitor enable/disable =====${tCLR}" && F_terminal_padding
				F_terminal_warning
				F_terminal_show "This will disable WAN IP change Email notification"
				F_terminal_show "You will not receive an Email notification if your WAN IP changes."
				if F_confirm "Are you sure you wish to disable?" ; then
					F_terminal_check_ok "Ok received, disabling..."
					F_replace_var user_wanip_notification 0 "$config_src"
					user_wanip_notification=0
					F_log_terminal_ok "Disabled WAN IP Email notification"
					return 0
				else
					F_terminal_check_ok "No received, exiting..."
					return 1
				fi
			else
				F_replace_var user_wanip_notification 0 "$config_src"
				user_wanip_notification=0
				F_log_terminal_ok "Disabled WAN IP change Email notfication"
				return 0
			fi
		;;
	esac

	F_terminal_show "${tYEL}===== WAN IP change notification enable/disable =====${tCLR}"

	if [ "$status_email_cfg" = 1 ] && [ "$user_wanip_notification" = 0 ] ; then
		if [ "$dual_wan_check" = 1 ] && [ "$(F_nvram wans_dualwan)" != 'wan none' ] ; then
			F_log_terminal_fail "Error - Dual WAN is enabled, WAN IP change cannot be enabled"
			F_menu_exit
		fi
		F_notify_wanip create
	elif [ "$user_wanip_notification" = 1 ] ; then
		F_notify_wanip remove
	else
		F_terminal_padding
		F_terminal_check_fail "Error - invalid Email settings, use Main Menu to add settings"
	fi
	F_menu_exit
} # notify_wanip

F_wanip_monitor() {
	case "$1" in
		'check')
			status_wanipmon=0
			if [ "$user_wanip_monitor" = 1 ] && [ "$status_cru" = 1 ] && [ "$status_srvstrt" = 1 ] ; then
				[ "$fw_sw_mode" = 1 ] && [ "$status_wanevent" = 0 ] && return 1
				status_wanipmon=1
				return 0
			fi
			return 1
		;;

		'create')
			building_settings=1
			F_auto_run createall
			! F_compare && F_script_wan_update
			F_replace_var user_wanip_monitor 1 "$config_src"
			F_log_terminal_ok "Enabled WAN IP change monitoring"
			return 0
		;;

		'remove')
			user_wanip_monitor=0
			if [ "$user_wanip_notification" = 1 ] ; then
				if ! F_notify_wanip remove mon ; then
					F_terminal_check_fail "Disabling cancelled"
					F_menu_exit
				fi
			fi

			F_replace_var user_wanip_monitor 0 "$config_src"
			[ "$2" != 'un' ] && F_log_terminal_ok "Disabled WAN IP change monitoring"
			if [ "$user_wanip_notification" = 0 ] && [ "$user_fw_update_notification" = 0 ] && [ "$user_update_notification" = 0 ] && [ "$user_reboot_notification" = 0 ] ; then
				[ "$2" != 'un' ] && F_auto_run removeall
			else
				if [ "$fw_sw_mode" = 1 ]
				then F_wan_event remove
				else F_terminal_check_ok "Not in router mode, skipping wan-event removal"
				fi
			fi

			if [ -n "$user_custom_script" ] ; then
				F_terminal_check_ok "Removed WAN IP change custom script entry"
				F_opt_script remove
			fi

			return 0
		;;
	esac

	F_terminal_show "${tYEL}===== WAN IP change monitor enable/disable =====${tCLR}"
	if [ "$user_wanip_monitor" = 0 ]
	then F_wanip_monitor create
	else F_wanip_monitor remove
	fi
}

# BUILD USER SETTINGS FUNCTIONS #######################################################################################
#######################################################################################################################

# all user entry functions called by until loops and return 1 for failed input and restart or return 0 with completed Y in while loop
F_send_to_addr() {
	F_terminal_entry_header 1
	F_terminal_show "Enter the Email address you wish to send a notification Email"
	F_terminal_show "to when your WAN IP changes"
	F_terminal_show "eg.  ${tGRN}myrecipient@myemail.com${tCLR}"
	[ -n "$user_send_to_addr" ] && F_terminal_padding && printf "%b Currently set to : %b%s%b \n" "$tTERMHASH" "$tGRN" "$user_send_to_addr" "$tCLR" && F_terminal_show "Leave entry blank to keep current"
	F_terminal_padding ; F_terminal_entry "Send to address : "

	read -r send_to_entry
	[ -z "$user_send_to_addr" ] && [ -z "$send_to_entry" ] && F_terminal_check_fail "Error, Email send to address cannot be empty - Any key to retry" && read -rsn1 && return 1
	[ -z "$send_to_entry" ] && [ -n "$user_send_to_addr" ] && return 0
	case "$send_to_entry" in
		E|e) F_menu_exit ;;
	esac

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
		F_terminal_entry_header 2
		printf "%b Second Email recipient already set to : %b%s%b \n\n" "$tTERMHASH" "$tGRN" "$user_send_to_cc" "$tCLR" ; F_terminal_padding

		while true; do
			F_terminal_check "Y||y keep - N||n enter new - R||r remove current & skip to server entry"   # for edits can remove 2nd email if wanted.
			read -rsn 1 ccmailwait2
			case "$ccmailwait2" in
				Y|y) return 0 ;;
				N|n) user_send_to_cc= ; return 1 ;;
				R|r) F_replace_var user_send_to_cc "" "$config_src" && user_send_to_cc= && return 0 ;;
				E|e) F_menu_exit ;;
				*) F_terminal_check_fail "Invalid Entry , Y||y N||n R||r - Any key to retry" ; read -rsn1 ; F_terminal_erase ; continue ;;
			esac
			break
		done

	else
		F_terminal_entry_header 2
		F_terminal_show "Enter a 2nd Email address you wish to send a notification Email"
		F_terminal_show "to when your WAN IP changes"
		F_terminal_show "eg.  ${tGRN}my2ndrecipient@myemail.com${tCLR}"
		F_terminal_padding ; F_terminal_show "Leave entry blank to leave CC option empty and continue"
		F_terminal_padding ; F_terminal_entry "Send to CC address : "

		read -r send_to_cc_entry
		[ -z "$send_to_cc_entry" ] && return 0
		case "$send_to_cc_entry" in
			E|e) F_menu_exit ;;
		esac

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
	F_terminal_entry_header 3
	F_terminal_show "Enter the SMTP server address and port # like as shown for your"
	F_terminal_show "Email provider - eg.  ${tGRN}smtp.myemailprovider.com:465${tCLR}"
	[ -n "$user_smtp_server" ] && F_terminal_padding && printf "%b Currently set to : %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_smtp_server" "$tCLR" && F_terminal_show "Leave entry blank to keep current"
	F_terminal_padding ; F_terminal_entry "Server address and port : "

	read -r smtp_server_entry
	[ -z "$user_smtp_server" ] && [ -z "$smtp_server_entry" ] && F_terminal_check_fail "Error, Server address cannot be empty - Any key to retry" && read -rsn1 && return 1
	[ -z "$smtp_server_entry" ] && [ -n "$user_smtp_server" ] && return 0
	case "$smtp_server_entry" in
		E|e) F_menu_exit ;;
	esac

	if F_confirm correct "$smtp_server_entry" ; then
		F_replace_var user_smtp_server "$smtp_server_entry" "$config_src"
		user_smtp_server="$smtp_server_entry"
	else
		smtp_server_entry=''
		return 1
	fi
} ### smtp_server

F_send_type() {
	F_terminal_entry_header 4
	F_terminal_show "SMTP Email server send configuration type for ${tGRN}${user_smtp_server}${tCLR}"
	F_terminal_padding
	F_terminal_show "                                                         ${tYEL}Selection${tCLR}"
	F_terminal_show "WITH password and SSL required (default)                   - 1"
	F_terminal_show "WITH password and StartTLS                                 - 2"
	F_terminal_show "ISP type with NO password and NO StartTLS/SSL- eg.port 25  - 3"
	F_terminal_show "WITH password and NO StartTLS or SSL (plain auth)          - 4"
	F_terminal_show "WITH password and StartTLS v1                              - 5"
	[ -n "$user_message_type" ] && F_terminal_padding && printf "%b Currently set to : %b%s%b\n" "$tTERMHASH" "$tGRN" "$user_message_type" "$tCLR" && F_terminal_show "Leave selection blank to keep current setting"
	F_terminal_padding ; F_terminal_entry "Selection : "

	read -r send_type_entry
	case "$send_type_entry" in
		1|2|3|4|5) ;;
		"") if [ -n "$user_message_type" ] ; then
				return 0
			else
				F_terminal_check_fail "Invalid entry, 1,2,3,4,5 only - Any key to retry" && read -rsn1 && return 1
			fi
			;;
		e|E) F_menu_exit ;;
		*) F_terminal_check_fail "Invalid Entry, 1,2,3,4,5 only - Any key to retry" && read -rsn1 && return 1 ;;
	esac

	if ! F_confirm correct "$send_type_entry" ; then
		send_type_entry=''
		return 1
	fi

	[ "$send_type_entry" = "1" ] && F_replace_var user_message_type "smtp_ssl" "$config_src" && user_message_type="smtp_ssl"
	[ "$send_type_entry" = "2" ] && F_replace_var user_message_type "smtp_start_tls" "$config_src" && user_message_type="smtp_start_tls"
	[ "$send_type_entry" = "3" ] && F_replace_var user_message_type "smtp_isp_nopswd" "$config_src" && user_message_type="smtp_isp_nopswd"
	[ "$send_type_entry" = "4" ] && F_replace_var user_message_type "smtp_plain_auth" "$config_src" && user_message_type="smtp_plain_auth"
	[ "$send_type_entry" = "5" ] && F_replace_var user_message_type "smtp_start_tls_v1" "$config_src" && user_message_type="smtp_start_tls_v1"

	if [ "$user_message_type" != 'smtp_isp_nopswd' ] && [ "$user_message_type" != 'smtp_plain_auth' ] ; then
		F_terminal_header ; F_terminal_warning
		F_terminal_show "If using GMail for your sending service you must have"
		F_terminal_show "2 factor authentication enabled and create a App"
		F_terminal_show "password for this script to use"
		F_terminal_padding ; F_terminal_check "Any key to continue" && read -rsn1
	fi

	return 0
} ### send_type

F_login_addr() {
	F_terminal_entry_header 5
	F_terminal_show "Enter the Email login address (username) for your Email provider"
	F_terminal_show "eg.  ${tGRN}myemail@myemailprovider.com${tCLR}    for ${tGRN}${user_smtp_server}${tCLR}"
	if [ -n "$user_login_addr" ] ; then
		F_terminal_padding
		F_terminal_show "Currently set to : ${tGRN}${user_login_addr}${tCLR}"
		F_terminal_show "Leave entry blank to keep current"
	fi
	F_terminal_padding
	F_terminal_entry "Login Email addr : "

	read -r email_login_entry
	[ -z "$user_login_addr" ] && [ -z "$email_login_entry" ] && F_terminal_check_fail "Error - login credentials cannot be empty - Any key to retry" && read -rsn1 && return 1
	[ -z "$email_login_entry" ] && [ -n "$user_login_addr" ] && return 0
	case "$email_login_entry" in
		E|e) F_menu_exit ;;
	esac

	if F_confirm correct "$email_login_entry" ; then
		F_replace_var user_login_addr "$email_login_entry" "$config_src"
		F_replace_var user_from_addr "$email_login_entry" "$config_src"
		user_login_addr="$email_login_entry"
		user_from_addr="$email_login_entry"
	else
		email_login_entry=''
		return 1
	fi
} ### from_email_addr

F_from_addr() {
	F_terminal_entry_header 6
	F_terminal_show "Enter the message 'from' Email address for the notification Email"
	F_terminal_show "Typically this is the same as your Email login address"
	F_terminal_padding
	F_terminal_show "Currently set to : ${tGRN}${user_from_addr}${tCLR}"
	F_terminal_show "Leave entry blank to keep current"
	F_terminal_padding
	F_terminal_entry "Email from address : "

	read -r from_addr_entry
	[ -z "$user_from_addr" ] && [ -z "$from_addr_entry" ] && F_terminal_show "Error, cannot be blank, any key to retry" && read -rsn1 && return 1
	case "$from_addr_entry" in
		E|e) F_menu_exit ;;
	esac
	F_terminal_padding

	if [ -n "$user_from_addr" ] && [ -z "$from_addr_entry" ] ; then
		return 0
	fi

	if F_confirm correct "$from_addr_entry" ; then
		F_replace_var user_from_addr "$from_addr_entry" "$config_src"
		[ -n "$from_addr_entry" ] && user_from_addr="$from_addr_entry"
	else
		from_addr_entry=''
		return 1
	fi
} # from_addr

F_email_from() {
	F_terminal_entry_header 7
	F_terminal_show "Enter the Email message 'from' name you'd like to appear"
	if [ -n "$user_email_from" ] ; then
		F_terminal_padding
		F_terminal_show "Currently set to : ${tGRN}${user_email_from}${tCLR}"
		F_terminal_show "Leave entry blank to keep current"
	fi
	F_terminal_padding
	F_terminal_entry "Email from name : "

	read -r email_from_entry
	[ -z "$user_email_from" ] && [ -z "$email_from_entry" ] && F_terminal_check_fail "Error - from name cannot be empty - Any key to retry" && read -rsn1 && return 1
	[ -z "$email_from_entry" ] && [ -n "$user_email_from" ] && return 0
	case "$email_from_entry" in
		E|e) F_menu_exit ;;
	esac
	F_terminal_padding

	if F_confirm correct "$email_from_entry" ; then
		F_replace_var user_email_from "$email_from_entry" "$config_src"
		user_email_from="$email_from_entry"
	else
		email_from_entry=''
		return 1
	fi
} # email_from

F_email_to_name() {
	F_terminal_entry_header 8
	F_terminal_show "Enter the Email message 'send to' name you'd like to appear"

	if [ -n "$user_msg_to" ] ; then
		F_terminal_padding
		F_terminal_show "Currently set to : ${tGRN}${user_msg_to}${tCLR}"
		F_terminal_show "Leave entry blank to keep current"
	fi
	F_terminal_padding
	F_terminal_entry "Email to name : "

	read -r email_to_entry
	[ -z "$user_msg_to" ] && [ -z "$email_to_entry" ] && F_terminal_check_fail "Error - from name cannot be empty - Any key to retry" && read -rsn1 && return 1
	[ -z "$email_to_entry" ] && [ -n "$user_msg_to" ] && return 0
	case "$email_to_entry" in
		E|e) F_menu_exit ;;
	esac
	F_terminal_padding

	if F_confirm correct "$email_to_entry" ; then
		F_replace_var user_msg_to "$email_to_entry" "$config_src"
		user_msg_to="$email_to_entry"
	else
		email_to_entry=''
		return 1
	fi
} # email_to_name

F_pswd_entry() {
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
} # pswd_entry replaces typed chars with *

F_smtp_pswd() {
	F_terminal_entry_header 8
	F_terminal_show "${tYEL}===== Password entry menu =====${tCLR}   E||e to exit"
	F_terminal_padding
	if [ "$amtm_import" = 1 ] && [ "$status_amtm" = 1 ] ; then
		F_terminal_check_ok "amtm import ${tGRN}enabled${tCLR} using its saved password"
		F_terminal_padding
		F_terminal_check "S||s to show amtm password - Any key to exit..."
		read -rsn1 pswdamtm
		case "$pswdamtm" in
			S|s)
				user_pswd="$(eval "$(F_printfstr "$amtm_d" | openssl base64 -d)" < "$amtm_cred_loc")"
				F_terminal_check_ok "Saved amtm password : $(F_printfstr "$user_pswd")"
				user_pswd=
				F_menu_exit
			;;
		esac
		F_clean_exit reload
	elif [ -f "$cred_loc" ] ; then
		F_terminal_check_ok "Saved password exists, leave blank to use saved - S||s to show password"
	fi

	if [ "$status_email_cfg" = 0 ] || [ "$user_smtp_server" = 'smtp_isp_nopswd' ] && [ "$building_settings" = 0 ] ; then
		F_terminal_check_fail "Error, Email settings not created or smtp type is smtp_no_pswd"
		F_terminal_padding
		F_terminal_check "Any key to return to the main menu"
		read -rsn1
		F_clean_exit reload
	fi

	F_terminal_show "Enter the password for your Email"
	F_terminal_padding
	F_terminal_entry "Password  : "

	F_pswd_entry

	password_entry_1="$passwordentry"
	case "$passwordentry" in
		E|e)
			F_terminal_check_ok "Exit confirmed"
			F_menu_exit
		;;

		S|s)
			F_terminal_padding
			if [ -f "$cred_loc" ] ; then
				user_pswd="$(eval "$(F_printfstr "$user_d" | openssl base64 -d)" < "$cred_loc")"
				F_terminal_check_ok "Saved password : $(F_printfstr "$user_pswd")"
				user_pswd=
			else
				F_terminal_check_fail "No password to show"
			fi
			F_menu_exit
		;;
	esac

	if [ -f "$cred_loc" ] && [ -z "$passwordentry" ] ; then   # keep saved
		F_terminal_erase
		F_terminal_check_ok "Keeping saved"
		return 0

	elif [ ! -f "$cred_loc" ] && [ -z "$passwordentry" ] ; then
		F_terminal_show "Error - Password cannot be empty - Any key to retry - E||e to Exit"
		read -rsn1 waitsmtppswd
		case "$waitsmtppswd" in
			E|e) F_clean_exit reload ;;
		esac
		return 1
	fi

	passwordentry=''
	F_terminal_entry "Reconfirm : "

	F_pswd_entry

	password_entry_2="$passwordentry"

	case "$passwordentry" in
		E|e) F_menu_exit ;;
	esac

	if [ "$password_entry_1" != "$password_entry_2" ] || [ -z "$password_entry_2" ] ; then
		F_terminal_check_fail "Passwords do NOT match - Any key to retry"
		read -rsn1
		password_entry_1='' ; password_entry_2='' ; passwordentry=''
		return 1
	fi

	# encrypt remove new lines so no sed errors
	user_pswd_enc="$(F_printfstr "$password_entry_1" | eval "$(F_printfstr "$user_e" | openssl base64 -d)" )"
	if F_printfstr "$user_pswd_enc" > "$cred_loc" ; then
		F_chmod "$cred_loc"
		F_terminal_check_ok "Password successfully encrypted and saved"
		passwordentry='' ; password_entry_1='' ; password_entry_2='' ; user_pswd_enc=''
		return 0
	else
		F_terminal_show "Failed updating script with encrypted password"
		passwordentry='' ; password_entry_1='' ; password_entry_2='' ; user_pswd_enc=''
		return 0
	fi
} # smtp_pswd

F_build_settings() {
	building_settings=1   # for opt_sample no exit, move to test option
	until F_send_to_addr ; do : ; done
	until F_send_to_cc; do : ; done
	until F_smtp_server ; do : ; done
	until F_send_type ; do : ; done
	until F_login_addr ; do : ; done
	until F_from_addr ; do : ; done
	until F_email_from ; do : ; done
	until F_email_to_name ; do : ; done
	[ "$user_message_type" != 'smtp_isp_nopswd' ] && until F_smtp_pswd ; do : ; done

	F_replace_var created_date "$(F_date f)" "$config_src"
	created_date="$(F_date f)"
	F_terminal_header

	F_status | sed -n '/Current saved WAN/,/Script install date/p'

	F_terminal_check "Any key to continue to view sample Email output"
	read -rsn1
	source "$config_src"
	F_settings_test
	F_opt_sample
	F_terminal_padding
	F_log_terminal_ok "Congratulations, you've completed the wicens setup"
	F_terminal_padding
	F_terminal_check "Hit T|t to send a test Email - M|m for Main Menu - Any key to exit"

	read -rsn1 setupwait
	case "$setupwait" in
		T|t) F_opt_test ; F_menu_exit ;;
		M|m) F_clean_exit reload ;;
		*)
			printf "\r%b" "$tERASE"
			F_terminal_check_ok "This script is now configured"
			F_terminal_show "Run wicens on the command line to run script manually with set config"
			F_clean_exit
		;;
	esac
} # build_settings

F_edit_settings() {
	F_terminal_header
	F_terminal_show "${tYEL}===== Welcome to the wicens Email config editor =====${tCLR}   E||e to exit"
	F_terminal_padding
	if [ "$amtm_import" = 1 ] ; then
		F_terminal_check_fail "amtm import currently enabled, edit menu unavailable"
		F_terminal_padding
		F_terminal_show "Edit amtm Email settings within amtm"
		F_terminal_show "To edit wicens saved Email settings disable amtm import"
		F_terminal_padding
		F_terminal_check "Any key to return to the main menu"
		read -rsn1
		F_clean_exit reload
	fi

	F_terminal_show "         ${tYEL}Setting                   Select  Setting${tCLR}"
	F_edit "Current Email send to address         1   " "$user_send_to_addr"
	F_edit "Current Email send to CC address      2   " "$user_send_to_cc"
	F_edit "Current Email server addr:port        3   " "$user_smtp_server"
	F_edit "Current Email send format type        4   " "$user_message_type"
	F_edit "Current Email login user (address)    5   " "$user_login_addr"
	F_edit "Current Email from Email address      6   " "$user_from_addr"
	F_edit "Current Email message from name       7   " "$user_email_from"
	F_edit "Current Email message to name         8   " "$user_msg_to"
	[ "$user_message_type" = "smtp_ssl" ] && F_edit "Current curl SSL protocol             9   " "$protocol"
	[ -f "$cred_loc" ] && F_edit "Email Password menu                   0   " "Password saved"
	F_terminal_show "Reset saved Email settings         R||r   "
	F_terminal_padding
	F_terminal_show "Make a selection or E||e to exit"
	F_terminal_padding

	while true; do
		F_terminal_check "Selection : "
		read -r editselect
		case "$editselect" in
			1) until F_send_to_addr ; do : ; done ;;
			2) until F_send_to_cc; do : ; done ;;
			3) until F_smtp_server ; do : ; done ;;
			4) until F_send_type ; do : ; done ;;
			5) until F_login_addr ; do : ; done ;;
			6) until F_from_addr ; do : ; done ;;
			7) until F_email_from ; do : ; done ;;
			8) until F_email_to_name ; do : ; done ;;
			9)
				if [ "$user_message_type" = "smtp_ssl" ] ; then
					if [ "$protocol" = 'smtps' ] ; then
						F_replace_var protocol 'smtp' "$config_src"
						F_terminal_padding ; F_terminal_check_ok "Switched to protocol SMTP" ; F_terminal_padding
					else
						F_replace_var protocol 'smtps' "$config_src"
						F_terminal_padding ; F_terminal_check_ok "Switched to protocol SMTPS" ; F_terminal_padding
					fi
				else
					F_terminal_erase
					F_fail_entry
				fi
				F_terminal_check "Any key to return..."
				read -rsn1
			;;

			0) 	if F_ready_check pswdset ; then
					until F_smtp_pswd ; do : ; done
					F_menu_exit
				fi
			;;

			R|r)
				F_terminal_erase
				F_terminal_warning
				F_terminal_show "This will remove all saved Email settings, custom text/subject/script,"
				F_terminal_show "and set all notification options to disabled"
				if F_confirm "Reset settings?" ; then
					[ "$status_amtm" = 1 ] && F_amtm remove

					F_replace_var created_date '' "$config_src"
					for remove_config in user_send_to_addr user_send_to_cc user_smtp_server user_from_addr user_message_type user_login_addr user_from_addr # userfromname is temp
					do
						[ -n "$remove_config" ] && F_replace_var "$remove_config" '' "$config_src"
					done

					[ -n "$user_custom_script" ] && F_replace_var 'user_custom_script' '' "$config_src"
					[ -n "$user_custom_subject" ] && F_replace_var 'user_custom_subject' '' "$config_src"
					[ -n "$user_custom_text" ] && F_replace_var 'user_custom_text' '' "$config_src"

					F_log_terminal_ok "User settings in config file reset"
					[ -f "$cred_loc" ] && rm -f "$cred_loc"  && F_log_terminal_ok "Removed saved password"
					F_replace_var user_email_from 'wicens script' "$config_src"

					F_auto_run removeall
					[ "$user_reboot_notification" = 1 ] && F_notify_reboot remove un
					[ "$user_fw_update_notification" = 1 ] && F_notify_firmware remove un
					[ "$user_update_notification" = 1 ] && F_notify_update remove un
					[ "$user_wanip_notification" = 1 ] && F_notify_wanip remove nouser > /dev/null 2>&1
					F_replace_var created_date '' "$config_src"
					F_log_terminal_ok "Script Email settings reset"
					F_terminal_check "Any key to continue..."
					read -rsn1
					F_clean_exit reset
				else
					F_terminal_check_ok "No, selected"
					F_menu_exit
				fi
			;;

			E|e) F_clean_exit reload ;;
			*) F_terminal_erase && F_fail_entry ;;
		esac
		break
	done

	F_edit_settings
} # edit_settings

F_amtm() {
	case "$1" in
		'check')
			if [ ! -f "$amtm_email_conf" ] || [ ! -f "$amtm_cred_loc" ] ; then
				return 1
			else
				for var_set_check in FROM_ADDRESS TO_NAME TO_ADDRESS FROM_ADDRESS USERNAME SMTP PORT PROTOCOL ; do
					pull_var=$(grep -F "$var_set_check" "$amtm_email_conf" | cut -d'=' -f2 | tr -d '"')
					[ -z "$pull_var" ] && return 1
				done
			fi
			return 0
		;;

		'create')
			building_settings=1
			F_replace_var amtm_import 1 "$config_src"
			F_replace_var created_date "$(F_date f)" "$config_src"
			F_log_terminal_ok "amtm Email settings enabled"
			F_amtm load
			building_settings=0
			return 0
		;;

		'load')
			source "$amtm_email_conf"
			user_send_to_addr="$TO_ADDRESS"
			user_login_addr="$USERNAME"
			user_from_addr="$FROM_ADDRESS"
			user_smtp_server="${SMTP}:${PORT}"
			user_message_type='smtp_ssl'
			protocol="$PROTOCOL"
			ssl_flag="$SSL_FLAG"
			return 0
		;;

		'remove')
			F_replace_var amtm_import 0 "$config_src"
			F_log_terminal_ok "amtm Email settings disabled"
			F_user_settings
			F_replace_var created_date '' "$config_src"   # set created date blank
			[ "$status_email_cfg" = 1 ] && F_replace_var created_date "$(F_date f)" "$config_src"   # script has saved settings that are good
			return 0
		;;
	esac

	F_terminal_show "${tYEL}===== amtm Email config sync enable/disable =====${tCLR}"

	if [ "$status_amtm" = 1 ] && [ "$amtm_import" = 0 ] ; then
		F_amtm create
	elif [ "$amtm_import" = 1 ] ; then
		F_amtm remove
	else
		F_terminal_check_fail "Cannot enable, amtm settings invalid"
	fi

	F_menu_exit
} # amtm

# NOTIFICATIONS #######################################################################################################
#######################################################################################################################

F_email_eg() {
	sample_email=1
	F_terminal_header
	F_terminal_show "${tYEL}===== wicens Email instructions =====${tCLR}   E||e to exit"
	F_terminal_padding
	F_terminal_show "Your script should create the text file containing the information below."
	F_terminal_show "For plain text Email only, please research how to implement HTML if needed"
	F_printf "$tGRN"
	F_printf "From: \"${user_email_from}\" <${user_from_addr}> ${tPUR}*from address set in wicens/amtm${tGRN}"
	F_printf "To: \"${user_msg_to}\" <${user_send_to_addr}>  ${tPUR}*or custom To: Email address passed on start${tGRN}"
	F_printfstr "Subject: Place your subject text here"
	F_printf "Date: $(date -R) ${tPUR}*Current date/time in RFC format use date -R command${tGRN}"
	F_printf "${tPUR}      *this space is required between Email header info and body text${tGRN}"

	# body
	F_printfstr "Hello world!"
	F_printfstr "This is my custom Email body text"
	F_email_seperator
	F_printfstr "Message sent: $(F_date f)"
	F_printfstr "Script ran with option : ${run_option}"
	F_printf "A message from wicens script v${script_version} on your ${fw_device_model}${tCLR}"
	F_terminal_show "End of Email content"
	sample_email=0

	F_menu_exit
} # email_eg

F_fw_update_email_msg() {
	if [ "$sample_email" = 0 ] ; then
		new_fw_ver="$(F_nvram webs_state_info)"
		new_fw_ver_pretty="$(F_printfstr "$new_fw_ver" | awk -F '_' '{print $2 "." $3 "_" $4}')"
		F_log_terminal_ok "Sending Email notification for available firmware update - v${new_fw_ver_pretty}"
	fi
	[ -f "$fw_email" ] && rm -f "$fw_email"
	mail_file="$fw_email"

	{
		# header
		F_printfstr "From: \"${user_email_from}\" <${user_from_addr}>"
		F_printfstr "To: \"${user_msg_to}\" <${user_send_to_addr}>"
		[ -n "$user_send_to_cc" ] && F_printfstr "Cc: ${user_send_to_cc}"
		if [ -z "$user_custom_subject_decoded_f" ]
		then F_printfstr "Subject: ${firmware_subject}"
		else F_printfstr "Subject: ${user_custom_subject_decoded_f}"
		fi
		F_printfstr "Date: $(F_date r)"

		# mime html
		if [ "$sample_email" = 0 ] ; then
			F_printfstr 'MIME-Version: 1.0'
			F_printfstr 'Content-Type: text/html; charset="UTF-8"'
			F_printfstr ''
			F_printfstr '<!DOCTYPE html>'
			F_printfstr '<html>'
			F_printfstr '<body>'
		else
			F_terminal_padding
		fi

		# body
		if [ "$test_mode" = 1 ] && [ "$sample_email" = 0 ] ; then
			F_printfp "<b>########## TEST message ##########</b>"
		else
			F_printfp "<b>********** NOTICE **********</b>"
		fi
		F_printfp "<b>A newer firmware version is available for ASUS router</b>"
		F_email_seperator
		F_printfpre "Model                : ${fw_device_model}"
		F_printfpre "Host/Domain          : ${fw_pulled_device_name}.${fw_pulled_lan_name}"
		F_printfpre "LAN IP               : ${fw_lan_addr}"
		F_printfp "Installed fw version : ${fw_build_full}"
		F_printfp "Available fw version : <b>${new_fw_ver_pretty}</b>"
		F_printfp "Visit <a href=\"https://www.asuswrt-merlin.net\">https://www.asuswrt-merlin.net</a>"
		[ -n "$user_custom_text_f" ] && F_email_seperator && F_printfpre "$(F_printf "${user_custom_text_f_decoded}")"
		F_email_seperator
		F_printfp "Message sent: $(F_date f)"
		F_printfp "Script ran with option : ${run_option}"
		F_printfp "A message from wicens script v${script_version}"

		# html footer
		F_printfstr '</body>'
		F_printfstr '</html>'
	} > "$fw_email"

	[ "$sample_email" = 1 ] && return 0

	###########################################################################
	if [ -f "$wicens_fw_retry" ] ; then
		F_printfstr "Attempting to send script fw update notification $(F_date r)" >> "$wicens_fw_retry"
	elif [ "$test_mode" = 0 ] ; then
		{
			F_printfstr "#!/bin/sh"
			F_printfstr "wicens_fw_retry_time=${run_epoch}"
			F_printfstr "# Attempting to send firmware update notification $(F_date r)"
		} > "$wicens_fw_retry"
		F_chmod "$wicens_fw_retry"
	fi

	F_internet_check fwupdate

	if ! F_send_email; then
		F_log_terminal_fail "Error, failed to send firmware update Email notification"
		user_pswd=''
		rm -f "$fw_email"
		cat "$mail_log" >> "$script_log_loc"
		return 1
	fi

	user_pswd=''
	rm -f "$fw_email"
	rm -f "$wicens_fw_retry" 2> /dev/null  # remove cron retry file
	F_log_terminal_ok "Finished sending firmware update Email notification"
	F_replace_var fw_notify_state 0 "$update_src"   # set 1 by caller, set 0 on success
	return 0
} # fw_update_email_msg

F_script_update_email_msg() {
	[ -f "$update_email" ] && rm -f "$update_email"
	mail_file="$update_email"

	{
		# header
		F_printfstr "From: \"${user_email_from}\" <${user_from_addr}>"
		F_printfstr "To: \"${user_msg_to}\" <${user_send_to_addr}>"
		[ -n "$user_send_to_cc" ] && F_printfstr "Cc: ${user_send_to_cc}"
		if [ -z "$user_custom_subject_decoded_s" ]
		then F_printfstr "Subject: ${script_subject}"
		else F_printfstr "Subject: ${user_custom_subject_decoded_s}"
		fi
		F_printfstr "Date: $(F_date r)"

		# mime html
		F_printfstr 'MIME-Version: 1.0'
		F_printfstr 'Content-Type: text/html; charset="UTF-8"'
		F_printfstr ''
		F_printfstr '<!DOCTYPE html>'
		F_printfstr '<html>'
		F_printfstr '<body>'

		# body
		F_printfp "<b>********** NOTICE **********</b>"
		F_printfp "<b>Update is available for wicens script</b>"
		F_email_seperator
		F_printfpre "Model       : ${fw_device_model}"
		F_printfpre "Host/Domain : ${fw_pulled_device_name}.${fw_pulled_lan_name}"
		F_printfpre "LAN IP      : ${fw_lan_addr}"
		F_email_seperator
		case "$update_avail" in
			'hotfix')
				F_printfp "A <b>hotfix</b> is available for v${script_version} of wicens"
				F_email_seperator # -----
				F_printfp "Change log  :"
				F_printfpre "$(/usr/sbin/curl -fsL --retry 3 --connect-timeout 5 "https://raw.githubusercontent.com/maverickcdn/wicens/master/CHANGELOG.md" | /bin/sed -n "/^## $script_version/,/^##/p" | head -n -1 | /bin/sed 's/## //')<br><br>"
			;;
			*)
				F_printfpre "Version     : <b>${update_avail}</b> is available"
				F_email_seperator # -----
				F_printfp "Change log  :"
				F_printfpre "$(/usr/sbin/curl -fsL --retry 3 --connect-timeout 5 "https://raw.githubusercontent.com/maverickcdn/wicens/master/CHANGELOG.md" | /bin/sed -n "/^## $git_version/,/^## $script_version/p" | head -n -1 | /bin/sed 's/## //')<br><br>"
			;;
		esac
		F_printfp "Run wicens script on your router and select option I||i to update"
		[ -n "$user_custom_text_s" ] && F_email_seperator && F_printfpre "$(F_printf "${user_custom_text_s_decoded}")"
		F_email_seperator # -----
		F_printfp "Message sent: $(F_date f)"
		F_printfp "Script ran with option : ${run_option}"
		F_printfp "A message from wicens script v${script_version}"

		# html footer
		F_printfstr '</body>'
		F_printfstr '</html>'
	} > "$update_email"

	[ "$sample_email" = 1 ] && return 0
	###########################################################################
	if ! F_send_email; then
		F_log_terminal_fail "Error, failed to send update Email notification"
		user_pswd=''
		rm -f "$update_email"
		cat "$mail_log" >> "$script_log_loc"
		return 1   # skip below hopefully resend next cron if message fail
	fi

	user_pswd=''
	rm -f "$update_email"
	rm -f "$wicens_update_retry"
	F_log_terminal_ok "Finished sending update Email notification"
	F_replace_var update_notify_state 1 "$update_src"
	return 0
} # script_update_email_msg

F_reboot_email_msg() {
	router_reboot_downtime="$(($(F_date s) - router_reboot_downtime))"    # time between last saved record and reboot call = 'downtime'
	[ -f "$reboot_email" ] && rm -f "$reboot_email"
	mail_file="$reboot_email"
	F_uptime

	if [ "$sample_email" = 0 ] || [ "$test_mode" = 0 ] ; then
		if [ ! -f '/tmp/wicens_reboot_uptime.tmp' ] ; then   # keep original found uptime for failed email retries
			F_printfstr "$router_reboot_uptime" > /tmp/wicens_reboot_uptime.tmp
			F_printfstr "$router_reboot_downtime" > /tmp/wicens_reboot_downtime.tmp
		else
			router_reboot_uptime="$(cat '/tmp/wicens_reboot_uptime.tmp')"   # were in a Email retry use initial saved
			router_reboot_downtime="$(cat '/tmp/wicens_reboot_downtime.tmp')"
		fi

		[ "$sample_email" = 0 ] && [ "$router_uptime" -lt 7200 ] && sleep "$reboot_notify_wait"   # sleep only for services-start call (not testing)
		[ "$sample_email" = 0 ] && F_log_terminal_ok "Sending router reboot notification to ${user_send_to_addr}"
	else
		router_reboot_downtime=0
		router_reboot_uptime="$router_uptime"
	fi

	{
		# header
		F_printfstr "From: \"${user_email_from}\" <${user_from_addr}>"
		F_printfstr "To: \"${user_msg_to}\" <${user_send_to_addr}>"
		[ -n "$user_send_to_cc" ] && F_printfstr "Cc: ${user_send_to_cc}"
		if [ -z "$user_custom_subject_decoded_r" ]
		then F_printfstr "Subject: ${reboot_subject}"
		else F_printfstr "Subject: ${user_custom_subject_decoded_r}"
		fi
		F_printfstr "Date: $(F_date r)"

		# mime html
		if [ "$sample_email" = 0 ] ; then
			# mime html
			F_printfstr 'MIME-Version: 1.0'
			F_printfstr 'Content-Type: text/html; charset="UTF-8"'
			F_printfstr ''
			F_printfstr '<!DOCTYPE html>'
			F_printfstr '<html>'
			F_printfstr '<body>'
		else
			F_terminal_padding
		fi

		# body
		if [ "$test_mode" = 1 ] ; then
			F_printfp "<b>########## TEST message ##########</b>"
		else
			F_printfp "<b>********** NOTICE **********</b>"
		fi
		F_printfp "<b>ASUS router has rebooted</b>"
		F_email_seperator # -----
		F_printfpre "Model       : ${fw_device_model}"
		F_printfpre "Host/Domain : ${fw_pulled_device_name}.${fw_pulled_lan_name}"
		F_printfpre "LAN IP      : ${fw_lan_addr}"
		F_email_seperator # -----
		F_printfpre "Current router uptime        : ${uptime_pretty}"
		F_printfpre "Downtime after shutdown      : $(printf '%3dd %2dh %2dm %2dsec\n' $((router_reboot_downtime/86400)) $((router_reboot_downtime%86400/3600)) $((router_reboot_downtime%3600/60)) $((router_reboot_downtime%60))) *"
		F_printfpre "Uptime saved prior to reboot : $(printf '%3dd %2dh %2dm %2dsec\n' $((router_reboot_uptime/86400)) $((router_reboot_uptime%86400/3600)) $((router_reboot_uptime%3600/60)) $((router_reboot_uptime%60))) *"
		F_printfpre "* approx"
		[ -n "$user_custom_text_r" ] && F_email_seperator && F_printfpre "${user_custom_text_r_decoded}"
		F_email_seperator # -----
		F_printfp "Message sent: $(F_date f)"
		F_printfp "Script ran with option : ${run_option}"
		F_printfp "A message from wicens script v${script_version}"

		# html footer
		F_printfstr '</body>'
		F_printfstr '</html>'
	} > "$reboot_email"

	[ "$sample_email" = 1 ] && return 0
	###########################################################################
	if [ -f "$wicens_reboot_retry" ] ; then
		F_printfstr "Attempting to send reboot notification $(F_date r)" >> "$wicens_reboot_retry"
	elif [ "$test_mode" = 0 ] ; then
		{
			F_printfstr "#!/bin/sh"
			F_printfstr "wicens_reboot_retry_time=${run_epoch}"
			F_printfstr "# Attempting to send reboot Email notification $(F_date r)"
		} > "$wicens_reboot_retry"
		F_chmod "$wicens_reboot_retry"
	fi

	F_internet_check reboot

	if ! F_send_email; then
		F_log_terminal_fail "Error - failed to send router reboot Email notification"
		user_pswd=''
		rm -f "$reboot_email"
		cat "$mail_log" >> "$script_log_loc"
		return 1
	fi

	user_pswd=''
	rm -f "$reboot_email"
	rm -f "$wicens_reboot_retry" 2> /dev/null
	rm -f '/tmp/wicens_reboot_uptime.tmp' 2> /dev/null
	rm -f '/tmp/wicens_reboot_downtime.tmp' 2> /dev/null
	F_log_terminal_ok "Success sending router reboot Email notification"
	F_replace_var reboot_notify_state 0 "$update_src"
	return 0
} # reboot_email_msg

F_wanip_email_msg() {
	[ "$sample_email" = 0 ] && F_log_terminal_ok "Attempting to send WAN IP change Email notification to $user_send_to_addr"
	[ -f "$wanip_email" ] && rm -f "$wanip_email"
	mail_file="$wanip_email"
	F_uptime

	if [ -n "$user_custom_subject_decoded" ] ; then
		formatted_custom_subject="$(F_printfstr "$user_custom_subject_decoded" | \
		/bin/sed "s~\$fw_device_model~$fw_device_model~g" | \
		/bin/sed "s~\$current_wan_ip~$current_wan_ip~g" | \
		/bin/sed "s~\$saved_wan_ip~$saved_wan_ip~g" | \
		/bin/sed "s~\$fw_pulled_lan_name~$fw_pulled_lan_name~g" | \
		/bin/sed "s~\$fw_pulled_device_name~$fw_pulled_device_name~g" | \
		/bin/sed "s~\$fw_lan_addr~$fw_lan_addr~g")"
		wan_subject="$formatted_custom_subject"
	fi

	{
		# header
		F_printfstr "From: \"${user_email_from}\" <${user_from_addr}>"
		F_printfstr "To: \"${user_msg_to}\" <${user_send_to_addr}>"
		[ -n "$user_send_to_cc" ] && F_printfstr "Cc: ${user_send_to_cc}"
		F_printfstr "Subject: ${wan_subject}"
		F_printfstr "Date: $(F_date r)"

		# mime html
		if [ "$sample_email" = 0 ] ; then
			F_printfstr 'MIME-Version: 1.0'
			F_printfstr 'Content-Type: text/html; charset="UTF-8"'
			F_printfstr ''
			F_printfstr '<!DOCTYPE html>'
			F_printfstr '<html>'
			F_printfstr '<body>'
		else
			F_terminal_padding
		fi

		# body
		if [ "$test_mode" = 1 ] && [ "$sample_email" = 0 ] ; then
			F_printfp "<b>########## TEST MESSAGE ##########</b>"
		else
			F_printfp "<b>********** NOTICE **********</b>"
		fi
		F_printfp "<b>WAN IP address has changed</b>"
		F_email_seperator # -----
		F_printfpre "Model       : ${fw_device_model}"
		F_printfp "Host/Domain : ${fw_pulled_device_name}.${fw_pulled_lan_name}"
		F_printfpre "LAN IP      : ${fw_lan_addr}"
		F_email_seperator # -----
		if F_printfstr "$current_wan_ip" | F_cgnat_ip ; then
			F_printfp "<b>Warning</b> - the new WAN IP is a <u>CGNAT</u> address"
			F_printfp "You may not be able to access your router from anywhere outside your local network"
			F_email_seperator # -----
		fi
		F_printfpre "New WAN IP  : <b>${current_wan_ip}</b>"
		F_printfpre "Old WAN IP  : ${saved_wan_ip}"
		F_printfpre "Old WAN IP recorded in script   : ${saved_wan_date}"
		F_printfpre "Old WAN IP lease time observed  : $(F_calc_lease)"
		F_printfpre "Router uptime                   : ${uptime_pretty}"
		[ -n "$user_custom_text" ] && F_email_seperator && F_printfpre "$(F_printf "${user_custom_text_decoded}")"   # preserve custom text new lines

		if [ -f "$history_src" ] ; then
			F_email_seperator # -----
			if [ "$(wc -l < "$history_src")" -ge 5 ]
			then F_printfpre "            WAN IP history (last ${wan_history_count}) most recent first"
			else F_printfpre "            WAN IP history most recent first"
			fi
			F_printfpre "    Time Found              IP             Leased time"
			F_email_seperator # -----
			tail -n "$wan_history_count" < "$history_src" | /bin/sed 'x;1!H;$!d;x' | /bin/sed 's/.*/<pre>&<\/pre>/'   # invert list
		elif [ "$sample_email" = 1 ] || [ "$test_mode" = 1 ] ; then
			F_email_seperator # -----
			F_printfpre "            WAN IP history most recent first"
			F_printfpre "    Time Found              IP             Leased Time"
			F_email_seperator # -----
			F_printfpre "Jan 01 2025 00:12:34  123.145.167.189   11d 12h 13m 14sec"
		fi

		F_email_seperator # -----
		F_printfp "Message sent : $(F_date f)"
		F_printfp "Script ran with option : ${run_option}"
		F_printfp "A message from wicens v${script_version}"

		# html footer
		F_printfstr '</body>'
		F_printfstr '</html>'
	} > "$wanip_email"

	###########################################################################
	[ "$sample_email" = 1 ] && return 0

	if [ -f "$wicens_wanip_retry" ] ; then
		F_printfstr "# Attempting to send wan ip change notification $(F_date r)" >> "$wicens_wanip_retry"
	elif [ "$test_mode" = 0 ] ; then
		{
			F_printfstr "#!/bin/sh"
			F_printfstr "wicens_wanip_retry_time=${run_epoch}"
			F_printfstr "# Attempting to send wan ip change notification $(F_date r)"
		} > "$wicens_wanip_retry"
		F_chmod "$wicens_wanip_retry"
	fi

	F_internet_check wanip

	if ! F_send_email; then
		# wanip email failed
		user_pswd=''
		rm -f "$wanip_email"
		F_log_terminal_fail "Error, script failed to send Email notification"
		F_log_show "Are your Email settings in this script correct? and password?"
		F_log_show "Or maybe your Email host server was temporarily down?"
		F_log_show "Main Menu - option L||l to view errors - P||p to re-enter password"
		[ "$test_mode" = 0 ] && F_log_show "Resetting WAN IP to old WAN IP to attempt again in ${cron_check_freq} minutes"
		cat "$mail_log" >> "$script_log_loc"

		F_replace_var saved_wan_date "$original_wan_date" "$config_src"
		F_replace_var saved_wan_epoch "$original_wan_epoch" "$config_src"
		F_replace_var saved_wan_ip "$original_wan_ip" "$config_src"

		case "$from_menu" in
			1) F_menu_exit ;;
			0) F_clean_exit ;;
		esac
	fi

	# success cleanup
	user_pswd=''
	rm -f "$wanip_email"
	rm -f "$wicens_wanip_retry" 2> /dev/null

	case "$test_mode" in
		0)
			F_log_terminal_ok "Success sending Email notification, update devices to $current_wan_ip"
			F_script_wan_update
		;;
		1) F_log_terminal_ok "Success sending test Email notification" ;;
	esac

	case "$from_menu" in
		1)
			case "$building_settings" in
				0) F_menu_exit ;;
				1) F_terminal_check_ok "This script is now configured" ; F_menu_exit ;;
			esac
		;;
	esac
} # wanip_email_message

# EMAIL CONTROL #######################################################################################################
#######################################################################################################################

F_send_email() {
	[ -f "$mail_log" ] && rm -f "$mail_log"
	F_printfstr "Created by PID $$ on $(F_date r), ran by $run_option" > "$mail_log"

	case "$amtm_import" in
		1) user_pswd="$(eval "$(F_printfstr "$amtm_d" | openssl base64 -d)" < "$amtm_cred_loc")" ;;
		0) [ "$user_message_type" != 'smtp_isp_nopswd' ] && user_pswd="$(eval "$(F_printfstr "$user_d" | openssl base64 -d)" < "$cred_loc")" ;;
	esac

	case "$user_message_type" in
		'smtp_isp_nopswd') F_send_format_isp && return 0 ;;
		'smtp_plain_auth') F_send_format_plain_auth && return 0 ;;
		'smtp_start_tls') F_send_format_start_tls && return 0 ;;
		'smtp_start_tls_v1') F_send_format_tls_v1 && return 0 ;;
		'smtp_ssl') F_send_format_ssl && return 0 ;;
	esac

	return 1
} # send_email

F_send_format_isp() {
	/usr/sbin/sendmail > "$mail_log" 2>&1 < "$mail_file" \
	-S "$user_smtp_server" -f "$user_login_addr" -t "$user_send_to_addr" -v
} # send_format_isp

F_send_format_start_tls() {
	/usr/sbin/sendmail >> "$mail_log" 2>&1 < "$mail_file" \
	-H "exec /usr/sbin/openssl s_client -quiet \
	-starttls smtp \
	-connect $user_smtp_server  \
	-no_ssl3 -no_tls1" \
	-t \
	-f "$user_from_addr" -au"$user_login_addr" -ap"$user_pswd" "$user_send_to_addr" -v
} # send_format_tls

F_send_format_tls_v1() {
	/usr/sbin/sendmail >> "$mail_log" 2>&1 < "$mail_file" \
	-H "exec /usr/sbin/openssl s_client -quiet \
	-tls1 -starttls smtp \
	-connect $user_smtp_server" \
	-t \
	-f "$user_from_addr" -au"$user_login_addr" -ap"$user_pswd" "$user_send_to_addr" -v
} # send_format_tls1

F_send_format_plain_auth() {
	/usr/sbin/sendmail >> "$mail_log" 2>&1 < "$mail_file" \
	-t -S "$user_smtp_server" -f "$user_from_addr" "$user_send_to_addr" -au"$user_login_addr" -ap"$user_pswd" -v
} # send_format_plain_auth

F_send_format_ssl() {
	ehlo_ip="\[$(F_nvram wan0_realip_ip)\]"
	if [ -z "$user_send_to_cc" ] ; then
		curl >> "$mail_log" 2>&1 \
		-v \
		--url "$protocol"://"$user_smtp_server"/"$ehlo_ip" \
		--mail-from "$user_from_addr" --mail-rcpt "$user_send_to_addr" \
		--upload-file "$mail_file" \
		--ssl-reqd \
		--crlf \
		--user "$user_login_addr:$user_pswd" $ssl_flag
	else
		curl >> "$mail_log" 2>&1 \
		-v \
		--url "$protocol"://"$user_smtp_server"/"$ehlo_ip" \
		--mail-from "$user_from_addr" --mail-rcpt "$user_send_to_addr" \
		--mail-rcpt "$user_send_to_cc" \
		--upload-file "$mail_file" \
		--ssl-reqd \
		--crlf \
		--user "$user_login_addr:$user_pswd" $ssl_flag
	fi
} # send_format_ssl

# SCRIPT UPDATES ######################################################################################################
#######################################################################################################################

F_web_update_check() {
	if [ "$1" = 'force' ] ; then
		F_terminal_header
		F_terminal_show "${tYEL}===== Script Update Check =====${tCLR}"
	else   # update found running install, check again
		[ "$update_avail" != 'none' ] && F_terminal_show "Confirming update ${tGRN}${update_avail}${tCLR} is most current "
		orig_update="$update_avail"   # keep note of original found update
	fi

	F_log_show "Checking for script update"
	F_internet_check

	# download wait timer for terminal git timeout 15secs
	update_time=15
	F_time() {
		while [ "$update_time" != 0 ] ; do
			F_term_waitdel "Checking for update ${tGRN}${update_time}${tCLR} secs"
			update_time=$((update_time - 1))
			sleep 1
			printf '\r%b' "$tERASE"
		done
	}

	# start terminal timer wait for var to set and kill timer
	F_time & child_pid="${child_pid} $!"
	git_version="$(F_git_get file | grep -Fm1 'script_version=' | cut -d'=' -f2 | sed "s/'//g")"
	server_md5="$(F_git_get file | md5sum | awk '{print $1}')"
	local_md5="$(md5sum "$script_name_full" | awk '{print $1}')"
	sleep 2   # pretty terminal wait

	if [ -z "$git_version" ] || [ -z "$server_md5" ] ; then
		kill "$child_pid" > /dev/null 2>&1
		printf '%b' "$tERASE$tBACK$tERASE"
		F_log_terminal_fail "Failed, could not read server script version or calc md5, aborting update check"
		F_wait 10
		return 1   # skip everything below
	fi

	kill "$child_pid" > /dev/null 2>&1
	F_replace_var update_cron_epoch "$(F_date s)" "$update_src"

	if [ "$script_version" = "$git_version" ] ; then
		if [ "$local_md5" != "$server_md5" ] ; then
			F_replace_var update_avail "hotfix" "$update_src"
			F_log "Success checking for update... hotfix available"
			F_terminal_check_ok "${tGRN}Success${tCLR} checking for update... ${tRED}hotfix${tCLR} available"
			F_terminal_padding
			F_terminal_show "Change log:"
			F_git_get hotfix
		else
			F_terminal_check_ok "${tGRN}Success${tCLR} checking for update... none available"
			# cleanup, if no update found, make sure update file is correct
			[ "$update_avail" != 'none' ] && F_replace_var update_avail 'none' "$update_src"
			[ "$update_notify_state" = 1 ] && F_replace_var update_notify_state 0 "$update_src"
		fi
	else
		F_replace_var update_avail "$git_version" "$update_src"
		F_log "Success checking for update... v${git_version} available"
		if [ "$1" = 'force' ] ; then   # manual update check
			F_terminal_check_ok "${tGRN}Success${tCLR} checking for update... Ver: ${tGRN}${git_version}${tCLR} available"
			F_terminal_padding
			F_terminal_show "Change log:"
			F_git_get update
		elif [ "$run_option" != 'cron' ] ; then # run by update installer verify newest or cron
			F_terminal_check_ok "${tGRN}Success${tCLR} checking for update..."
			if [ "$git_version" != "$orig_update" ] ; then
				F_git_get update
				F_log_terminal_ok "Will download newer version  v${git_version} vs originally found update v${orig_update}"
			else
				F_terminal_check_ok "v${git_version} is the most current available update"
			fi
			F_terminal_check "Any key to continue..."
			read -rsn1
		fi
	fi

	source "$update_src"   # resource config to update vars in current session
	[ "$1" = 'force' ] && F_menu_exit
	return 0
} # web_update_check

F_local_script_update() {
	F_terminal_header

	if [ "$update_avail" != 'none' ] && [ "$update_avail" != 'hotfix' ] ; then
		F_terminal_show "Update available - version $update_avail"
	elif [ "$update_avail" != 'none' ] && [ "$update_avail" = 'hotfix' ] ; then
		F_terminal_show "Hotfix update available!"
	fi

	if ! F_confirm "Proceed with installing script update?" ; then
		F_clean_exit reload
	fi

	if [ "$status_email_cfg" = 1 ] && [ ! -f "$script_backup_file" ] ; then
		F_terminal_padding ; F_terminal_erase
		F_terminal_warning
		F_terminal_check_fail "No backup file exists for your config." ; F_terminal_padding
		F_terminal_show "Continue upgrade without a backup?" ; F_terminal_padding
		F_terminal_check "C||c to continue upgrade w/o backup - Any key to return to Main Menu"
		read -rsn1 updatebackupwait
		case "$updatebackupwait" in
			C|c) clear ;;
			*) F_clean_exit reload ;;
		esac
	fi

	F_terminal_header
	F_terminal_check_ok "Installing..."
	F_terminal_check_ok "Starting script update to ver: $update_avail"

	# time between update found and current re-check give 60secs for menu update vs mail notification
	if [ "$(($(F_date s) - update_cron_epoch))" -gt 60 ] ; then
		F_web_update_check   # confirm saved update avail is current, notify if not
		F_terminal_header
	fi

	F_terminal_check "Downloading...."
	sleep 2

	if F_git_get download ; then
		F_terminal_check_ok "Success, script version $update_avail installed"

		# reset email notification for script update
		[ "$update_notify_state" = 1 ] && F_replace_var update_notify_state 0 "$update_src"
	else
		F_terminal_check_fail "Error, failed downloading/saving new script version"
		F_menu_exit
	fi

	F_terminal_padding
	git_version="$(grep -Fm1 'script_version=' "$script_name_full" | cut -d'=' -f2 | sed "s/'//g")"   # cut script version number from downloaded file
	F_terminal_show "Change log:"

	case "$update_avail" in
		'hotfix') F_git_get hotfix ;;
		*) F_git_get update ;;
	esac

	F_replace_var update_avail "none" "$update_src"
	F_replace_var update_date "$(F_date f)" "$config_src"

	F_terminal_padding

	F_log_terminal_ok "This install has been upgraded to version $git_version"
	F_terminal_check "Any key to continue..."
	read -rsn1
	F_clean_exit reset
} # local_script_update

F_integrity_check() {
	if [ "$update_settings_version" != "$current_core_config" ] ; then   # if new updated core config differs from saved, update
		old_version="$update_settings_version"

		F_terminal_header
		F_log_terminal_fail "Current script core config v${update_settings_version} is not current, starting update"
		config_updated=1   # prevents install message

		# current file is already sourced, remove file and change new file with loaded vars
		rm -f "$update_src"

		F_default_update_create
		source "$update_src"   # reset loaded for F_firmware_check
		F_log_terminal_ok "core config v${current_core_config} created, updating with current settings"

		[ "$(F_printf "$update_settings_version" | cut -d'.' -f1)" -le 3 ] && max_fw_nvram_check=0   # v3->v4 new config not yet sourced

		# if cron(cru) services-start wan-event enabled remove and reload
		if F_cru check ; then
			F_cru remove
			F_cru create
			F_log_terminal_ok "Updated cron(cru) entry"
		fi

		if F_serv_start check ; then
			F_serv_start remove
			F_serv_start create
			F_log_terminal_ok "Updated services-start entry"
		fi

		if F_wan_event check ; then
			F_wan_event remove
			F_wan_event create
			F_log_terminal_ok "Updated wan-event entry"
		fi

		F_printfstr "# Updated : v${old_version} to v${current_core_config} $(F_date r)" >> "$update_src"
		F_log_terminal_ok "Done, updated core config file from v${old_version} to v${current_core_config}"
		source "$update_src"
	fi

	if [ "$build_settings_version" != "$current_user_config" ] ; then   # if new updated user config differs from saved, update
		[ "$config_updated" != 1 ] && F_terminal_header   # only if we didnt update core config
		[ -n "$restore" ] && F_log_terminal_fail "Loaded backup config is outdated"
		F_log_terminal_fail "Current script user config v${build_settings_version} is not current, starting update"

		# current file is already sourced, remove file and change new file with loaded vars
		rm -f "$config_src"

		F_default_user_create
		F_log_terminal_ok "user config v${current_user_config} created, updating with current user settings"

		# v3->v4 adjustments ################### set new vars/format v3 vars/set new v4 vars w/loaded v3 config
		if [ "$(F_printfstr "$build_settings_version" | cut -d'.' -f1)" -le 3 ] ; then
			# added vars
			user_wanip_notification=1   # we assume if v3, wanip was enabled
			user_reboot_notification=0
			user_email_from='wicens script'
			# states are inverted
			if [ "$amtm_import" = 0 ] ; then amtm_import=1 ; else amtm_import=0 ; fi
			if [ "$user_update_notification" = 0 ] ; then user_update_notification=1 ; else user_update_notification=0 ; fi
			if [ "$user_fw_update_notification" = 0 ] ; then user_fw_update_notification=1 ; else user_fw_update_notification=0 ; fi
			if [ "$log_cron_msg" = 0 ] ; then log_cron_msg=1 ; else log_cron_msg=0 ; fi
			# var names were changed
			user_login_addr="$user_from_addr"
			user_from_addr="$user_from_name"
			# set to never if empty
			[ -z "$last_cron_run" ] && last_cron_run='never'
			[ -z "$last_wancall_run" ] && last_wancall_run='never'
			[ -z "$last_ip_change" ] && last_ip_change='never'
			[ -z "$update_date" ] && update_date='never'
			# change to new date format
			for var_update in last_cron_run last_wancall_run last_ip_change install_date update_date saved_wan_date created_date
			do
				new_value="$(eval "F_printfstr \"\${$var_update}\"" )"
				if [ -n "$new_value" ] && [ "$new_value" != 'never' ] ; then
					new_value="$(F_printfstr "$new_value" | sed 's/^... //;s/@ //g')"
					eval "$var_update=\"\$new_value\""
				else
					F_replace_var "$var_update" 'never' "$config_src"  # if blank in v3 force to never
				fi
			done

			if [ -f "$history_src" ] ; then
				sed -i 's/^... //;s/@ //g' "$history_src"
			fi

			# new color set vars
			case "$opt_color" in
				'yes') opt_color=1 ;;
				'no') opt_color=0 ;;
			esac

			[ -f '/tmp/wicens.lock' ] && rm -f /tmp/wicens.lock   # remove old v3 lock
		fi
		# end of v3->v4

		# v4.0->v4.1 wanip_monitor/user_msg_to
		[ -z "$user_msg_to" ] && user_msg_to='wicens user'
		if [ -z "$user_wanip_monitor" ] ; then
			case "$user_wanip_notification" in
				1)	user_wanip_monitor=1
					F_replace_var user_wanip_monitor '1' "$config_src"
				;;

				0)	user_wanip_monitor=0
					F_replace_var user_wanip_monitor '0' "$config_src"
				;;
			esac
		fi

		# update values in new default config with currently loaded config
		# build list of vars to update from old config, read them from old and set them
		sed '/#/d' "$config_src" | cut -d'=' -f1 | sed '/build_settings_version/d' | cut -d'=' -f1 > /tmp/wicens_config_copy.tmp

		while IFS= read -r config_line
		do
			value=$(eval F_printfstr "\"\$$config_line\"")
			F_replace_var "$config_line" "$value" "$config_src"
		done < '/tmp/wicens_config_copy.tmp'
		rm -f /tmp/wicens_config_copy.tmp

		F_printfstr "# Updated : v${build_settings_version} to v${current_user_config} $(F_date r)" >> "$config_src"
		F_log_terminal_ok "Done, updated user config file from v${build_settings_version} to v${current_user_config}"
		config_updated=1   # prevents install message
		source "$config_src"
	fi

	if [ "$config_updated" = 1 ] ; then
		fw_nvram_check_diff=$((max_fw_nvram_check + 1))   # if updated config force firmware check update
		F_firmware_check
		F_wait 60
		F_clean_exit reset
	fi
	return 0
} # integrity_check

# INTERNET ############################################################################################################
#######################################################################################################################

F_internet_ping() {

	# we ping websites to confirm DNS works for mail server lookup
	cycle_ping_count=1   # cycle through 15 good/bad pings if necessary till 6 good
	good_ping=0
	last_random=   # last random site chosen array

	while [ "$cycle_ping_count" -le 5 ] ; do  # 5 cycles x 3ping/cycle = 15 total failed / pass with 6 successful attempts
		random_site="$(F_random_num $(F_test_sites | wc -l))"   # pick random line #
		[ "${#last_random}" -ge 4 ] && last_random=   # refresh random array after 4 unique tests

		# if random picks one of last 3 recently tested sites try again
		if ! F_printfstr "$last_random" | grep -Fq "$random_site" ; then
			last_random="${last_random}$random_site"   # create array of tested sites from random_site
			tested_site="$(F_test_sites | sed -n "${random_site}p")"   # read line from list
			ping_try_count=0
			site_ping=0

			while [ "$ping_try_count" -ne 3 ] ; do   # ping site 3 times if fail then move on/otherwise 2 good move on
				if ping -q -w1 -c1 "$tested_site" > /dev/null 2>&1 ; then
					good_ping=$((good_ping + 1))
					site_ping=$((site_ping + 1))
					[ "$good_ping" -ge 6 ] && return 0
					[ "$site_ping" -ge 2 ] && break
				fi
				ping_try_count=$((ping_try_count + 1))
			done

			cycle_ping_count=$((cycle_ping_count + 1))
		fi
	done

	return 1
} # internet_ping   cycle through 2good/3bad pings to each random site till 6 good or 15 cycle attempts

F_internet_check() {
	internet_check_count=0
	F_printfstr "$(F_date s)" > "$internet_lock"

	# 10 attempts
	while [ "$internet_check_count" -le 11 ] ; do
		internet_check_count=$((internet_check_count + 1))

		# failed cleanup exit
		if [ "$internet_check_count" -eq 11 ] ; then
			F_log_terminal_fail "Could not ping $(F_test_sites | wc -l) test sites for the last 5 mins, exiting. Run again with next cron"

			# remove entry from wanip,send,update,fwupdate to retry again after internet up
			if [ -n "$1" ] ; then
				case "$1" in
					'wanip') file_line_remove="$wicens_wanip_retry" ;;
					'send') file_line_remove="$wicens_send_retry" ;;
					'update') file_line_remove="$wicens_update_retry" ;;
					'fwupdate') file_line_remove="$wicens_fw_retry" ;;
					'reboot') file_line_remove="$wicens_reboot_retry" ;;
				esac

				sed '$d' "$file_line_remove"
				F_log "Removed retry line from $file_line_remove"
			fi

			rm -f "$internet_lock"
			F_clean_exit
		fi

		# ping test
		F_terminal_check "Checking Internet status..."

		if F_internet_ping ; then
			[ "$1" != 'mini' ] && F_log_terminal_ok "Internet check 6 successful pings, appears up"
			break
		else
			F_log_terminal_fail "Failed pings to 3-5 sites, Internet down?"
			wait_secs=30

			while [ "$wait_secs" -ne 0 ] ; do
				F_term_waitdel "$wait_secs before next attempt"
				sleep 1
				wait_secs=$((wait_secs - 1))
			done
		fi
	done

	rm -f "$internet_lock"
	return 0
} # internet_check

# WAN IP ##############################################################################################################
#######################################################################################################################

F_compare() {
	[ "$fw_sw_mode" = 1 ] && F_terminal_check_ok "Getting current WAN IP from nvram"
	current_wan_ip="$(F_nvram wan0_ipaddr)"

	if [ -z "$current_wan_ip" ] || [ "$current_wan_ip" = '0.0.0.0' ] ; then
		if [ "$fw_sw_mode" = 1 ] ; then
			F_log_terminal_fail "No valid IP found in NVRAM, checking with getrealip.sh"   # log nothing in nvram
			F_getrealip
		else
			F_ministun
		fi
	elif F_printfstr "$current_wan_ip" | F_private_ip ; then
		F_terminal_check_fail "nvram WAN IP ${current_wan_ip} is a private IP, using wan0_realip_ip"   # don't log if WAN IP is private (double nat)
		current_wan_ip="$(F_nvram wan0_realip_ip)"
		if [ -z "$current_wan_ip" ] || [ "$current_wan_ip" = '0.0.0.0' ] ; then
			if [ "$fw_sw_mode" = 1 ] ; then
				F_terminal_check_fail "nvram wan0_realip_ip is empty forcing update with getrealip.sh"
				F_getrealip
			else
				F_ministun
			fi
		fi
	fi

	# is WAN IP valid
	if F_printfstr "$current_wan_ip" | F_private_ip ; then
		F_log_terminal_fail "WAN IP ${current_wan_ip} is a private IP, something is wrong"
		[ "$run_option" = 'tty' ] && F_menu_exit
		F_clean_exit error
	fi

	if [ "$current_wan_ip" = "$saved_wan_ip" ] ; then
		F_terminal_check_ok "WAN IP lookup  - Current WAN IP :  ${tGRN}${current_wan_ip}${tCLR}"
		F_terminal_check_ok "WAN IP compare - Saved WAN IP   :  ${tGRN}${saved_wan_ip}${tCLR}"
		[ "$run_option" = 'wancall' ] && F_log "Saved WAN IP matches current IP"   # verify wan-event checks
		if F_printfstr "$current_wan_ip" | F_cgnat_ip ; then
			F_terminal_fail "Notice - Your WAN IP ${current_wan_ip} appears to be a CGNAT address"
		fi
		return 0
	else
		F_terminal_check_ok "WAN IP lookup  - Current WAN IP :  ${tGRN}$current_wan_ip${tCLR}"
		F_terminal_check_fail "WAN IP compare - Saved WAN IP   :  ${tRED}$saved_wan_ip${tCLR}"
		[ -n "$saved_wan_ip" ] && [ "$building_settings" = 0 ] && F_log_terminal_fail "WAN IP has changed to ${current_wan_ip} "
		if F_printfstr "$current_wan_ip" | F_cgnat_ip ; then
			F_log_terminal_fail "Notice - New WAN IP ${current_wan_ip} appears to be a CGNAT address"
		fi

		# user_custom_script 'immediate' call
		[ "$run_option" = 'tty' ] && [ -n "$user_custom_script" ] && F_terminal_show "Notice - custom script is set to execute but will not run in terminal IP compare"
		if [ -n "$user_custom_script" ] && [ "$building_settings" = 0 ] && [ "$test_mode" = 0 ] && [ ! -f '/tmp/wicens_user_script_i.tmp' ] && [ "$run_option" != 'tty' ] ; then
			if [ "$user_custom_script_time" = 'i' ] ; then
				nohup /bin/sh "$user_custom_script_decoded" "$current_wan_ip" > "$user_script_log" 2>&1 & custom_script_pid=$!
				F_log_terminal_ok "Executed custom script ${user_custom_script_decoded} and put in background with PID ${custom_script_pid}"
				touch /tmp/wicens_user_script_i.tmp   # prevent duplicate runs if email fails on first detection as this will run
			fi
		fi
		return 1
	fi
} # compare

F_getrealip() {
	F_internet_check
	getrealip_cnt="$getrealip_max"   # max tries to get WAN IP

	F_doiplook() {   # watcher for getrealip.sh so if it hangs it doesnt sit around forever
		(sh /usr/sbin/getrealip.sh | grep -Eo "$ip_regex" ) & command_pid=$!
		(sleep 5 && /bin/kill -HUP "$command_pid" 2> /dev/null && rm -f /tmp/wicenswanipget.tmp && F_log_terminal_fail 'Notice - Killed hung getrealip.sh process after 5 secs' ) & watcher_pid=$!
		wait "$command_pid" && /bin/kill -HUP "$watcher_pid" 2> /dev/null
		getrealip_cnt=$((getrealip_cnt - 1))
	} # getrealip

	while [ "$getrealip_cnt" -ne 0 ] ; do
		F_terminal_check_ok "Retrieving WAN IP using /usr/sbin/getrealip.sh (STUN lookup)"
		F_doiplook > /tmp/wicenswanipget.tmp   # output to file or watcher doesnt function properly when var=
		current_wan_ip="$(grep -Eo "$ip_regex" /tmp/wicenswanipget.tmp 2> /dev/null)"
		[ -f /tmp/wicenswanipget.tmp ] && rm -f /tmp/wicenswanipget.tmp

		if [ "$current_wan_ip" = '0.0.0.0' ] || [ -z "$current_wan_ip" ] ; then
			if [ "$getrealip_cnt" -eq 0 ] ; then
				F_log_terminal_fail "Error retrieving WAN IP ${getrealip_max} times, aborting"
				F_clean_exit error
			else
				reattempt="$(F_random_num 15)"
				F_terminal_check_fail "Error retrieving WAN IP with getrealip.sh, attempt again in ${reattempt} secs"
				sleep "$reattempt"
				F_terminal_erase
			fi
		else
			break
		fi
	done
	return 0
} # getrealip

F_ministun() {
	last_random_mini=
	F_internet_check mini
	stun_list="$(F_stun_servers | wc -l)"
	stun_count="$stun_max"   # copy stun_max from config for writeable var

	while [ "$stun_count" -gt 0 ] ; do
		server_attempt=0
		while [ "${#server_attempt}" -lt "$stun_list" ] ; do
			server_random="$(F_random_num $stun_list)"

			if ! F_printfstr "$last_random_mini" | grep -Fq "$server_random" ; then
				last_random_mini="${last_random_mini}$server_random"
				server_attempt=$((server_attempt + 1))
				stun_server="$(F_stun_servers | sed -n "${server_random}p")"
				F_terminal_check_ok "Retrieving WAN IP w/ STUN server:  ${tGRN}${stun_server}${tCLR}"
				current_wan_ip="$(ministun -t 1000 -c 1 "$stun_server" 2>/dev/null)"
				[ $? = 0 ] && break

				F_terminal_check_fail "Failed lookup at STUN server: ${stun_server}"
				current_wan_ip=
			fi
		done

		if [ "$current_wan_ip" = '0.0.0.0' ] || [ -z "$current_wan_ip" ] ; then
			if [ "$stun_count" -eq 1 ] ; then
				F_log_terminal_fail "Error retrieving WAN IP with ministun ${stun_max} times at ${stun_list} servers... aborting"
				case "$run_option" in
					'tty') F_menu_exit ;;
				esac
				F_clean_exit error
			else
				reattempt="$(F_random_num 15)"
				F_terminal_check_fail "Error retrieving WAN IP with ministun, attempt again in ${reattempt} secs"
				sleep "$reattempt"
				F_terminal_erase
				stun_count=$((stun_count - 1))
			fi
		else
			break
		fi
	done

	return 0
} # ministun

F_calc_lease() {
	current_epoch="$(F_date s)"
	[ -n "$saved_wan_epoch" ] && epoch_diff=$((current_epoch - saved_wan_epoch))
	if [ -z "$saved_wan_epoch" ] ; then
		F_printfstr '  0d  0h  0m  0sec'
	else
		F_printfstr "$(printf '%3dd %2dh %2dm %2dsec\n' $((epoch_diff/86400)) $((epoch_diff%86400/3600)) $((epoch_diff%3600/60)) $((epoch_diff%60)))"
	fi
} # calc_lease

F_script_wan_update() {
	[ -z "$saved_wan_ip" ] && building_settings=1
	if [ "$building_settings" = 1 ] ; then   # first run
		F_terminal_check_ok "Current WAN IP ${current_wan_ip} successfully retrieved"
	else
		# write IP history records before updating
		F_replace_var last_ip_change "$(F_date f)" "$config_src"
		printf '%-20s  %-15s  %s\n' "$saved_wan_date" "$saved_wan_ip" "$(F_calc_lease)" >> "$history_src"
		ip_change_count=$((ip_change_count + 1))   # update script IP changes after success
		F_replace_var ip_change_count "$ip_change_count" "$config_src"

		# user_custom_script 'wait' call
		[ "$run_option" = 'tty' ] && [ -n "$user_custom_script" ] && [ "$user_custom_script_time" = 'w' ] && F_terminal_show "Notice - custom script is set to execute but will not run in terminal IP compare"
		if [ -n "$user_custom_script" ] && [ "$user_custom_script_time" = 'w' ] && [ "$run_option" != 'test' ] && [ "$run_option" != 'tty' ] ; then
			nohup /bin/sh "$user_custom_script_decoded" "$current_wan_ip" > "$user_script_log" & custom_script_pid=$!
			F_log_terminal_ok "Executed custom script ${user_custom_script_decoded} and put in background with PID ${custom_script_pid}"
		fi

		# clean up custom script 'immediate' call lock
		if [ -f /tmp/wicens_user_script_i.tmp ] && [ "$test_mode" = 0 ] ; then
			rm -f /tmp/wicens_user_script_i.tmp   # immediate call lock file remove after success
		fi
	fi

	F_replace_var saved_wan_ip "$current_wan_ip" "$config_src"
	F_replace_var saved_wan_date "$(F_date f)" "$config_src"
	F_replace_var saved_wan_epoch "$(F_date s)" "$config_src"
	F_log_terminal_ok "Updated script with WAN IP ${current_wan_ip}"
	return 0
} # script_wan_update

# AUTO RUN ############################################################################################################
#######################################################################################################################

F_cru() {
	case "$1" in
		'check')
			cru l | grep -Fq "$script_name_full" && status_cru=1 && return 0
			status_cru=0 && return 1
		;;

		'create')
			cru a wicens "${cron_string}"
			F_log_terminal_ok "Added entry in cron(cru) with ${cron_check_freq}m interval"
			F_cru check   # update status_cru immediately
		;;

		'remove')
			if F_cru check ; then
				cru d wicens
				F_log_terminal_ok "Removed entry in cron(cru)"
			else
				F_log_terminal_ok "No entry in cron(cru) to remove"
			fi
			F_cru check   # update status_cru immediately
		;;
	esac
	return 0
} # cru

F_serv_start() {
	case "$1" in
		'check')
			grep -Fq "${script_name_full} cron" /jffs/scripts/services-start 2> /dev/null && status_srvstrt=1 && return 0
			status_srvstrt=0 && return 1
		;;

		'create')
			if [ -f /jffs/scripts/services-start ] ; then
				F_crlf '/jffs/scripts/services-start'
				F_chmod '/jffs/scripts/services-start'

				if ! grep -Fq '#!/bin/sh' /jffs/scripts/services-start ; then
					sed -i '1 i\#!/bin/sh' /jffs/scripts/services-start
					F_log_terminal_fail "Your services-start does not contain a '#!/bin/sh'"
					F_log_terminal_ok "Added #!/bin/sh to top of services-start file"
				fi

				{
					F_printfstr "/usr/sbin/cru a wicens \"${cron_string}\"   # added by wicens $(F_date r)"
					F_printfstr "/usr/bin/logger -t \"services-start[\$\$]\" \"Added wicens entry to cron(cru)\"   # added by wicens $(F_date r)"
				} >> /jffs/scripts/services-start

				F_log_terminal_ok "Added entry in /jffs/scripts/services-start for cron(cru)"
			else
				{
					F_printfstr "#!/bin/sh"
					F_printfstr "# Created by ${script_name_full} for WAN IP change notification $(F_date r)"
					F_printfstr "/usr/sbin/cru a wicens \"${cron_string}\"   # added by wicens $(F_date r)"
					F_printfstr "/usr/bin/logger -t \"services-start[\$\$]\" \"Added wicens entry to cron(cru)\"   # added by wicens $(F_date r)"
				} > /jffs/scripts/services-start

				F_chmod '/jffs/scripts/services-start'
				F_log_terminal_ok "Created /jffs/scripts/services-start and added entry for cron(cru)"
			fi
			F_serv_start check
		;;

		'remove')
			if [ -f /jffs/scripts/services-start ] ; then
				if grep -Fq "${script_name_full} cron" /jffs/scripts/services-start ; then
					sed -i '/added by wicens/d' /jffs/scripts/services-start
					F_log_terminal_ok "Removed entry in /jffs/scripts/services-start for cron(cru)"
				else
					F_log_terminal_ok "No entry in /jffs/scripts/services-start for cron(cru) to remove"
				fi

				if [ "$(wc -l < /jffs/scripts/services-start )" -eq 1 ] ; then
					if grep -Fq '#!/bin/sh' /jffs/scripts/services-start ; then
						F_log_terminal_ok "/jffs/scripts/services-start appears empty, removing file"
						rm -f /jffs/scripts/services-start
					fi
				fi
			else
				F_log_terminal_ok "No entry in /jffs/scripts/services-start for cron(cru), file doesn't exist"
			fi
			F_serv_start check
		;;
	esac
	return 0
} # serv_start

F_wan_event() {
	case "$1" in
		'check')
			grep -Fq "${script_name_full} wancall" /jffs/scripts/wan-event 2> /dev/null && status_wanevent=1 && return 0
			status_wanevent=0 && return 1
		;;

		'create')
			if [ -f /jffs/scripts/wan-event ] ; then
				F_crlf '/jffs/scripts/wan-event'
				F_chmod '/jffs/scripts/wan-event'

				if ! grep -Fq '#!/bin/sh' /jffs/scripts/wan-event ; then
					sed -i '1 i\#!/bin/sh' /jffs/scripts/wan-event
					F_log_terminal_fail "Your wan-event does not contain a '#!/bin/sh'"
					F_log_terminal_ok "Added #!/bin/sh to top of wan-event file"
				fi

				{
					F_printfstr "[ \"\$2\" = \"connected\" ] && nohup sh ${script_name_full} wancall & wicenspid=\$!  # added by wicens $(F_date r)"
					F_printfstr "[ \"\$2\" = \"connected\" ] && /usr/bin/logger -t \"wan-event[\$\$]\" \"Started wicens with pid \${wicenspid}\"   # added by wicens $(F_date r)"
				} >> /jffs/scripts/wan-event

				F_log_terminal_ok "Added entry in /jffs/scripts/wan-event with connected event trigger"
			else
				{
					F_printfstr "#!/bin/sh"
					F_printfstr "# Created by ${script_name_full} for WAN IP change notification   # added by wicens $(F_date r)"
					F_printfstr "[ \"\$2\" = \"connected\" ] && nohup sh ${script_name_full} wancall & wicenspid=\$!   # added by wicens $(F_date r)"
					F_printfstr "[ \"\$2\" = \"connected\" ] && /usr/bin/logger -t \"wan-event[\$\$]\" \"Started wicens with pid \${wicenspid}\"   # added by wicens $(F_date r)"
				} > /jffs/scripts/wan-event

				F_chmod '/jffs/scripts/wan-event'
				F_log_terminal_ok "Created /jffs/scripts/wan-event and added connected event trigger"
			fi
			F_wan_event check
		;;

		'remove')
			if [ -f /jffs/scripts/wan-event ] ; then
				if grep -Fq "${script_name_full} wancall" /jffs/scripts/wan-event ; then
					sed -i '/added by wicens/d' /jffs/scripts/wan-event
					F_log_terminal_ok "Removed entry in /jffs/scripts/wan-event"
				else
					F_log_terminal_ok "No entry in /jffs/scripts/wan-event to remove"
				fi

				if [ "$(wc -l < /jffs/scripts/wan-event)" -eq 1 ] ; then
					if grep -Fq '#!/bin/sh' /jffs/scripts/wan-event ; then
						F_log_terminal_ok "/jffs/scripts/wan-event appears empty, removing file"
						rm -f /jffs/scripts/wan-event
					fi
				fi
			else
				F_log_terminal_ok "No entry in /jffs/scripts/wan-event - file doesn't exist"
			fi
			F_wan_event check
		;;
	esac
	return 0
} # wan_event

F_auto_run() {
	case "$1" in
		'createall')
			if [ "$status_cru" = 0 ] ; then F_cru create ; else F_terminal_check_ok "cron(cru) entry already enabled" ; fi
			if [ "$status_srvstrt" = 0 ] ; then F_serv_start create ; else F_terminal_check_ok "services-start entry already enabled" ; fi
			if [ "$status_wanevent" = 0 ] ; then
				if [ "$fw_sw_mode" = 1 ]
				then F_wan_event create   # only enable wan-event if in router mode
				else F_terminal_check_ok "Not in router mode, skipping wan-event"
				fi
			else
				F_terminal_check_ok "wan-event entry already enabled"
			fi
		;;

		'create2')
			if [ "$status_cru" = 0 ] ; then F_cru create ; else F_terminal_check_ok "cron(cru) entry already enabled" ; fi
			if [ "$status_srvstrt" = 0 ] ; then F_serv_start create ; else F_terminal_check_ok "services-start entry already enabled" ; fi
		;;

		'removeall')
			F_cru remove
			F_serv_start remove
			F_wan_event remove
		;;

		'remove2')
			F_cru remove
			F_serv_start remove
		;;

		'testall')
			F_cru check
			F_serv_start check
			F_wan_event check
		;;
	esac
	return 0
} # auto_run

# SETTINGS TEST #######################################################################################################
#######################################################################################################################

F_settings_test() {

	# amtm check valid/load ###################################################
	status_amtm=0
	if F_amtm check ; then
		case "$amtm_import" in
			1) F_amtm load ;;
		esac
		status_amtm=1
	fi

	case "$amtm_import" in
		1)
			case "$status_amtm" in
				0)
					F_terminal_header
					F_log_terminal_fail "Error - script set to load amtm settings but amtm settings invalid"
					F_log_terminal_fail "Notice - disabling amtm import, run script to re-enable"
					F_replace_var amtm_import 0 "$config_src"
					if [ "$run_option" != 'tty' ] ; then
						F_log_show "If valid settings were created inside this script, will try with those settings"
					else
						F_wait 15
					fi
				;;
			esac
		;;
	esac

	# email settings valid ####################################################
	status_email_cfg=1
	[ -z "$user_login_addr" ] && [ -n "$user_from_addr" ] && user_login_addr="$user_from_addr"   # v3-v4 opt_restore status page
	if [ -z "$user_from_addr" ] || [ -z "$user_message_type" ] || [ -z "$user_send_to_addr" ] || [ -z "$user_smtp_server" ] || [ -z "$user_login_addr" ] ; then
		status_email_cfg=0
		[ "$run_option" != 'tty' ] && [ "$user_wanip_monitor" = 0 ] && F_log "Missing core settings"
		fail_reason="$(printf "[%bFAIL%b] Missing core Email settings \n\n" "$tRED" "$tCLR")"
	elif [ ! -f "$cred_loc" ] && [ "$user_message_type" != 'smtp_isp_nopswd' ] && [ "$status_email_cfg" = 1 ] && [ "$amtm_import" = 0 ] ; then
		fail_reason="$(printf "[%bFAIL%b] Email send type set to %s but missing required password \n\n" "$tRED" "$tCLR" "$user_message_type")"
		[ "$run_option" != 'tty' ] && [ "$user_wanip_monitor" = 0 ] && F_log "Email send type set to ${user_message_type} but missing required password"
		status_email_cfg=0
	fi

	# auto-run services #######################################################
	F_auto_run testall

	# config file sanity checks ###############################################
	# email settings dont exist disable all
	case "$status_email_cfg" in
		0)
			[ "$user_wanip_notification" = 1 ] && F_notify_wanip remove nouser
			[ "$user_update_notification" = 1 ] && F_notify_update remove
			[ "$user_fw_update_notification" = 1 ] && F_notify_firmware remove
			[ "$user_reboot_notification" = 1 ] && F_notify_reboot remove
		;;
	esac

	# enabled option dependencies check #######################################
	if [ -z "$restore" ] ; then   # only if not run with backup restore
		# check wan ip notification dependencies
		[ "$user_wanip_notification" = 1 ] && [ "$user_wanip_monitor" = 0 ] && F_wanip_monitor create

		# check monitor depenencies
		if [ "$user_wanip_monitor" = 1 ] ; then
			if [ "$fw_sw_mode" = 1 ] ; then
				if [ "$status_cru" = 0 ] || [ "$status_srvstrt" = 0 ] || [ "$status_wanevent" = 0 ] ; then
					F_auto_run createall
				fi
			else
				if [ "$status_cru" = 0 ] || [ "$status_srvstrt" = 0 ] ; then
					F_auto_run create2
				fi
			fi
		else
			[ "$status_wanevent" = 1 ] && F_wan_event remove
		fi

		# notifications disabled but auto runs exist - remove them ############
		if [ "$status_cru" = 1 ] || [ "$status_srvstrt" = 1 ] ; then
			if [ "$user_wanip_notification" = 0 ] && [ "$user_reboot_notification" = 0 ] && [ "$user_fw_update_notification" = 0 ] && [ "$user_update_notification" = 0 ] && [ "$user_wanip_monitor" = 0 ] ; then
				F_auto_run removeall > /dev/null 2<&1
			fi
		fi

		# notifications enabled but no auto run exists - create auto runs #####
		if [ "$user_update_notification" = 1 ] || [ "$user_reboot_notification" = 1 ] || [ "$user_fw_update_notification" = 1 ] ; then
			if [ "$status_cru" = 0 ] || [ "$status_srvstrt" = 0 ] ; then
				F_auto_run create2
			fi
		fi

		# firmware enabled but no entry in update-notification - add it #######
		if [ "$user_fw_update_notification" = 1 ] ; then
			! F_notify_firmware check status && F_notify_firmware create
		fi

		# reboot enabled but no entry in services-start - add it ##############
		if [ "$user_reboot_notification" = 1 ] ; then
			! F_notify_reboot check status && F_notify_reboot create
		fi

		# custom script file check (spam the log) - auto disable w/tty ########
		if [ -n "$user_custom_script" ] ; then
			if [ ! -f "$user_custom_script_decoded" ] ; then
				F_log_terminal_fail "Error - custom script ${user_custom_script_decoded} is set to run but file is not there"
			else
				[ -z "$user_custom_script_time" ] && F_log_terminal_fail "Error - custom script is set to run but runtime is missing"
			fi

			F_wanip_monitor check   # havent yet checked
			F_notify_wanip check
			if [ "$status_wanipmon" = 0 ] ; then
				F_log_terminal_fail "Error - custom script ${user_custom_script_decoded} is set to run but WAN IP monitor is not enabled, removing"
				F_opt_script remove
				[ "$run_option" = 'tty' ] && F_wait 15
			else
				if [ "$status_wanip" = 0 ] && [ "$user_custom_script_time" = 'w' ] ; then
					F_log_terminal_fail "Error - custom script time set to wait but WAN IP Email disabled"
					F_replace_var user_custom_script_time 'i' "$config_src"
					F_log_terminal_ok "Switched custom script time to immediate"
					[ "$run_option" = 'tty' ] && F_wait 15 && F_clean_exit reload
				fi
			fi
		fi
	fi

	# CHECK NOTIFY STATUS FOR MENU ############################################
	F_notify_firmware check
	F_notify_reboot check
	F_notify_update check
	F_notify_wanip check
	F_wanip_monitor check

	# CLEAN UP ################################################################
	# only with tty
	case "$run_option" in
		'tty')
			# clean old user_pswd if setup was edited/proper config doesnt exist
			if [ "$status_email_cfg" = 0 ] || [ "$user_message_type" = 'smtp_isp_nopswd' ] ; then
				if [ -f "$cred_loc" ] ; then
					rm -f "$cred_loc"
					F_terminal_header
					F_log_show "Removed old saved password, invalid Email type or invalid Email settings"
					[ "$run_option" = 'tty' ] && F_wait 10
				fi
			fi

			# cleanup password backup if config backup doesnt exist ###########
			[ -f "$cred_loc_bak" ] && [ ! -f "$script_backup_file" ] && rm -f "$cred_loc_bak"

			# started custom script entry and wrote time but exited ###########
			[ -n "$user_custom_script_time" ] && [ -z "$user_custom_script" ] && F_replace_var user_custom_script_time '' "$config_src"

			# custom script loaded but can no longer find script ##############
			if [ -n "$user_custom_script" ] && [ ! -f "$user_custom_script_decoded" ] ; then
				F_terminal_header
				F_terminal_warning
				F_terminal_check_fail "Custom script set to $user_custom_script_decoded but can't find file"
				F_terminal_padding
				F_log_show "Disabling custom script on WAN IP change option"
				F_terminal_padding
				F_opt_script remove
				F_wait 15
			fi
		;;
	esac
	return 0
} # settings_test

F_ready_check() {
	[ "$status_wanipmon" = 1 ] && return 0   # if wanipmon enabled we dont care if email is configured for cron to run
	case "$status_email_cfg" in
		0)
			if [ "$run_option" = 'tty' ] && [ "$from_menu" = 1 ] ; then
				[ "$1" = 'pswdset' ] && return 0
				[ "$1" != 'options' ] && F_terminal_header   # not sent here from a menu option, displayed already
				F_terminal_check_fail "Error - no Email settings have been setup"
				F_terminal_padding
				F_terminal_show "Use menu option 1 to add settings"
				F_menu_exit
			else
				F_log "Error - no config or incomplete Email config found in this script"
				F_log "Run $script_name_full to add a config to this script"
				F_clean_exit error
			fi
		;;

		1) # passes test but trying to establish pswd with isp_type or incomplete settings
			case "$1" in
				'pswdset')
					if [ "$user_message_type" = 'smtp_isp_nopswd' ] ; then
						F_terminal_padding
						F_terminal_check_fail "Cannot add password, SMTP type is set to ISP type"
						F_terminal_padding
						F_menu_exit
					fi
				;;
			esac
			return 0
		;;
	esac
} # ready_check

# STATUS/TERMINAL #####################################################################################################
#######################################################################################################################

F_terminal_header() {
	clear
	case "$1" in
		exit) sed -n '3,8p' "$script_name_full" | sed 's/#//g' | sed 's/^.\{14\}//' ; return 0 ;;
		'') sed -n '2,11p' "$script_name_full" ; F_printf "${tBACK}${tBACK}#                                                              pid $$ v${script_version}\n" ;;
	esac

	case "$fw_build_no" in
		'384'|'386'|'388') F_printf "       ${tGRN}$(F_date r)${tCLR}    Model: ${tGRN}${fw_device_model}${tCLR} FW: ${tGRN}${fw_build_full}${tCLR}" ;;
		'374') F_printf "   ${tGRN}$(F_date r)${tCLR}    ${tGRN}${fw_device_model}${tCLR} FW ver: ${tGRN}${fw_build_no}.${fw_build_extend}${tCLR}" ;;
	esac

	F_terminal_separator

	case "$building_settings" in
		1)
			F_terminal_padding
			F_printf "[${tGRN} HI${tCLR} ] ${tYEL}===== Welcome to the wicens Email setup wizard =====${tCLR}   E||e to exit"
			if [ "$selection" = '1f' ] && [ "$amtm_import" = 1 ] ; then
				F_terminal_warning
				F_terminal_show "amtm import enabled"
				F_terminal_show "script will save your entries but will continue using amtm config"
			fi
		;;
	esac

	case "$test_mode" in
		1)
			F_terminal_padding
			F_printf "[${tYEL}INFO${tCLR}] ${tYEL}===== Test Mode - Sending 1 test message =====${tCLR}"
		;;
	esac

	case "$from_menu" in
		1) F_terminal_padding ;;
	esac

	return 0
} # terminal_header

F_status() {

	F_pg1() {
		update_rem=$((update_period - update_diff))
		clear
		F_printf "${tYEL}============================ wicens status page 1/2=============================${tCLR}"
		F_terminal_padding
		F_status_grn "Current saved WAN IP" "$saved_wan_ip"
		F_status_grn "Current Email send to address" "$user_send_to_addr"
		F_status_grn "Current Email send to CC address" "$user_send_to_cc"
		F_status_grn "Current Email server addr:port" "$user_smtp_server"
		F_status_grn "Current Email send format type" "$user_message_type"
		F_status_grn "Current Email login address" "$user_login_addr"
		F_status_grn "Current Email from address" "$user_from_addr"
		F_status_grn "Current Email msg from name" "$user_email_from"
		F_status_grn "Current Email msg to name" "$user_msg_to"
		[ "$build_entry" = 1 ] && return 0
		[ -f "$cred_loc" ] && F_status_grn "Current Email password" "Password saved"
		[ "$user_message_type" = "smtp_ssl" ] && F_status_grn "Current Email protocol" "$protocol"
		[ -n "$ssl_flag" ] && F_status_grn "SSL flag set" "$ssl_flag"
		F_terminal_separator

		if [ -n "$user_custom_subject" ] ; then
			user_custom_subject_show="$user_custom_subject_decoded"
			[ ${#user_custom_subject_show} -gt 31 ] && user_custom_subject_show="$(F_printfstr "$user_custom_subject_decoded" | awk '{print substr($0, 1, 33)}' | /bin/sed 's/$/.../g')"
			F_status_grn "Custom WAN IP Subject line set" "$user_custom_subject_show"
		fi

		if [ -n "$user_custom_subject_r" ] ; then
			user_custom_subject_show="$user_custom_subject_r_decoded"
			[ ${#user_custom_subject_show} -gt 31 ] && user_custom_subject_show="$(F_printfstr "$user_custom_subject_r_decoded" | awk '{print substr($0, 1, 33)}' | /bin/sed 's/$/.../g')"
			F_status_grn "Custom Reboot Subject line set" "$user_custom_subject_show"
		fi

		if [ -n "$user_custom_subject_f" ] ; then
			user_custom_subject_show="$user_custom_subject_f_decoded"
			[ ${#user_custom_subject_show} -gt 31 ] && user_custom_subject_show="$(F_printfstr "$user_custom_subject_f_decoded" | awk '{print substr($0, 1, 33)}' | /bin/sed 's/$/.../g')"
			F_status_grn "Custom Firmware Subject line set" "$user_custom_subject_show"
		fi

		if [ -n "$user_custom_subject_s" ] ; then
			user_custom_subject_show="$user_custom_subject_s_decoded"
			[ ${#user_custom_subject_show} -gt 31 ] && user_custom_subject_show="$(F_printfstr "$user_custom_subject_s_decoded" | awk '{print substr($0, 1, 33)}' | /bin/sed 's/$/.../g')"
			F_status_grn "Custom Update Subject line set" "$user_custom_subject_show"
		fi

		if [ -n "$user_custom_text" ] ; then
			user_custom_text_show="$user_custom_text_decoded"
			[ ${#user_custom_text_show} -gt 35 ] && user_custom_text_show="$(F_printf "$user_custom_text_decoded" | awk 'NR==1 {print substr($0, 1, 33)}' | /bin/sed 's/$/.../g')"
			F_status_grn "Custom WAN IP message text is set" "$user_custom_text_show"
		fi

		if [ -n "$user_custom_text_r" ] ; then
			user_custom_text_show="$user_custom_text_r_decoded"
			[ ${#user_custom_text_show} -gt 35 ] && user_custom_text_show="$(F_printf "$user_custom_text_r_decoded" | awk 'NR==1 {print substr($0, 1, 33)}' | /bin/sed 's/$/.../g')"
			F_status_grn "Custom Reboot message text is set" "$user_custom_text_show"
		fi

		if [ -n "$user_custom_text_f" ] ; then
			user_custom_text_show="$user_custom_text_f_decoded"
			[ ${#user_custom_text_show} -gt 35 ] && user_custom_text_show="$(F_printf "$user_custom_text_f_decoded" | awk 'NR==1 {print substr($0, 1, 33)}' | /bin/sed 's/$/.../g')"
			F_status_grn "Custom Firmware message text is set" "$user_custom_text_show"
		fi

		if [ -n "$user_custom_text_s" ] ; then
			user_custom_text_show="$user_custom_text_s_decoded"
			[ ${#user_custom_text_show} -gt 35 ] && user_custom_text_show="$(F_printf "$user_custom_text_s_decoded" | awk 'NR==1 {print substr($0, 1, 33)}' | /bin/sed 's/$/.../g')"
			F_status_grn "Custom Update message text is set" "$user_custom_text_show"
		fi

		if [ -n "$user_custom_script_decoded" ] ; then
			user_custom_script_show="$user_custom_script_decoded"
			[ ${#user_custom_script_show} -gt 35 ] && user_custom_script_show="$(F_printfstr "$user_custom_script_decoded" | awk '{print substr($0,length($0)-33)}' | /bin/sed 's/^/.../g')"
			F_status_grn "Custom script path" "$user_custom_script_show"
		fi

		[ -n "$user_script_call_time" ] && F_status_grn "Custom script call time" "$user_script_call_time"
		F_status_grn "Cron run interval" "${cron_check_freq} minutes"
		F_status_grn "Number of cron checks" "$cron_run_count"
		F_status_grn "Number of wan-event checks" "$wancall_run_count"
		F_status_grn "Total IP changes" "$ip_change_count"
		F_status_grn "Last IP change" "$last_ip_change"
		F_status_grn "Last ran with wan-event" "$last_wancall_run"
		F_status_grn "Last monitored with cron" "$last_cron_run"
		F_status_grn "Script configured date" "$created_date"
		F_status_grn "Current saved WAN IP recorded" "$saved_wan_date"
		F_status_grn "Current saved WAN IP lease age" "$(F_calc_lease | sed 's/^[[:space:]]*//')"
		F_uptime
		F_status_grn "Current router uptime" "$(F_printfstr "$uptime_pretty" | sed 's/^[[:space:]]*//')"
		F_status_grn "Script last updated date" "$update_date"
		F_status_grn "Script install date" "$install_date"
		[ "$user_update_notification" = 1 ] && [ "$update_avail" = 'none' ] && F_status_grn "Secs to next update check w/cron" "$update_rem"
		F_terminal_separator
		F_terminal_padding
		[ "$count_entry" = 1 ] && return 0
		F_terminal_check "Any key - next page   E||e to return to Main Menu"
		read -rsn1 pg1wait
		case $pg1wait in
			E|e) F_clean_exit reload ;;
			*) F_pg2 ;;
		esac
	} # pg1

	F_pg2() {
		clear
		F_printf "${tYEL}============================ wicens status page 2/2=============================${tCLR}"
		F_terminal_padding

		if [ "$user_wanip_monitor" = 1 ]
		then F_status_enabled "WAN IP change monitoring"
		else F_status_disabled "WAN IP change monitoring"
		fi

		if [ "$user_wanip_notification" = 1 ]
		then F_status_enabled "WAN IP change Email notify"
		else F_status_disabled "WAN IP change Email notify"
		fi

		if [ "$user_reboot_notification" = 1 ]
		then F_status_enabled "Router reboot Email notify"
		else F_status_disabled "Router reboot Email notify"
		fi

		if [ "$user_fw_update_notification" = 1 ]
		then F_status_enabled "Firmware update Email notify"
		else F_status_disabled "Firmware update Email notify"
		fi

		if [ "$user_update_notification" = 1 ]
		then F_status_enabled "Script update Email notify"
		else F_status_disabled "Script update Email notify"
		fi

		F_terminal_separator

		if [ "$amtm_import" = 1 ]
		then F_status_enabled "Sync from amtm Email config"
		else F_status_disabled "Sync from amtm Email config"
		fi

		if [ "$status_amtm" = 1 ]
		then F_status_pass "amtm valid Email config test"
		else F_status_fail "amtm valid Email config test"
		fi

		if [ "$status_email_cfg" = 1 ]
		then F_status_pass "Loaded Email settings config test"
		else F_status_fail "Loaded Email settings config test"
		fi

		F_terminal_separator

		if [ "$fw_sw_mode" = 1 ] ; then
			if F_wan_event check
			then F_status_pass "wan-event entry test"
			else F_status_fail "wan-event entry test"
			fi
		else
			F_terminal_show "$(printf "%s%s|\n" "wan-event entry test" "$(printf '%*s' "$((35 - 20))" | tr ' ' '-')") ${tRED}Disabled - Not in router mode${tCLR}"
		fi

		if F_cru check
		then F_status_pass "cron(cru) entry test"
		else F_status_fail "cron(cru) entry test"
		fi

		if F_serv_start check
		then F_status_pass "services-start cron(cru) entry test"
		else F_status_fail "services-start cron(cru) entry test"
		fi

		if F_notify_reboot check status
		then F_status_pass "services-start reboot entry test"
		else F_status_fail "services-start reboot entry test"
		fi

		if F_notify_firmware check status
		then F_status_pass "update-notification fw entry test"
		else F_status_fail "update-notification fw entry test"
		fi

		F_terminal_separator

		F_status_grn "Config file versions" "User: v$build_settings_version Core: v$update_settings_version"
		[ "$update_avail" != 'none' ] && [ "$update_avail" != 'hotfix' ] && F_status_grn "New version is available!" "Version $update_avail"
		[ "$update_avail" != 'none' ] && [ "$update_avail" = 'hotfix' ] && F_status_grn "Hotfix update is available!" "Hotfix for v$script_version"

		F_status_grn "Script TTY lock age" "${tGRN}$(( $(F_date s) - $(/bin/sed -n '3p' /tmp/wicens_lock.tty) )) secs${tCLR}"
		F_terminal_separator

		[ "$status_email_cfg" = 0 ] && F_printf "$fail_reason"
		F_terminal_padding
		F_terminal_check "Any key - previous page   E||e to return to Main Menu"
		read -rsn1 pg2wait
		case $pg2wait in
			E|e) F_clean_exit reload ;;
			*) F_pg1 ;;
		esac
	}

	F_pg1
	return 0
} # status

F_config_verbose() {
	F_conf_pg1(){
		clear
		F_printf "${tYEL}===== Verbose config file status - User Config - 1/2 =====${tCLR}"
		while IFS= read -r fileline ; do
			if F_printfstr "$fileline" | grep -Fq '=' ; then
				config_var="$(F_printfstr "$fileline" | cut -d'=' -f1)"
				value=$(F_printfstr "$fileline" | cut -d'=' -f2 | tr -d "'" | sed 's/#.*//')   # trim var comments
				F_status_grn "$config_var" "$value"
			fi
		done < "$config_src"
		F_terminal_separator
		F_terminal_check "Any key - next page   E||e to return to Main Menu"
		read -rsn1 pg1wait
		case $pg1wait in
			E|e) F_clean_exit reload ;;
			*) F_conf_pg2 ;;
		esac
	}

	F_conf_pg2() {
		clear
		F_printf "${tYEL}===== Verbose config file status - Core Config - 2/2 =====${tCLR}"
		while IFS= read -r fileline ; do
			if F_printfstr "$fileline" | grep -Fq '=' ; then
				config_var="$(F_printfstr "$fileline" | cut -d'=' -f1)"
				value=$(F_printfstr "$fileline" | cut -d'=' -f2 | tr -d "'" | sed 's/#.*//')   # trim var comments
				F_status_grn "$config_var" "$value"
			fi
		done < "$update_src"
		F_terminal_separator
		F_terminal_check "Any key - previous page   E||e to return to Main Menu"
		read -rsn1 pg1wait
		case $pg1wait in
			E|e) F_clean_exit reload ;;
			*) F_conf_pg1 ;;
		esac
	}

	F_conf_pg1
} # config_verbose

F_main_menu() {
	F_terminal_header
	F_printf "       ${tYEL}Option                        Select  Status${tCLR}"
	F_terminal_separator

	if [ "$status_amtm" = 1 ] && [ "$amtm_import" = 1 ] ; then F_menu_enabled "amtm Email config sync-------|  0    "
	elif [ "$status_amtm" = 1 ] && [ "$amtm_import" = 0 ] && [ "$status_email_cfg" = 1 ] ; then F_menu_disabled "amtm Email config sync-------|  0    "
	elif [ "$status_amtm" = 0 ] && [ "$amtm_import" = 0 ] ; then F_terminal_show "amtm Email config sync-------|  0     ${tRED}Disabled - amtm not configured${tCLR}"
	elif [ "$status_amtm" = 1 ] && [ "$amtm_import" = 0 ] && [ "$status_email_cfg" = 0 ] ; then F_terminal_show "amtm Email config sync-------|  0     ${tRED}Disabled -${tCLR} ${tGRN}Available${tCLR}"
	fi

	case "$status_email_cfg" in
		1) F_menu_enabled "Create/Edit Email settings---|  1    " ;;
		0) F_terminal_show "Create/Edit Email settings---|  1     ${tRED}Disabled - V||v to view errors${tCLR}" ;;
	esac

	case "$status_wanipmon" in
		1) F_menu_enabled "WAN IP change monitor--------|  2    " ;;
		0) F_menu_disabled "WAN IP change monitor--------|  2    " ;;
	esac

	case "$status_wanip" in
		1) F_menu_enabled "WAN IP change Email notify---|  3    " ;;
		0) F_menu_disabled "WAN IP change Email notify---|  3    " ;;
	esac

	case "$status_reboot" in
		1) F_menu_enabled "Router reboot Email notify---|  4    " ;;
		0) F_menu_disabled "Router reboot Email notify---|  4    " ;;
	esac

	case "$status_fw" in
		1) F_menu_enabled "Firmware update Email notify-|  5    " ;;
		0) F_menu_disabled "Firmware update Email notify-|  5    " ;;
	esac

	case "$status_update" in
		1) F_menu_enabled "Script update Email notify---|  6    " ;;
		0) F_menu_disabled "Script update Email notify---|  6    " ;;
	esac

	if [ -n "$user_custom_script" ]
	then F_terminal_show "WAN IP change script---------|  7     ${tGRN}Enabled${tCLR} - Action ${tGRN}$user_script_call_time${tCLR}"
	else F_menu_disabled "WAN IP change script---------|  7    "
	fi

	if [ -n "$user_custom_text" ] || [ -n "$user_custom_text_r" ] || [ -n "$user_custom_text_f" ] || [ -n "$user_custom_text_s" ]
	then F_menu_enabled "Custom Email text menu-------|  8    "
	else F_menu_disabled "Custom Email text menu-------|  8    "
	fi

	if [ -n "$user_custom_subject" ] || [ -n "$user_custom_subject_r" ] || [ -n "$user_custom_subject_f" ] || [ -n "$user_custom_subject_s" ]
	then F_menu_enabled "Custom Email subjects--------|  9    "
	else F_menu_disabled "Custom Email subjects--------|  9    "
	fi

	F_terminal_separator
	F_terminal_show "View current status/settings-| V||v"
	F_terminal_show "Force WAN IP compare w/script| M||m"
	F_terminal_show "Show sample WAN IP Email-----| S||s"
	F_terminal_show "Send a test Email------------| T||t"
	F_terminal_show "Show last Email curl log-----| L||l"
	F_terminal_show "Show script log--------------| Z||z"
	F_terminal_show "Reset cron/wan-event counts--| N||n"
	F_terminal_show "Reset script to default------| R||r"
	F_terminal_show "Toggle terminal color on/off-| C||c"
	F_terminal_show "Uninstall script-------------| U||u"

	if [ "$status_email_cfg" = 0 ] && [ -f "$script_backup_file" ]
	then F_terminal_show "Backup Email config----------| B||b   ${tGRN}Backup Found - select to restore${tCLR}"
	else F_terminal_show "Backup/Restore settings menu-| B||b"
	fi

	if [ "$update_avail" != 'none' ] && [ "$update_avail" != 'hotfix' ] ; then F_terminal_show "Install script update--------| I||i   ${tGRN}Update available - version $update_avail${tCLR}"
	elif [ "$update_avail" != 'none' ] && [ "$update_avail" = 'hotfix' ] ; then F_terminal_show "Install script update--------| I||i   ${tGRN}Hotfix available!${tCLR}"
	else F_terminal_show "Check for script update------| F||f"
	fi

	F_terminal_show "Other options----------------| H||h"
	F_terminal_show "About script-----------------| A||a"
	F_terminal_show "Exit-------------------------| E||e"

	[ "$from_menu" = 0 ] && stop_time="$(awk '{print $1}' < /proc/uptime)"
	load_time="$(F_printf "$start_time $stop_time" | awk '{diff = $2 - $1; if (diff >= 10) printf "10s+"; else printf "%.2f", diff}')"
	F_printf "[${tGRN}${load_time}${tCLR}] Menu load time"

	case "$1" in
		'hidden') F_terminal_padding ; F_opt_about | sed -n '93,101p' ;;
	esac

	F_terminal_padding
	F_terminal_check "Selection : "
	selection=''
	from_menu=1
	read -r selection
	F_terminal_erase

	case "$selection" in
		0) F_amtm ;;
		1) if [ "$status_email_cfg" = 1 ] ; then
				F_edit_settings
			else
				F_build_settings
			fi
		;;
		'1f'|'1F') source "$config_src" ; F_build_settings ;;
		2) F_wanip_monitor ; F_menu_exit ;;
		3) F_notify_wanip ;;
		4) F_notify_reboot ;;
		5) F_notify_firmware ;;
		6) F_notify_update ;;
		7) until F_opt_script ; do : ; done ; F_menu_exit ;;
		8) until F_opt_text_select ; do : ; done ; F_menu_exit ;;
		9) until F_opt_subject_select ; do : ; done ; F_menu_exit ;;
		a|A) F_opt_about ; F_menu_exit ;;
		b|B) F_opt_backup_restore ;;
		c|C) F_opt_color ;;
		e|E) F_clean_exit ;;
		f|F) F_web_update_check force ;;
		i|I)
			case "$update_avail" in
				'none') printf "%b %s is an invalid entry, any key to retry" "$tCHECKFAIL" "$selection" ; read -rsn1 ; return 1 ;;
				*) F_local_script_update ;;
			esac
		;;
		l|L) F_opt_mail_log ;;
		m|M)
			if ! F_compare ; then
				building_settings=1
				F_script_wan_update
				building_settings=0
			fi
			F_menu_exit
		;;
		n|N) F_opt_count ;;
		r|R) F_opt_reset ;;
		s|S) F_opt_sample ;;
		t|T) until F_opt_test ; do : ; done ; F_menu_exit ;;
		u|U) F_opt_uninstall ;;
		v|V) F_status && F_menu_exit ;;
		z|Z)
			if [ -f "$script_log_loc" ] ; then
				clear
				cat "$script_log_loc"
			else
				F_terminal_check_fail "/jffs/addons/wicens/wicens.log does not exist"
			fi
			F_menu_exit
		;;
		vv|VV) F_config_verbose ;;
		fr) F_replace_var update_avail 'none' "$update_src" ; F_replace_var update_notify_state 0 "$update_src" ; F_replace_var update_cron_epoch 0 "$update_src" ; F_terminal_check_ok "Reset any found script updates" ; F_menu_exit ;;
		fl) [ -f "$mail_log" ] && rm -f "$mail_log" && F_terminal_check_ok "Reset Email curl/sendmail log output" ; F_menu_exit ;;
		ul) [ -f "$user_script_log" ] && clear && cat "$user_script_log" ; F_menu_exit ;;
		fe) F_email_eg ;;
		rc) F_default_update_create ; config_updated=1 ; fw_nvram_check_diff=666 ; source "$update_src" ; F_terminal_check_ok "wicens update(core) config reset" ; F_firmware_check ; F_menu_exit ;;
		ri) F_replace_var saved_wan_ip '' "$config_src" ; F_terminal_check_ok "Removed saved WAN IP" ; F_menu_exit ;;
		dw)
			case "$dual_wan_check" in
				1)
					F_replace_var dual_wan_check 0 "$update_src"
					F_log_terminal_ok "Dual WAN check disabled"
				;;
				0)
					F_replace_var dual_wan_check 1 "$update_src"
					F_log_terminal_ok "Dual WAN check enabled"
				;;
			esac
			F_menu_exit
		;;
		h|H) from_menu=2 ; F_main_menu hidden ;;
		*)
			from_menu=2
			[ -n "$selection" ] && F_terminal_check_fail "${tRED}$selection${tCLR} is an invalid selection, any key to retry" && read -rsn1
			return 1
		;;
	esac
} # main menu

# SCRIPT LOCK #########################################################################################################
#######################################################################################################################

F_lock() {
	case "$run_option" in
		'cron'|'tty')
			if [ -f '/tmp/wicens_lock.tty' ] ; then
				lock_pid="$(sed -n '2p' "/tmp/wicens_lock.tty")"
				lock_epoch="$(sed -n '3p' "/tmp/wicens_lock.tty")"
				lock_age="$(($(F_date s) - lock_epoch))"
				if [ ! -d "/proc/$lock_pid" ] ; then   # if tty lock exists but not running remove
					rm -f '/tmp/wicens_lock.tty'
					[ -f '/tmp/wicens_internetlock.tty' ] && rm -f '/tmp/wicens_internetlock.tty' && F_log "Error - Removed tty internet lock, process non-existent"
					F_terminal_header exit
					F_log_show "Error - Removed tty lock - Lock age: ${lock_age}s PID: (${lock_pid}) non-existent "
				else
					if [ "$lock_age" -gt 1800 ] ; then   # if terminal has been running for 30 mins kill it and continue
						kill -9 "$lock_pid" 2> /dev/null
						rm -f '/tmp/wicens_lock.tty'
						F_terminal_header exit
						F_log_terminal_fail "Error - Removed tty lock - Lock age: ${lock_age}s - Killed PID: ${lock_pid}"
					else
						# prevent cron while in tty
						F_printfstr "[FAIL] Running in terminal session - Lock age: ${lock_age}s - PID: ${lock_pid}"
						[ "$run_option" = 'cron' ] && exit 0
					fi
				fi
				[ "$run_option" = 'tty' ] && F_wait 20
			fi

			# check age of all call types and clean up with cron/tty, prevent cron from running while other valid call is running
			for lockfile in fwupdate wancall reboot send cron ; do
				if [ ! -f "/tmp/wicens_lock.${lockfile}" ] ; then
					[ -f "/tmp/wicens_internetlock.${lockfile}" ] && rm -f "/tmp/wicens_internetlock.${lockfile}"
				else
					lock_pid="$(sed -n '2p' "/tmp/wicens_lock.$lockfile")"
					lock_epoch="$(sed -n '3p' "/tmp/wicens_lock.$lockfile")"
					lock_age="$(($(F_date s) - lock_epoch))"
					if [ -z "$lock_pid" ] || [ -z "$lock_epoch" ] || [ -z "$lock_age" ] ; then
						rm -f "/tmp/wicens_lock.$lockfile"
						F_log "Error - found /tmp/wicens_lock.${lockfile} but file missing pid/epoch, removed"
					else
						if [ "$lock_age" -gt 180 ] ; then
							if [ -d "/proc/$lock_pid" ] ; then
								# internet check can run longer than lock_age_max check if thats what the old process is doing
								if [ -f "/tmp/wicens_internetlock.$lockfile" ] ; then
									internetlock_age="$(sed -n '1p' "/tmp/wicens_internetlock.$lockfile")"
									if [ "$(($(F_date s) - internetlock_age))" -gt 315 ] ; then
										kill -9 "$lock_pid" 2> /dev/null
										rm -f "/tmp/wicens_lock.$lockfile"
										rm -f "/tmp/wicens_internetlock.$lockfile"
										F_log_terminal_fail "Error - found wicens_lock.${lockfile} ${lock_age}s and internet lock ${internetlock_age}s, killed process ${lock_pid} and removed locks"
									else
										F_log_terminal_fail "Error - found wicens_lock.${lockfile} ${lock_age}s and internet_lock ${internetlock_age}s, internet lock not over age limit(5 mins)... exiting"
										exit 0
									fi
								else
									kill -9 "$lock_pid" 2> /dev/null
									rm -f "/tmp/wicens_lock.${lockfile}" 2> /dev/null
									F_log_terminal_fail "Error - Killed process pid ${lock_pid} started by ${lockfile} over age limit(180) ${lock_age}"
								fi
							else
								F_log_terminal_fail "Error - Process doesn't exit - process lock age: ${lock_age} secs Max:180, removing lock"
								rm -f "/tmp/wicens_lock.${lockfile}" 2> /dev/null
								[ -f "/tmp/wicens_internetlock.$lockfile" ] && rm -f "/tmp/wicens_internetlock.$lockfile"
							fi
						else
							# prevent cron from running while any other valid automated call is running
							F_terminal_header
							F_terminal_warning
							F_log_terminal_fail "Script already running - locked by ${lockfile} pid ${lock_pid} running ${lock_age} secs"
							F_log_show "$((180 - lock_age)) secs remaining till lock purge possible if necessary"
							[ "$run_option" = 'cron' ] && exit 0
							[ "$run_option" = 'tty' ] && F_menu_exit
						fi
					fi
				fi
			done
		;;
		*)
			if [ -f "wicens_lock.${run_option}" ] ; then
				lock_pid="$(sed -n '2p' "/tmp/wicens_lock.$run_option")"
				lock_epoch="$(sed -n '3p' "/tmp/wicens_lock.$run_option")"
				lock_age="$(($(F_date s) - lock_epoch))"
				F_log "Error - lock file exists for this call type Aged:${lock_age}secs max:180 PID:$lock_pid"
				exit 2
			fi
		;;
	esac

	{
		F_printfstr "$run_option"
		F_printfstr "$$"
		F_printfstr "$(F_date s)"
		F_printfstr "$(F_date r)"
	} > "$script_lock"

	return 0
} # lock

F_ntp() {
	ntp_lock="/tmp/wicens_ntplock.$run_option"
	[ -f "$ntp_lock" ] && exit 0   # script already running waiting on NTP sync

	F_uptime
	case "$(F_nvram ntp_ready)" in
		1) ;;
		*) # if ntp nolonger synced but up greater than a day warn user
			if [ "$router_uptime" -gt 86400 ] ; then
				F_log_terminal_fail "script failed to start, current time may be correct"
				F_log_terminal_fail "but your your NTP is NOT synced and router uptime >1 day"
				F_log_show "Please check your NTP configuration"
				exit 1   # script lock not yet created
			fi

			F_printfstr "$(F_date s) $$" > "$ntp_lock"
			ntp_wait_time=0
			F_log_show "NTP is not synced, waiting upto 600 seconds (10min) checking every 3 seconds for NTP sync"

			while [ "$(F_nvram ntp_ready)" -ne 1 ] && [ "$ntp_wait_time" -lt 600 ] ; do
				ntp_wait_time="$((ntp_wait_time + 3))"
				printf '\r%b Elapsed time : %s secs' "$tTERMHASH" "$ntp_wait_time"
				sleep 3
				printf '%b' "$tERASE"
			done

			if [ "$ntp_wait_time" -ge 600 ] ; then
				F_log_show "NTP failed to sync and update router time after 10 mins of checking"
				F_log_show "Please check your NTP configuration"
				F_clean_exit
			fi

			rm -f "$ntp_lock"
			# ntp_ready can be set but just let settle
			sleep 5
		;;
	esac

	TZ="$(cat /etc/TZ)"
	export TZ
	run_date="$(F_date f)"
	run_epoch="$(F_date s)"

	# lock script from duplicate runs
	F_lock

	# time is set load user settings
	F_user_settings

	# if auto run check Script eg amtm enabled - any notification enabled - but they delete their amtm config we'll spam the log
	case "$1" in
		'noterminal') F_ready_check ;;
	esac
	return 0
} # ntp

# FIRST SCRIPT COMMANDS ###############################################################################################
#######################################################################################################################
#######################################################################################################################

case "$run_option" in
	'reload') # reload menu without ntp/lock/alias/fw check etc
		run_date="$(F_date r)"
		run_epoch="$(F_date s)"
		run_option='tty'
		script_lock="/tmp/wicens_lock.$run_option"
		F_user_settings
		until F_main_menu ; do : ; done
	;;

	'tty') # only check alias/FW ver with terminal runs
		F_ntp
		F_firmware_check
		F_alias   # installed with F_firmware_check, checked here (sanity check)

		# if Email send failed we need to clear out the file for future
		if [ -f "$wicens_wanip_retry" ] || [ -f "$wicens_fw_retry" ] || [ -f "$wicens_update_retry" ] || [ -f "$wicens_send_retry" ] || [ -f "$wicens_reboot_retry" ] ; then
			F_terminal_header
			F_terminal_show "A failed Email retry file exists... removing"
			F_terminal_padding

			for file_remove in "$wicens_wanip_retry" "$wicens_fw_retry" "$wicens_reboot_retry" "$wicens_send_retry" "$wicens_update_retry"
			do
				[ -f "$file_remove" ] && cat "$file_remove" && F_terminal_padding && rm -f "$file_remove"
			done
			F_wait 60
		fi

		# start wicens menu
		until F_main_menu ; do : ; done
	;;

	'uninstall'|'-uninstall'|'--uninstall')
		run_option='tty'
		F_ntp
		F_opt_uninstall
	;;

	'help'|'-help'|'--help'|'-h'|'--h') F_opt_about ;;

	##### auto-run options ############################################################################################
	# exit needed in all but cron so it can fall through every call type check

	'wancall') # wan-event call
		F_ntp noterminal
		new_wancall_count="$((wancall_run_count + 1))"
		F_log_show "Started by 'wan-event connected' trigger, sleeping $wan_event_wait seconds before running IP compare"
		F_replace_var wancall_run_count "$new_wancall_count" "$config_src"
		F_replace_var last_wancall_run "$run_date" "$config_src"
		sleep "$wan_event_wait"   # let connection settle before checking anything

		# if called by wancall ensure we start fresh 5 attempts
		[ -f "$wicens_wanip_retry" ] && rm -f "$wicens_wanip_retry"

		if ! F_compare ; then
			if [ "$user_wanip_notification" = 1 ] ; then
				F_wanip_email_msg
			else
				F_script_wan_update
			fi
		fi
		F_clean_exit
	;;

	'reboot') # router reboot call
		F_ntp noterminal
		[ -f "$wicens_reboot_retry" ] && rm -f "$wicens_reboot_retry"   # should never execute but due diligence
		F_log_show "Started by services-start, reboot detected, sending reboot notification in $reboot_notify_wait seconds"

		# set 1 at start of attempt set to 0 by F_reboot_email_msg on msg success and checked by cron
		F_replace_var reboot_notify_state 1 "$update_src"
		F_reboot_email_msg
		F_clean_exit
	;;

	'fwupdate') # firmware update call
		F_ntp noterminal
		# called by update-notification event
		F_uptime && [ "$router_uptime" -lt 600 ] && sleep 60   # router up less than 10 mins wait 1 mins before sending
		[ -f "$wicens_fw_retry" ] && rm -f "$wicens_fw_retry"   # if retry file exists remove, we were called by update-notification again
		F_log_show "Started by update-notification trigger, sending firmware update notification"

		# set 1 at start of attempt set to 0 by F_fw_update_email_msg msg success and checked by cron
		F_replace_var fw_notify_state 1 "$update_src"
		F_fw_update_email_msg
		F_clean_exit
	;;

	'send') # called as email forwarder
		F_ntp noterminal
		fwd_send_msg="$2"
		fwd_send_addr="$3"

		if [ -z "$fwd_send_msg" ] ; then
			F_log_show "Error, script called as forwarder but no Email message defined"
			F_clean_exit fail
		elif [ ! -f "$fwd_send_msg" ] ; then
			F_log_show "Error, script called as forwarder but can't find $fwd_send_msg Email message"
			F_clean_exit fail
		fi

		if [ -n "$fwd_send_addr" ] ; then
			F_log_terminal_ok "script started as forwarder, attempting to send $fwd_send_msg to $fwd_send_addr"
		else
			F_log_terminal_ok "script started as forwarder, attempting to send $fwd_send_msg to $user_send_to_addr"
		fi

		if F_opt_forward ; then
			F_clean_exit
		else
			F_clean_exit fail
		fi
	;;

	'cron') # cron call
		# router up less than 10 mins don't execute cron check
		F_uptime && [ "$router_uptime" -lt 600 ] && exit 0
		F_ntp noterminal
		[ "$cron_option" = 0 ] && F_clean_exit   # update_conf allows disabling cron checks but keeps cron entries

		F_replace_var cron_run_count "$((cron_run_count + 1))" "$config_src"
		F_replace_var last_cron_run "$run_date" "$config_src"

		[ "$(wc -c "$script_log_loc" | cut -d' ' -f1)" -gt 200000 ] && F_printfstr "$(F_date f) Log file grew to 200KB file was reset" > "$script_log_loc"

		# cron - Sunday logging 6pm ###################################################################################
		weekly_wancall_total=$((wancall_run_count - last_wancall_log_count))   # log msg count

		if [ "$(/bin/date +'%u')" = 7 ] && [ "$log_cron_msg" = 1 ] && [ "$(/bin/date +'%H')" = 18 ] ; then
			F_log "Started successfully by wan-event connected $weekly_wancall_total times in the last week, $wancall_run_count times since $created_date"
			F_log "Last wan-event connected trigger $last_wancall_run"
			F_log "Recorded $ip_change_count IP change(s) since install"
			F_uptime && F_log "Router uptime $uptime_pretty"
			F_replace_var last_wancall_log_count "$wancall_run_count" "$config_src"
			F_replace_var log_cron_msg 0 "$config_src"
		fi

		if [ "$(/bin/date +'%u')" = 1 ] && [ "$log_cron_msg" = 0 ] ; then   # monday reset
			F_replace_var log_cron_msg 1 "$config_src"
		fi

		# cron - update check #########################################################################################
		if [ "$user_update_notification" = 1 ] && [ "$update_avail" = 'none' ] ; then   # if update already found dont recheck
			update_cron_diff=$((run_epoch - update_cron_epoch))

			if [ "$update_cron_diff" -ge "$update_period" ] ; then   # check for webupdate every 48hours
				sleep "$(F_random_num 15)"   # good internet neighbor
				F_web_update_check
				F_replace_var update_cron_epoch "$(F_date s)" "$update_src"
			fi
		fi

		# cron - update notification initial attempt and retry if 'cron update check' found an update #################
		# set notify_state 1 on success, reset with upgrade
		if [ "$update_avail" != 'none' ] && [ "$update_notify_state" = 0 ] && [ "$user_update_notification" = 1 ] ; then   # no notification yet sent for update & enabled
			if [ -f "$wicens_update_retry" ] ; then   # set 5 time retry, retry reset in script_update_email_msg success
				F_printfstr "# Attempting to send script update notification $(F_date r)" >> "$wicens_update_retry"
			else
				F_printfstr "# Attempting to send script update-notification $(F_date r)" > "$wicens_update_retry"
			fi

			if [ "$(wc -l < "$wicens_update_retry")" -le "$max_email_retry" ] ; then
				F_internet_check update
				if [ "$update_avail" = 'hotfix' ] ; then
					F_log "Hotfix update for ver $script_version available, run manually to update"
				else
					F_log "Update to ver $update_avail available, run manually to update"
				fi

				F_log "Sending script update notification Email to ${user_send_to_addr}"
				F_script_update_email_msg
			else
				F_log "Critical error, attempted to send script update Email $max_email_retry times, giving up"
				F_replace_var update_notify_state 1 "$update_src"   # set like we had success to only log error 1 time
			fi
		fi

		# cron - fw update notification retry #########################################################################
		# set 1 and retry created by initial fwupdate call, reset to 0 after success
		if [ "$fw_notify_state" = 1 ] && [ -f "$wicens_fw_retry" ] ; then
			source "$wicens_fw_retry"

			# dont exit continue to forwarder/ipcheck
			if [ "$(wc -l < "$wicens_fw_retry")" -le "$((max_email_retry + 2))" ] ; then   # retry created in wicens fwupdate
				F_fw_update_email_msg
			else
				# check age of retries if over reset and start over
				wicens_fw_retry_age=$((run_epoch - wicens_fw_retry_time))
				if [ "$wicens_fw_retry_age" -gt "$retry_wait_period" ] ; then
					rm -f "$wicens_fw_retry"
					F_fw_update_email_msg
				fi
			fi
		fi

		# cron - reboot notification retry ############################################################################
		# set 1 and retry created by initial reboot call, reset to 0 after success
		if [ "$reboot_notify_state" = 1 ] && [ -f "$wicens_reboot_retry" ] ; then
			source "$wicens_reboot_retry"

			if [ "$(wc -l < "$wicens_reboot_retry")" -le "$((max_email_retry + 2))" ] ; then   # retry created in reboot_email
				F_reboot_email_msg
			else
				wicens_reboot_retry_age=$((run_epoch - wicens_reboot_retry_time))
				if [ "$wicens_reboot_retry_age" -gt "$retry_wait_period" ] ; then
					rm -f "$wicens_reboot_retry"
					F_reboot_email_msg
				fi
			fi
		fi

		# cron - wicens forwarder retry ###############################################################################
		if [ -f "$wicens_send_retry" ] ; then   # retry created in F_opt_forward
			source "$wicens_send_retry"   # source as retry needs msg/sendto/retrytime

			if [ "$(wc -l < "$wicens_send_retry")" -le "$((max_email_retry + 4))" ] ; then   # retry for forwarder has 4 lines coded
				F_opt_forward
			else
				wicens_send_retry_age=$((run_epoch - wicens_send_retry_time))
				if [ "$wicens_send_retry_age" -gt "$retry_wait_period" ] ; then   # email failed 5 times w/internet up, after 6 hrs try again
					rm -f "$wicens_send_retry"  # remove to refresh retries
					F_opt_forward
				fi
			fi
		fi

		# cron - wanip notify #########################################################################################
		# cron - wicens IP check ##################################################################################
		if [ "$user_wanip_monitor" = 1 ] ; then
			if ! F_compare ; then
				if [ -f "$wicens_wanip_retry" ] ; then
					if [ "$(wc -l < "$wicens_wanip_retry")" -ge "$((max_email_retry + 2))" ] ; then
						source "$wicens_wanip_retry"
						wicens_wanip_retry_age=$((run_epoch - wicens_wanip_retry_time))

						if [ "$wicens_wanip_retry_age" -gt "$retry_wait_period" ] ; then
							rm -f "$wicens_wanip_retry"   # remove and refresh attempts fall through to F_wanip_email
						else
							F_clean_exit   # done cron check exit
						fi

					fi
				fi

				if [ "$user_wanip_notification" = 1 ] ; then
					F_wanip_email_msg   # sets wicens_wanip_retry, clears on success
				else
					F_script_wan_update
				fi
			fi
		fi

		stop_time="$(awk '{print $1}' < /proc/uptime)"
		F_printf "[${tGRN}$(F_printf "$start_time $stop_time" | awk '{diff = $2 - $1; if (diff >= 10) printf "9.99"; else printf "%.2f", diff}')${tCLR}] Cron run time"
		F_clean_exit
	;;

	*)
		F_terminal_check_fail "wicens.sh ${tRED}${run_option}${tCLR} is an invalid option"
		F_terminal_padding
		exit 0
	;;
esac

########################################################################################################################
########################################################################################################################
# EOF
