# wicens change log
-----------------
## 2.82
June 24 2022
* FIXED: broken new installs
* FIXED: update config when user upgrades router FW
## 2.80
June 8 2022
* ADDED: Historcal WAN IP changes written to Email message 
* CHANGED: write all possible nvram settings to config to avoid NVRAM lookup hangs 
* CHANGED(important): User backup moved to /jffs/addons/wicens/wicens_user_config.backup (cleaner)
* CHANGED: updated documentation for Googles discontinuation of 'less secure apps'
## 2.70
February 13 2022
* CHANGED: private ip in nvram assumes double-nat forces getrealip.sh
* ADDED: random sleep on cron for double-nat to google stun
* MOVED: F_random_sleep to main script and rename
* HF: fix firmware build check for notifications
## 2.66
January 4 2022
* FIXED: wan-event logger call syntax missing
* ADDED: update logging
## 2.65
December 28 2021
* FIXED: formatting of log output for script call
* REMOVED: auto update check on manual run
* CHANGED: update check to daily regardless if notify enabled (use f to force update check)
* CHANGED: some var names
## 2.60
December 7 2021
* CHANGED : main menu layout/settings error msg
* FIXED : pid of calls in events
* MOVED : settings fail to view opt v, fixed update time
* ADDED : backup delete opt
* CHANGED : file creation function calling
## 2.50
Nov 6 2021
* ADDED : firmware update notifications for 384/386 branch
* ADDED : random sleep period 0-30secs for cron update checks to github (good internet neighbor)
* CHANGED : wan-event/service-start/update-notification entries append time/date and logging added
* CHANGED : some script formatting/var names
* HF : fix uninstall yes or no
## 2.41
Nov 4 2021
* FIXED: timezone DST adjustment with cron
## 2.40
Oct 29 2021
* CHANGED: terminal output header for lts374
* CHANGED: performance update, not calling settings test repeatedly
* CHANGED: fail messages for invalid settings
* FIXED: duplicate set file permission
* CHANGED: removed pswd backup force re-entry on restore
* MOVED: user backup to /jffs/scripts  more visible for saving if formatting jffs
## 2.30 
Oct 22 2021
* CHANGED: versioning on update config file, update on version change
* FIXED: curl output for changelogs
* FIXED: wan-event syntax back to v1.13
* UPDATED: script, trimmed white space
* HF: invalid file to set permissions
## 2.22
Oct 20 2021
* FIXED: changelog sed for output/email
## 2.21
Oct 20 2021
* FIXED: update_src file properly replaced on update if change to file structure
## 2.20
Oct 19 2021
* CHANGED: moved/renamed some vars
* CHANGED: cron update check period for Email updates moved to update config (user editable)
* FIXED: curl output for update changelog
* ADDED: changelog in notification Email
* ADDED: update config file cleanup
* FIXED: misc script beauty
## 2.10  
Oct 17 2021
* ADDED: email notification for updates (default: no)
* CHANGED: some format fixes and outputs
## 2.00  
Oct 16 2021
* ADDED: auto/manual update check (autocheck has 15min interval on manual runs, must use menu f otherwise), 
will notify if update/hotfix available
* ADDED: new backup/restore function (not compatible with v1.xx)
* CHANGED: user config removed from script to file in /jffs/addons/wicens/
* CHANGED: gets wan IP via nvram, getrealip.sh is a fall back
* CHANGED: edited many functions/script checks to be more robust/editable
* REMOVED: user cron period entry, default 10 min watchdog now
## 
