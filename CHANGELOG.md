# wicens change log
-----------------
## 2.50
Nov 6 2021
* ADDED : firmware update notifications for 384/386 branch
* ADDED : random sleep period 0-30secs for cron update checks to github (good internet neighbor)
* CHANGED : wan-event/service-start/update-notification entries append time/date and logging added
* CHANGED : some script formatting/var names
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
