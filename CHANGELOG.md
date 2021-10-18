# wicens change log
-----------------
## v2.10  
Oct 17 2021
* ADDED: email notification for updates (default: no)
* CHANGED: some format fixes and outputs
## v2.00  
Oct 16 2021
* ADDED: auto/manual update check (autocheck has 15min interval on manual runs, must use menu f otherwise), 
will notify if update/hotfix available
* ADDED: new backup/restore function (not compatible with v1.xx)
* CHANGED: user config removed from script to file in /jffs/addons/wicens/
* CHANGED: gets wan IP via nvram, getrealip.sh is a fall back
* CHANGED: edited many functions/script checks to be more robust/editable
* REMOVED: user cron period entry, default 10 min watchdog now
## 
