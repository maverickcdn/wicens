# wicens change log
-----------------
## 4.04
January 22 2025
* ADDED: crlf conversion for Email text file @molejado(GitHub)
* CHANGED: example email instructions option fe
* FIXED: removal of reboot uptime temp file
* CHANGED: wording on non-existent backup file during script upgrade @jksmurf

## 4.03
Jan 8 2025
* CHANGED: added device_name to Email subject lines

## 4.02
Jun 14 2024
* ADDED: support for 3.0.0.6 FW for wifi7 devices (untested)

## 4.01
May 31 2024
* CHANGED: prevent cron execution if router up less than 10 mins
* CHANGED: F_getrealip don't sleep if grabbing WAN IP for the first time
* CHANGED: misc wording for when new fw version found and password backup (not backed up when amtm enabled)

## 4.00
May 8 2024
* NEW: Router Reboot notification
* NEW: html formatting
* FIXED: various bug fixes
* REMOVED: multiple Emails/intervals were removed, script now functions for 1 Email per notification type only
* CHANGED: script performance and efficency increased, focused on modularity
* CHANGED: amtm config now syncs instead of overwriting wicens config, only 1 config can be used at once
* CHANGED: notification types (wanip/reboot/fwupdate/script-update) can be independently enabled/disabled
* ADDED: cgnat WAN IP warning
* ADDED: wicens_update_config.wic now contains a few adjustable timeouts/freq etc.
* NOTE: wan ip change history files from v3 will be misaligned in v4 emails

## 3.41
