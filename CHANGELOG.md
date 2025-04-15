# wicens change log
-----------------
## 4.11
April 10 2025
* ADDED: cron fully customizable in wicens_update_conf.wic
* ADDED: cron on/off in wicens_update_conf.wic (cron_option 1=on 0=off) (off: cron entries will still be created, script will immediately exit on cron runs)
* NOTE: disabling or editing cron beyond 20 min (default:11min) intervals is not recommended
* ADDED: can disable jffs independent logging in wicens_update_conf.wic (script_log 1=on 0=off)
* ADDED: can change independent log location in wicens_update_conf.wic (script_log_loc)
* CHANGED: don't write WAN IP after Email settings creation
* CHANGED: check if hardware is in router mode for WAN IP notifications
* CHANGED: added menu option for hidden options/other minor appearance tweaks
* CHANGED: core config from v4.1 to v4.2 for cron/logging options
## 4.10
Feb 3 2025
* ADDED: reboot notification has down time between power loss-reboot *approx
* ADDED: logging to independent file in wicens directory (maxsize: 200KB) option z
* ADDED: check custom script file exists w/cron (if missing we spam log with cron)
* ADDED: Email test can now send wanip/firmware update/reboot Email messages
* FIXED: script lock remove stale without relying on same call type running again
* FIXED: status display of multiline custom email text
* FIXED: ehlo in curl RFC 5321
* FIXED: F_internet_ping cycles (15 total attempts)
* FIXED: HTML structure in Emails
* FIXED: misc minor bug fixes
* CHANGED: check for dual wan on wanip change enable
* CHANGED: lock_age_max to 3mins (internet up)
* CHANGED: misc tweaks(hidden options/log time) and wording
* CHANGED: amtm style terminal exit (logo only)

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
