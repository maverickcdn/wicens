# wicens change log
-----------------
## 3.11
Apr 4 2023
* CHANGED: curl swap from name/user name
## 3.10
Oct 27 2022
* ADDED: AMTM Email config sync, will sync wicens with config in AMTM if enabled, if updating from =< 3.0 must manually enable
* FIXED: couple misdirected var changes in AMTM import, missing AMTM pswd will fail check
* CHANGED: removed plaintext encrypt/decrypt methods
* CHANGED: removed hard coded built-in command paths
## 3.00
Sept 16 2022
* ADDED: router uptime to Email notification
* ADDED: wicens can act as an Email sender with your own generated Email text file leveraging retry/internet check etc (see about)
* ADDED: max 6 (1/10mins every 6 hrs) re-attempts for wan-event/forwarder Email send attempts if internet is up, cleared with new wan-event trigger or manual run
* ADDED: AMTM Email config import option
* ADDED: if valid config, option 1 now uses edit menu, use 1f to force guided setup
* ADDED: current observed lease age in status
* ADDED: install/configured dates in status
* CHANGED: randomized test sites for ping to check if internet is up (good Internet neighbor)
* CHANGED: script reorganized/code cleanup/optimizations
* CHANGED: script update check to 48hrs interval, user must enable script update notifications otherwise use menu f to force
## 2.85
June 26 2022
* FIXED: revert change to F_fail_entry (broken y or n outside selection)
* CHANGED: cannot enable script notifications unless WAN IP notify enabled (relies on cron)
* CHANGED: wan history in Email most recent to oldest and formatted
* ADDED: ability to exit any step in setup by entering e 
* MISC: script cleanup and optimizations (var change function)
