        WICENS - WAN IP Change Email Notification Script

This script when configured will send a notification to your Email(s)
notifying you when your WAN IP has changed.

Optional Firmware Update and Router Reboot notifications also available

Supports GMail, Hotmail, Outlook, ISP based Email

Supports amtm Email configuration import

Script will function in Double NAT scenarios but does not support Dual WAN
Dual WAN check can be disabled by editing setting in config manually

SMTP Email send formats available:
sendmail - StartTLS v1.1 higher (eg. GMail port 587)
sendmail - StartTLS v1 only
curl     - SSL (eg GMail port 465) # amtm default
sendmail - SMTP plain auth (no encryption)
sendmail - ISP based (no password reqd, generally port 25)

IMPORTANT - If using GMail/Outlook you must use 2 factor authentication and
setup an assigned App password for this script to use.

IMPORTANT - Your Email address(es) are stored as plain text within this
script.  Your Email password is encrypted and saved to router storage.
If you dont practice good security habits around your router ssh access,
this script might not be for you.

Script compares IP in nvram for wan0 to saved IP with wancall connected
events and cron, cron is also a watchdog and monitors for failed Email
attempts. Should the nvram IP be invalid/private IP script will use firmware
built in getrealip.sh to retrieve your WAN IP using Google STUN server.
If Dual Wan is enabled, script will abort before running getrealip.sh

All cron/wan-event/services-start/update-notification entries needed for this
script are automatically created and removed with enable and disable options.

NTP sync must occur to update router date/time for proper script function

### Technical ###

Supports being used as an Email forwarder for other scripts, in your
script call /jffs/scripts/wicens.sh send {your email.txt path here}
ie. /jffs/scripts/wicens.sh send /tmp/email.txt
Use option fe (unlisted) in the menu to view a sample Email .txt file

When using wicens as an Email forwarder you can pass a second argument after
the Email text path as an alternate send to address different from what is
saved in the current config ie. wicens send /path "myadd@mail.com"

Should Email sending fail the script will retry 4 more times with cron
1/11mins) in 172800 second intervals.

Script generates a lock file /tmp/wicens_lock.tty to prevent
duplicate runs as well as /tmp/wicens_internet_lock.tty
when sending Email notifications. Script will automatically remove stale
lock files if original starting process no longer exists or lock file are
over age limit.

Sendmail/Curl output for Emails is saved to /tmp/wicens_email.log for
debugging if needed.  This file can be viewed by running this script and
select option L||l

Sendmail doesnt always return an error code on a misconfiguration so false
send success can occur.  If script says Email has sent but no Email received
use option L||l from the Main Menu to read sendmail output for errors

The script does not update its saved WAN IP until the script has completed
sending the notification so in the event of message failure it should run
again with next cron run and attempt to send again.

Using option 5 you can call your own script either immediately upon WAN IP
change detection, or wait until the Email message has been successfully sent.
Script will be put in background as to not block this script.

Output from a custom script set to run on WAN IP change is saved to
/jffs/addons/wicens/user_script.log

Hidden menu options - 1f forces build_settings menu - fl remove mail log file
vv - list out all settings from config files - fr remove any found update
fe - show example Email text file for using wicens as Email forwarder

If you wish to see sample Reboot/FW update Emails you can force send them
by running wicens w/ reboot or fwupdate as an argument

Every Sunday the script will log the number of times it ran with wan-event.

Thank you for using this script.

SNBforums thread https://www.snbforums.com/threads/wicens-wan-ip-change-email-notification-script.69294/
