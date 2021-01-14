# wicens.sh
        WICENS - WAN IP Change Email Notification Script.

This script when configured will send an Email (1-4) at variable intervals
X(second/minute/hour/day) to your Email notifying you when your WAN IP
has changed.

Supports GMail, Hotmail, Outlook

SMTP Email send formats available:
sendmail - StartTLS v1.1 higher (eg. GMail port 587)
sendmail - StartTLS v1 only
curl     - SSL (eg GMail port 465)
sendmail - SMTP plain auth (no encryption)
sendmail - ISP based (no password reqd, generally port 25)

IMPORTANT - If using GMail, you must enable 'insecure app' access to your
GMail account. If you use 2factor authentication you must setup an assigned
password in GMail for this script to use.

IMPORTANT - Your Email address(es) are stored as plain text within this
script.  Your Email password is obfuscated and saved to the script.
If you dont practice good security habits around your router ssh access,
this script might not be for you.

Uses firmware built in getrealip.sh to retrieve your WAN IP using Google
STUN server. This will show your WAN IP regardless if your router is behind
NAT (unbridged modem) or not.

Executed by settable minute || hour cron run (default 31min) for checking
your current WAN IP. Also executed by 'wan-event connected' trigger. A DHCP
renewal when your IP changes may not trigger a 'wan-event connected' event.

All cron/wan-event entries are automatically generated upon completion of
your Email user login information and is double checked with every run.

'wan-event connected' execution has a 90 sec delay from trigger to WAN IP
check as we wait for DHCP/NTP to catch up on reboots.

### Technical ###

Script generates a lock file in /tmp called wicens.lock to prevent
duplicate runs as well as another file in /tmp called wicenssendmail.lock
when sending Email notifications. Script will automatically remove (with
cron) stale lock files if original starting process no longer exists or
lock files are over age limit.

Sendmail/Curl output for Emails is saved to /tmp/wicenssendmail.log for
debugging if neeeded.  This file can be viewed by running this script and
select option 6

Sendmail doesnt always return an error code on a misconfiguration so false
send success can occur.  If script says Email has sent but no Email received
use option 6 from the Main Menu to read sendmail output for errors

The script does not update its saved WAN IP until the script has completed
sending all notifications and adds to the Email message of success or
failure in updating it, so in the event of message failure it should run
again with next cron run and attempt to send again.

Using option S you can call your own script either immediately upon WAN IP
change detection, or wait until all Email messages have been sent and
script has successfully updated. Script will be put in background as to not
block this script

Every Sunday the script will log the number of calls from cron/wan-event.

To download, copy/paste in an ssh terminal

`curl --retry 3 "https://raw.githubusercontent.com/maverickcdn/wicens/master/wicens.sh" -o "/jffs/scripts/wicens.sh" && chmod a+rx "/jffs/scripts/wicens.sh"`

Run with 'sh /jffs/scripts/wicens.sh'

After first run, you should be able to run by simply typing wicens

Thank you for using this script.
