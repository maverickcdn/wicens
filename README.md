# wicens.sh
    WICENS - WAN IP Change Email Notification Script.

This script when configured will send an Email 
to your Email(s) notifying you when your WAN IP
has changed.  Optional Firmware update and reboot
Email notifications.

Supports GMail, Hotmail, Outlook, ISP based Email

Supports amtm Email config import

SMTP Email send formats available:
* sendmail - StartTLS v1.1 higher (eg. GMail port 587)
* sendmail - StartTLS v1 only
* curl     - SSL (eg GMail port 465/amtm)
* sendmail - SMTP plain auth (no encryption)
* sendmail - ISP based (no password reqd, generally port 25)

See 'about' section within wicens.sh for more details

To download, copy/paste in an ssh terminal

`curl --retry 3 "https://raw.githubusercontent.com/maverickcdn/wicens/master/wicens.sh" -o "/jffs/scripts/wicens.sh" && chmod a+rx "/jffs/scripts/wicens.sh"`

Run with 'sh /jffs/scripts/wicens.sh'

After first run and new terminal session you should be able to run by simply typing wicens

Thank you for using this script.

SNBforums thread https://www.snbforums.com/threads/wicens-wan-ip-change-email-notification-script.69294/
