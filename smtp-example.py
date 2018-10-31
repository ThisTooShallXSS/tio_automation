#!/usr/bin/env python
#
# Notes:
# This is a sample SMTP script. Doesn't really do much but gives the
# necessary base of code to send a notification/email of your choosing.
#
# Author: ThisTooShallXSS (https://github.com/thistooshallxss)
# Requirements: Python 2.7
#
# Usage: 
# - python smtp-python-example.py

SMTP_SERVER_HOST = 'smtp.company.com'
SMTP_SERVER_PORT = 25
SMTP_SENDTO_ADDR = ['it-security@company.com']
SMTP_FROM_ADDR = 'noreply@company.com'

def some_action():
    import datetime, time

    ts = time.time()
    timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

    if email_notify(timestamp):
        print("{}|An email was sent out.").format(timestamp)
    else:
        print("Failed to send email.")

def email_notify(time):
    import smtplib
    ip = '192.168.1.1'

    email_text = 'This is an email.\n\nHost IP: {}\nTimestamp: {}'.format(ip, time)
    email_subject = 'Report to be sent: {}'.format(ip)
    message = 'From: {}\nTo: {}\nSubject: {}\n\n{}\r\n'.format(SMTP_FROM_ADDR, SMTP_SENDTO_ADDR, email_subject, email_text)

    try:
        mail = smtplib.SMTP(SMTP_SERVER_HOST, SMTP_SERVER_PORT)
        mail.starttls()
        mail.ehlo("example.com")
        mail.mail(SMTP_FROM_ADDR)
        mail.rcpt(SMTP_SENDTO_ADDR)
        mail.data(message)
        mail.quit()
        ret = 1
    except:
        ret = 0

    return ret

def main():
    some_action()

if __name__ == '__main__':
    main()
