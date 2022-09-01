#!/usr/bin/env python
#
# Requirements: python-crontab
# To install: pip install python-crontab
#
# Author: ThisTooShallXSS (https://github.com/thistooshallxss)
# Requirements: Python 2.7+
#
# Example:
# python cron.py 'root' 'tag_tg_generator.py'
# python cron.py 'user1' 'agent_group_tg_generator.py'
#

def main():
    from crontab import CronTab
    import sys

    try:
        user_arg = sys.argv[1]
    except:
        print("No user given. Defaulting to root")
        user_arg = 'root'

    try:
        script_to_run = sys.argv[2]
    except:
        print("Please provide a python file to be ran inside quotes.")
        sys.exit()

    command = 'python {}'.format(script_to_run)
    cron = CronTab(user=user_arg)
    job = cron.new(command=command) 
    job.minute.every(15)

    cron.write()

if __name__ == '__main__':
    main()