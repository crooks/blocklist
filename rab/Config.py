#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# nymserv.py - A Basic Nymserver for delivering messages to a shared mailbox
# such as alt.anonymous.messages.
#
# Copyright (C) 2012 Steve Crook <steve@mixmin.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTIBILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

import ConfigParser
import os
import sys


def makedir(d):
    """Check if a given directory exists.  If it doesn't, check if the parent
    exists.  If it does then the new directory will be created.  If not then
    sensible options are exhausted and the program aborts.

    """
    if not os.path.isdir(d):
        parent = os.path.dirname(d)
        if os.path.isdir(parent):
            os.mkdir(d, 0700)
            sys.stdout.write("%s: Directory created.\n" % d)
        else:
            msg = "%s: Unable to make directory. Aborting.\n" % d
            sys.stdout.write(msg)
            sys.exit(1)


# Configure the Config Parser.
config = ConfigParser.RawConfigParser()

# By default, all the paths are subdirectories of the homedir. We define the
# actual paths after reading the config file as they're relative to basedir.
config.add_section('paths')
homedir = os.path.expanduser('~')

# Logging
config.add_section('logging')
config.set('logging', 'level', 'info')
config.set('logging', 'format', '%(asctime)s %(levelname)s %(message)s')
config.set('logging', 'datefmt', '%Y-%m-%d %H:%M:%S')

config.add_section('general')
config.set('general', 'subject', 'Block Request')
config.set('general', 'mydomain', 'domain.invalid')
config.set('general', 'myname', 'Remailer Blocklist')
config.set('general', 'hash_output', 'no')
config.set('general', 'trim_keys', 20)
# Try to be clever about guessing my email name.
if '/' in homedir:
    config.set('general', 'myaddy', homedir.rsplit('/', 1)[1])
else:
    config.set('general', 'myaddy', homedir)


# Try and process the .mail2newsrc file.  If it doesn't exist, we bailout
# as some options are compulsory.
if 'MIXBLK' in os.environ:
    configfile = os.environ['MIXBLK']
else:
    configfile = os.path.join(homedir, '.rabrc')
if os.path.isfile(configfile):
    config.read(configfile)
else:
    sys.stdout.write("%s: Config file not found.\n" % configfile)
    sys.exit(1)
# Compulsory settings that have no defaults.
if not config.has_option('general', 'secret'):
    sys.stdout.write("%s: Secret phrase for hash salting much be set.\n"
                     % configfile)
    sys.exit(1)
# Now we check the directory structure exists and is valid.
if config.has_option('paths', 'basedir'):
    basedir = config.get('paths', 'basedir')
else:
    basedir = os.path.join(homedir, 'rab')
    config.set('paths', 'basedir', basedir)
makedir(basedir)

if not config.has_option('paths', 'log'):
    config.set('paths', 'log', os.path.join(basedir, 'log'))
makedir(config.get('paths', 'log'))

if not config.has_option('paths', 'lib'):
    config.set('paths', 'lib', os.path.join(basedir, 'lib'))
makedir(config.get('paths', 'lib'))

if not config.has_option('paths', 'etc'):
    config.set('paths', 'etc', os.path.join(basedir, 'etc'))
makedir(config.get('paths', 'etc'))

# Paths to specific files.  By default these are relative to directory paths
# defined earlier in this file.
if not config.has_option('paths', 'outfile'):
    config.set('paths', 'outfile', os.path.join(basedir, 'dest.blk'))
if not config.has_option('paths', 'request_db'):
    config.set('paths', 'request_db',
               os.path.join(config.get('paths', 'lib'), 'request.db'))
if not config.has_option('paths', 'duplicate_db'):
    config.set('paths', 'duplicate_db',
               os.path.join(config.get('paths', 'lib'), 'duplicate.db'))
if not config.has_option('paths', 'master_db'):
    config.set('paths', 'master_db',
               os.path.join(config.get('paths', 'lib'), 'master.db'))
if not config.has_option('paths', 'request_txt'):
    config.set('paths', 'request_txt',
               os.path.join(config.get('paths', 'etc'), 'request.txt'))
if not config.has_option('paths', 'duplicate_txt'):
    config.set('paths', 'duplicate_txt',
               os.path.join(config.get('paths', 'etc'), 'duplicate.txt'))
if not config.has_option('paths', 'success_txt'):
    config.set('paths', 'success_txt',
               os.path.join(config.get('paths', 'etc'), 'success.txt'))
if not config.has_option('paths', 'failed_txt'):
    config.set('paths', 'failed_txt',
               os.path.join(config.get('paths', 'etc'), 'failed.txt'))

# Write the default text files if they don't exist.
if not os.path.isfile(config.get('paths', 'request_txt')):
    f = open(config.get('paths', 'request_txt'), 'w')
    f.write("""\
Subject: Request for subscription to Remailer Abuse Blocklist

This email is a response to a request to subscribe your email address to the
Remailer Abuse Blocklist.  If you didn't submit this request, please ignore
this email; someone else has attempted to submit your address.  If however you
did submit such a request, please read on.

In order to complete your subscription to the blocklist you need to respond to
this email, keeping the content intact.  In other words, don't create a new
email, instead use your email application's Reply functionality to create a
response.  Once this response has been processed, you will receive confirmation
of your successful subscription.

We apologise if this process appears complicated but it is important to ensure
that your request is a genuine one and not a forgery.

Regards
RAB Administrators
""")
    f.close()
if not os.path.isfile(config.get('paths', 'duplicate_txt')):
    f = open(config.get('paths', 'duplicate_txt'), 'w')
    f.write("""\
Subject: Duplicate request for subscription to Remailer Abuse Blocklist

This email is a response to a request to subscribe your email address to the
Remailer Abuse Blocklist.  If you didn't submit this request, please ignore
this email; someone else has attempted to submit your address.  If however you
did submit such a request, please read on.

You appear to have submitted a duplicate subscription request.  Please ensure
that when you respond to this email you use the correct address, as specified
in the From and Reply-To headers of this email.

To prevent abuse of your email address, you will receive no further infomation
in relation to this service for 24 hours.  After that, you may resubmit your
request if desired.

Regards
RAB Administrators
""")
    f.close()
if not os.path.isfile(config.get('paths', 'success_txt')):
    f = open(config.get('paths', 'success_txt'), 'w')
    f.write("""\
Subject: Congratulations, your address has been added to the RAB.

Your application to the Remailer Abuse Blocklist has been successfully
processed.  There may be a delay of up to 24 hours whilst this update is
propagated to the participating Anonymous Remailers.  If you continue to
receive unwanted emails via remailers after this time, please contact the abuse
address supplied on those emails.  It may be that the operator is not
participating in the RAB scheme.

Regards
RAB Administrators
""")
    f.close()
if not os.path.isfile(config.get('paths', 'failed_txt')):
    f = open(config.get('paths', 'failed_txt'), 'w')
    f.write("""\
Subject: RAB subscription failed

Your application to the Remailer Abuse Blocklist was unsuccessful.  The
confirmation email we received from you was incorrect.  That's to say, it was
corrupted in some way or was returned to the wrong confirmation address.

If you are trying to subscribe and haven't received a confirmation request,
please send an email to rab@blocklist.mixmin.net.  If you do have a
confirmation request, please try sending another mail to the Reply-To address
in that email.  Please ensure that you send your confirmation using your mail
client's Reply functionality, not by sending a new email.

Regards
RAB Administrators
""")
    f.close()

#with open('samples/rabrc', 'wb') as configfile:
#    config.write(configfile)
