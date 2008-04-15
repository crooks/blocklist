#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 autoindent
#
# template.py -- This is a template for new Python programs
#
# Copyright (C) 2005 Steve Crook <steve@mixmin.org>
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

# Fully-qualified path to the rab.blk file we will read/write.
rabfile = '/home/rab/rab/data/rab.blk'

# Fully-qualified path to our logfile.
logfile = '/home/rab/rab/log'
# What loglevel should we run at?
loglevel = 'info'

# The secret key we use for hash authentication
secret = "Telephone boxes make my pet onion cry"
# We insist on a valid Subject on new requests so as not to auto-respond to
# spam emails with false From headers.
subject = "Block Request"

# Fully-qualified path to the requests db.
reqfile = "/home/rab/rab/data/request.db"
# Fuly-qualified path to the dupcheck db.
dupfile = "/home/rab/rab/data/duplicate.db"
# Fully-qualified path to the master db.
masterfile = "/home/rab/rab/data/master.db"

# The name and domain components of the email account that will send/receive
# emails for the RAB (myname@mydomain).
myname = "rab"
mydomain = "blocklist.mixmin.net"

# Do we want the final rab file written in plain-text or hashed format?
hashoutput = False

# Fully-qualified paths to the various text files we send in emails.
request_payload = "/home/rab/rab/request.txt"
duplicate_payload = "/home/rab/rab/duprequest.txt"
success_payload = "/home/rab/rab/success.txt"
failed_payload = "/home/rab/rab/failed.txt"
