#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 autoindent
#
# rab.py -- Control program for the Remailer Abuse Blocklist
#
# Copyright (C) 2005 Steve Crook <steve@mixmin.org>
# $Id$
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

from Config import config
import logging
import re
import bsddb
import hashlib
import os.path
import smtplib
import sys
import datetime
import email


def init_logging():
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    loglevels = {'debug': logging.DEBUG, 'info': logging.INFO,
                'warn': logging.WARN, 'error': logging.ERROR}
    log = logging.getLogger('rab')
    log.setLevel(logging.DEBUG)
    fh = logging.FileHandler(os.path.join(config.get('paths', 'log'),
                                          'rab.log'))
    fh.setLevel(loglevels[config.get('logging', 'level')])
    fh.setFormatter(logging.Formatter(logfmt, datefmt=datefmt))
    log.addHandler(fh)
    return log


def address_hash(address):
    """Take a plain-text address and convert it to a sha256 hash.  We use
    this function when configured to output a hashed rab.blk file."""
    hexsha = hashlib.sha256(address).digest().encode("hex")
    log.debug('Address %s hashes to %s', address, hexsha)
    return hexsha


def genhash(sender, timestamp):
    """Create a hash to use as a key for confirming requests.  The key
    consists of a secret+email_address+timestamp."""
    s = hashlib.sha224(config.get('general', 'secret'))
    s.update(sender)
    s.update(timestamp)
    hexsha = s.digest().encode("hex")[:config.getint('general', 'trim_keys')]
    log.debug("Generated a hash of: %s" % hexsha)
    return hexsha


def myaddress():
    """Join myaddy and mydomain config parameters to create an email address
    for the blocklist"""
    addy = "%s@%s" % (config.get('general', 'myaddy'),
                      config.get('general', 'mydomain'))
    return addy


def utcnow():
    """Just return the utc time.  Everything should work on utc."""
    utctime = datetime.datetime.utcnow()
    utcstamp = utctime.strftime("%Y-%m-%d %H:%M:%S")
    return utcstamp


def hours_ago(past_hours):
    """Return a timestamp for a given number of hours prior to utc. This
    is used by housekeeping to clear expired entries from the request and
    dupcheck databases."""
    thentime = (datetime.datetime.utcnow() -
                datetime.timedelta(hours=past_hours))
    timestamp = thentime.strftime("%Y-%m-%d %H:%M:%S")
    return timestamp


def opendbs():
    """The RAB functions around three bsddb style databases. All of them are
    an identical format: Key:Email Address, Data:Timestamp.
    request     New requests that haven't been confirmed
    depcheck    Re-requests.  Where a second request is received whilst
                expecting a confirmation. We only respond to these once
                in order to avoid the RAB being used to annoy people.
    master      The actual RAB itself.  Confirmed and accepted addresses.
    As we use all these databases for every aspect of functionality, we
    unconditionally open them all."""
    global request
    log.debug("Opening request database: %s"
              % config.get('paths', 'request_db'))
    request = bsddb.hashopen(config.get('paths', 'request_db'))
    global dupcheck
    log.debug("Opening dupcheck database: %s"
              % config.get('paths', 'duplicate_db'))
    dupcheck = bsddb.hashopen(config.get('paths', 'duplicate_db'))
    global master
    log.debug("Opening RAB master database: %s"
              % config.get('paths', 'master_db'))
    master = bsddb.hashopen(config.get('paths', 'master_db'))


def closedbs():
    """Close the various bsddb databases."""
    log.debug("Closing request database")
    request.close()
    log.debug("Closing dupcheck database")
    dupcheck.close()
    log.debug("Closing RAB master database")
    master.close()


def clean_address(addr):
    """Cleanup and return an email address"""
    # Strip linefeeds from the address.
    addr = addr.rstrip('\n')
    # Make sure the address is entirely lower case
    addr = addr.lower()
    return addr


def new_request(sender):
    """New requests start here, as do duplicate new requests.  We give
    an initial chance, followed by a duplicate warning and a second
    chance.  Then silence for 24 hours, although a valid confirmation
    will still be accepted.  Repeated attempts will cause a rolling 24
    hours from the last attempt."""
    log.info("Entering new request process for %s", sender)
    timestamp = utcnow()
    if sender in request:
        log.info("Address %s is already in the request database", sender)
        # This email address has already been processed today. Has it
        # been seen twice?
        if not sender in dupcheck:
            # It's not been seen twice, send a duplicate email.
            log.info("Address %s is a first-time duplicate, will resend"
                        % sender)
            key = genhash(sender, request[sender])
            email_create(config.get('paths', 'duplicate_txt'), sender, key)
            log.debug("Adding %s to duplicates database", sender)
            dupcheck[sender] = timestamp
        else:
            # We've twice sent a confirm request, time to ignore.
            log.warn("Ignoring request from %s, we sent two confirms already."
                     % sender)
    else:
        # There is no entry for this email address, treat it as new.
        log.debug("We have a new block request from %s" % sender)
        key = genhash(sender, timestamp)
        request[sender] = timestamp
        email_create(config.get('paths', 'request_txt'), sender, key)


def process(payload):
    """This is where it all starts to happen.  The function expects to be
    passed either a simple email address, or an entire email from which it can
    extract the sender address."""
    # Open the databases
    # Housekeeping clears old requests from the DB's.
    housekeeping()
    is_email = re.compile(r'[\w\-][\w\-\.]*@[\w\-][\w\-\.]+[a-zA-Z]{1,4}$')
    if is_email.match(payload):
        sender = clean_address(payload)
        log.info("We have been passed an address %s.  Treating as new "
                    "request." % sender)
        new_request(sender)
    else:
        msg = email.message_from_string(payload)
        # Use email Utils to extract the address from the From and To fields.
        # We don't use the real names but we get them anyway.
        sendname, sender = email.Utils.parseaddr(msg['From'])
        sender = clean_address(sender)
        log.info("Processing RAB email from %s", sender)
        recipname, recipient = email.Utils.parseaddr(msg['X-Original-To'])
        log.debug("Recipient is %s", recipient)
        # If the recipient is exactly my address, this cannot be a confirmation
        # as there's no delimiter and extension.  Treat it as a new request.
        if recipient == myaddress():
            log.debug("Recipient matches my configured address.")
            if msg['Subject']:
                subject = msg['Subject'].lower()
                # Strip leading and trailing spaces
                subject = subject.strip(' ')
                if subject == config.get('general', 'subject').lower():
                    log.debug("Subject on new request is accepted.")
                    new_request(sender)
                else:
                    log.info("Invalid Subject on new request. Not "
                             "processing.")
            else:
                log.warn("No Subject header on new request. Not processing.")
        # It's not an exact match to my address, so does it start with my name
        # and a '+' delimiter?  If so, treat it as a confirmation email.
        elif recipient.startswith(config.get('general', 'myaddy') + "+"):
            log.debug("Recipient starts with my address, looks like a "
                      "confirmation request.")
            if confirm(sender, recipient):
                log.info("Attempting to add %s to the RAB", sender)
                writerab(sender)
                cleanup(sender)
                # We need to pass False to create_email as there's no hash key
                # on a success email.
                email_create(config.get('paths', 'success_txt'), sender,
                             False)
            else:
                log.info("Address %s is not added to the RAB", sender)
                # If the sender if in the duplicates database, don't send
                # failure emails as their address might be under attack.
                if not sender in dupcheck:
                    log.debug("%s not in duplicates db, sending failure "
                              "email" % sender)
                    email_create(config.get('paths', 'failed_txt'), sender,
                                 False)
                else:
                    log.info("Not sending failure notice to %s due to "
                             "duplicate flag" % sender)
                # We update the dupcheck database with the current timestamp.
                # This prevents abuse for 24 hours from now.
                dupcheck[sender] = utcnow()
        elif not recipient:
            log.info("Empty To header, probably Bcc'd spam.  Ignore it.")
        # It's not an exact match indicating a new request.  It's not a
        # confirmation email as we tried that too.  Give up, it's a bad'n.
        else:
            log.warn("Unrecognized recipient %s. Giving up.", recipient)
    log.debug("Closing databases")


def confirm(sender, recipient):
    """The confirmation process breaks down the recipient email address into
    its component parts; name(+)extension(@)domain.  All three components are
    validated within this function and True is returned is everything checks
    out correctly."""
    sender = clean_address(sender)
    log.info("Entering confirmation process for %s", sender)
    # Split the name from the +recipient@domain
    name, therest = recipient.split('+', 1)
    log.debug("Splitting recipient name gives %s", name)
    sentkey, domain = therest.split('@', 1)
    log.debug("Splitting key and domain gives %s and %s", sentkey, domain)
    if name != config.get('general', 'myaddy'):
        log.warn("Recipient %s doesn't match configured %s"
                 % (name, config.get('general', 'myaddy')))
        return False
    if domain != config.get('general', 'mydomain'):
        log.warn("Received domain %s doesn't match configured %s"
                    % (domain, config.get('general', 'mydomain')))
        return False
    if len(sentkey) != config.getint('general', 'trim_keys'):
        log.warn("We expected a 56char hash, we didn't get it.")
        return False
    if sender in request:
        log.debug("Confirming request from %s", sender)
        timestamp = request[sender]
        key = genhash(sender, timestamp)
        if sentkey == key:
            log.debug("Key received from %s is correct", sender)
            return True
        else:
            log.info("Key received from %s is wrong, not accepting it"
                     % sender)
            return False
    else:
        # The confirmation sender isn't listed in the requests database.
        log.info("Confirmation email from %s but not expecting one"
                    % sender)
        return False


def writerab(sender):
    """Check if the Master DB contains the new address, if it does, just
    update the timestamp.  If it doesn't, add an entry for it with the current
    timestamp.  Lastly, write the text rab.blk file in either plain or hashed
    format depending on configuration (config.hashoutput).

    Updating the timestamp on existing entries allows for potential future
    functionality for expiring old addresses.  This will only really be
    required if the list grows to an unexpected volume of addresses."""
    timestamp = utcnow()
    if sender:
        if sender in master:
            log.info("RAB file already contains address %s.  Updating "
                     "timestamp" % sender)
        else:
            log.info("Address %s not in RAB, adding with timestamp %s"
                     % (sender, timestamp))
        master[sender] = timestamp
    else:
        log.info("Not passed a sender, just refreshing lists.")
    try:
        rab = open(config.get('paths', 'outfile'), "w")
    except IOError:
        log.error("Unable to open %s for writing."
                  % config.get('paths', 'outfile'))
    # Within the next loop we actually write the RAB text file, either in
    # plain text or in hashed format depending on config.hashoutput.
    for entry in master.keys():
        if config.getbool('general', 'hash_output'):
            hash = address_hash(entry)
            rab.write(hash + "\n")
        else:
            rab.write(entry + "\n")
    rab.close()


def email_create(filename, recipient, key):
    """Create an email for responding to subscription requests.  This
    could be a new request or a duplicate depending on the filename."""
    # Just to make sure we don't have a LF on the recipient, this breaks
    # the email.
    recipient = recipient.rstrip('\n')
    if key:
        log.debug("Creating a confirmation email to %s", recipient)
        msg = ("From: Remailer Abuse Blocklist <%s+%s@%s>\n"
               % (config.get('general', 'myaddy'), key,
                  config.get('general', 'mydomain')))
        msg += ("Reply-To: %s+%s@%s\n"
                % (config.get('general', 'myaddy'), key,
                   config.get('general', 'mydomain')))
    else:
        log.debug("Creating a basic email to %s", recipient)
        msg = ("From: Remailer Abuse Blocklist <%s@%s>\n"
               % (config.get('general', 'myaddy'),
                  config.get('general', 'mydomain')))
    msg += "To: %s\n" % (recipient,)
    try:
        request = open(filename, "r")
    except IOError:
        log.error("File %s doesn't exist, can't send email.", filename)
        #TODO: Hard exit is nasty.  Should return something.
        sys.exit(1)
    payload = request.readlines()
    for line in payload:
        msg = msg + line
    sendmail(recipient, msg)


def sendmail(recipient, msg):
    """Call Python's smtplib routine to send an email."""
    log.info("Sending email to %s", recipient)
    server = smtplib.SMTP('localhost')
    #server.set_debuglevel(1)
    server.sendmail(myaddress(), recipient, msg)
    server.quit()


def housekeeping():
    """Housekeeping checks the timestamps in the requests and dupcheck DB's.
    If they are sufficiently old, they are removed.  This process is run
    unconditionally with each request."""
    log.debug("Beginning housekeeping")
    age = hours_ago(24)
    log.debug("Checking for expired requests.")
    for address in request.keys():
        if request[address] < age:
            log.debug("%s has expired in requests.", address)
            if not address in dupcheck:
                log.info("%s not in duplicates, deleting from requests."
                         % address)
                del request[address]
            elif dupcheck[address] < age:
                log.debug("%s expired in dupcheck and requests. Deleting "
                          "both" % address)
                del request[address]
                del dupcheck[address]
            else:
                log.debug("%s expired in requests but still valid in "
                          "dupcheck." % address)
    # If requests DB is empty then so should dupcheck be empty.  You can't
    # have a duplicate of something you don't have!
    if len(request) == 0:
        log.debug("Request DB is empty.  Checking dupcheck DB is also "
                  "empty.")
        if len(dupcheck) != 0:
            log.warn("Database dupcheck is not empty.  It should be! "
                     "Deleting entries.")
            for address in dupcheck.keys():
                log.info("Deleting %s from dupcheck.", address)
                del dupcheck[address]
    request.sync()
    dupcheck.sync()
    log.debug("Housekeeping complete")


def listrab():
    """Do nothing other than list the content of the Master Database."""
    for entry in master.keys():
        print entry, master[entry]


def delrabkey(key):
    """Delete a given email entry from any databases it occurs in."""
    if key in master:
        log.info("Deleting %s from Master DB at operator request", key)
        del master[key]
        master.sync()
        writerab(None)
    if key in request:
        log.info("Deleting %s from Request DB at operator request", key)
        del request[key]
        request.sync()
    if key in dupcheck:
        log.info("Deleting %s from Duplicate DB at operator request", key)
        del dupcheck[key]
        dupcheck.sync()


def cleanup(sender):
    """Cleanup takes an email address and removes it from the request and
    dupcheck databases (if it's in them)."""
    # If the request db has the sender in it, delete them.
    if sender in request:
        log.debug("Removing %s from requests database", sender)
        del request[sender]
    # If the dupcheck db has the send in it, delete them.
    if sender in dupcheck:
        log.debug("Removing %s from duplicates database", sender)
        del dupcheck[sender]


def validate_command(cmd):
    cmds = ["refresh", "list", "add", "delete"]
    if cmd.startswith("--"):
        cmd = cmd[2:]
        if cmd in cmds:
            return cmd
        else:
            sys.stdout.write("%s is not a valid command\n" % (cmd,))
            sys.exit(1)
    else:
        sys.stdout.write("Not passed a command\n")
        sys.exit(1)


def main():
    opendbs()
    # Read input from stdin
    args = sys.argv
    args.pop(0)
    if len(args) > 0:
        cmd = validate_command(args[0])
        log.info("Processing %s command.", cmd)
        if cmd == "refresh":
            writerab(None)
        if cmd == "list":
            listrab()
        if cmd == "add" and len(args) > 1:
            writerab(args[1])
        if cmd == "delete" and len(args) > 1:
            delrabkey(args[1])
    else:
        # The main processing routine.  All else is called from there.
        sys.stdout.write("Enter address (or email) then Ctrl-D to submit.\n")
        input = sys.stdin.read()
        process(input)
    closedbs()

# As always, initialize logging before anything else.
log = init_logging()
if (__name__ == "__main__"):
    main()
