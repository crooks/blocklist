#!/usr/bin/python
# 
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# $Id$

import re
import cgi
import smtplib

# Define function to generate HTML form.
def generate_form():
    print "<HTML>"
    print "<HEAD>"
    print "<TITLE>Anonymous Remailer Abuse Blocklist</TITLE>"
    print "</HEAD>"
    print "<BODY BGCOLOR = white>"
    print "<H2>Anonymous Remailer Abuse Blocklist</H2>"
    print """This webpage provides an easy interface for submitting your email address to
the Remailer Abuse Blocklist (RAB).  The RAB is a list of email addresses
belonging to people who do not wish to receive email through Anonymous
Remailers.  Whilst Remailers are intended to provide a valuable service, there
is a small contingent of people who use them to abuse and harass others.  This
service enables those people to request that they no longer reveive any email
from anonymous sources.

Please be aware that not all Anonymous Remailers subscribe to this service so
it is possible that even after successful subscription, you may still receive
unwanted messages.  In these instances you will have to contact the originating
service directly at their abuse address.

After submitting your address to this form, you will receive a confirmation
email that you must reply to in order to complete your subscription.  This step
is required to ensure that the submitted address is owned by the requester.
After responding to the confirmation email you will receive a final
notification of your successful subscription."""
#    print "<br><br><TABLE BORDER = 0>"
    print "<FORM METHOD = post ACTION = \"rab.cgi\">"
    print "<br><br>Email Address:</TH><TD><INPUT type=text \
name=\"email\" maxlength=72 size=72></TD></TR>"
    print "<INPUT TYPE=hidden NAME=\"action\" VALUE=\
\"display\">"
    print "<br><br><INPUT TYPE=submit VALUE=\"Submit\">"
    print "</FORM>"
    print "</BODY>"
    print "</HTML>"

# Define function display data.
def success():
    print "<HTML>"
    print "<HEAD>"
    print "<TITLE>Anonymous Remailer Abuse Blocklist</TITLE>"
    print "<meta http-equiv=\"REFRESH\" content=\"8;url=\"http://www.mixmin.net/cgi-bin/rab.cgi\">"
    print "</HEAD>"
    print "<BODY BGCOLOR = white>"
    print "<H2>Request Accepted</H2>"
    print """Your email address has been accepted and you should receive a
 confirmation message shortly.<br>Please follow the instructions in this email
to complete your Blocklist subscription."""
    print "</BODY>"
    print "</HTML>"

def failure():
    print "<HTML>"
    print "<HEAD>"
    print "<TITLE>Anonymous Remailer Abuse Blocklist</TITLE>"
    print "<meta http-equiv=\"REFRESH\" content=\"8;url=\"http://www.mixmin.net/cgi-bin/rab.cgi\">"
    print "</HEAD>"
    print "<BODY BGCOLOR = white>"
    print "<H1>Error</H1>"
    print "<H2>Your submission has not been accepted.</H2>"
    print "Please note that you must submit a single, valid email address.<br>"
    print "You will shortly be returned the the submission interface"
    print "</BODY>"
    print "</HTML>"

# Define main function.
def main():
    print "Content-Type: text/html\n"
    form = cgi.FieldStorage()
    if form.has_key("email"):
        if (form["action"].value == "display"):
            address = form["email"].value
            is_email = re.compile(r'[\w\-][\w\-\+\.]*@[\w\-][\w\-\.]+[a-zA-Z]{1,4}$')
            if is_email.match(address):
                sendmail(address)
                success()
            else:
                failure()
    else:
        generate_form()

def sendmail(address):
    """Call Python's smtplib routine to send an email."""
    msg = "From: %s\n" % (address,)
    msg = msg + "To: rab@blocklist.mixmin.net\n"
    msg = msg + "Subject: Block Request\n"
    server = smtplib.SMTP('localhost')
    server.set_debuglevel(1)
    server.sendmail(address, "rab@blocklist.mixmin.net", msg)
    server.quit()

# Call main function.
if (__name__ == "__main__"):
    main()
