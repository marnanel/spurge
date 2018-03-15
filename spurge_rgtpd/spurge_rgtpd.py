#!/usr/bin/python3
"Spurge RGTP server (simple python-based user-friendly reverse gossip engine)"

#
# Copyright (c) 2002 Thomas Thurman
# thomas@thurman.org.uk
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have be able to view the GNU General Public License at 
# http://www.gnu.org/copyleft/gpl.html ; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.

################################################################
#
# Still to implement:

# Primary importance (needed for r/o operation)
# Secondary importance (needed for ordinary append access):
# -- all done

# Tertiary importance (needed for editing):
# EDLK EDUL EDIT EDIX EDCF EDAB MOTS

# Not very important (random little commands):
# ALVL ELOG DIFF UDBM
#
# Note that there's also no contention control,
# and there should be.
# 
################################################################

import sys
import configparser
import os.path
import hashlib
import binascii
import re
import socket
import traceback
import time
import random
import smtplib
import getopt

basic_config_filename = '/etc/spurge.conf'

################################################################

def auth_level(code):
    try:
        return ['none', 'read-only', 'append', 'editor'][code]
    except IndexError:
        raise "Unknown access level (%d)!" % (code)

################################################################

class blob:
    "A file on disk."

    def __init__(self, name):
        self.name = name

    def spew_into(self, target, filter=None):
        for line in open(self.name).xreadlines():
            if not filter or filter(line):
                target.output_line(line[:-1])

################################################################

def readln():
    "Returns the next line from stdin, with trailing control characters removed."
    str = sys.stdin.readline()
    while str and ord(str[-1])<32: str=str[:-1]
    return str

################################################################

# stuff we lifted from yarrow
# (hmm, should have some sort of mutual dependency thing)

def inverted_bitstring(x):
    result = ""
    for i in range(len(x)):
        result = result + chr(255-ord(x[i]))
    return result

def random_hex_string(length = 32):
    "Generates a string of random hex digits. Useful for nonces."

    result = ''

    # The easiest way to generate a hex digit is using the built-in
    # hex() function, which returns strings of the form "0x7"-- so
    # we take the third character.
    
    for n in range(0, length):
        result = result + hex(int(random.random()*16))[2]

    return result

################################################################

class connection:

    def __init__(self, config, vaultname):

        self.remote_host = calling_host()
        self.user = None
        self.grogname = None
        self.data = None
        self.expecting_secret = None
        self.creating_account = 0
        self.server_nonce = None
        self.itemid_regexp = re.compile('^[A-Z][0-9]{7}$')
        self.partial_log_line = None
        self.continuing = None
        self.config = config
        self.language = self.conf('default-language')
        self.access_level = self.confbool('allow-anonymous')
        self.potential_access_level = self.access_level
        self.directory = os.path.join(self.conf('vault-dir'),
                          vaultname)

        if self.confbool('logging'):
            self.logfile = open(os.path.join(self.conf('log-dir'),
                             vaultname+'.log'),
                        'a')
        else:
            self.logfile = None

        self.log('(connect)')

    def flush_log(self):
        "If there's data waiting in partial_log_line, writes it out."
        if self.logfile and self.partial_log_line:
            self.logfile.write('%s\n' % (self.partial_log_line))
            self.logfile.flush()
            self.partial_log_line = None

    def log(self, message):
        if self.logfile:
            self.flush_log()

            if self.user:
                if self.potential_access_level != self.access_level:
                    # We're not sure they are who they claim to be.
                    username = '(%s)' % (self.user)
                else:
                    username = self.user
            else:
                username = '-'

            self.partial_log_line = '%s %s [%s] %s' % (
                self.remote_host,
                username,
                time.ctime(),
                message,
                )

    def discuss(self):
        self.boilerplate('hello-' + auth_level(self.access_level))

        while 1:
            sys.stdout.flush()
            self.flush_log()
            command = readln()

            if not command:
                self.log('(disconnect)')
                self.handle_quit()

            # fixme: need sanity check here; command can't
            # be over 300 bytes according to the protocol

            self.log('"' + command + '"')
            command = command.split(' ', 1)
            if len(command)==1:
                params = ''
            else:
                params = command[1]
                
            command = 'handle_'+command[0].lower()[:4]
            methods = self.__class__.__dict__
            if methods.has_key(command):
                flags = methods[command].__doc__
                flags = flags[:flags.index(':')]

                if int(flags[0]) > self.access_level:
                    self.boilerplate('permission')
                elif ('d' in flags) and not self.data:
                    self.boilerplate('need-data')
                elif ('e' in flags) and not self.edit_lock:
                    self.boilerplate('need-lock')
                else:
                    methods[command](self, params)
            else:
                self.boilerplate('parse-fail')

    ################################################################

    def boilerplate(self, name):
        "Outputs a piece of boilerplate text."
        self.output(self.config.getint('codes', name),
                self.config.get('lang-'+self.language, name))

    def output(self, code, message=''):
        sys.stdout.write('%03d %s\r\n' % (code, message))
        if self.logfile:
            self.partial_log_line = '%s %03d' % (
                self.partial_log_line,
                code)

    def output_line(self, line):
        sys.stdout.write(line + '\r\n')

    def end_output(self):
        sys.stdout.write('.\r\n')

    ################################################################

    def handle_user(self, params):
        "0:say who you are"

        # The USER command has two distinct uses.
        # Usually it introduces a user who already has
        # an account, but sometimes it's the second
        # half of a REGU command.

        if self.creating_account:
            self.registration_handle_user(params)
        else:
            self.logging_in_handle_user(params)

    def logging_in_handle_user(self, params):
        "The USER command, when it's for identification."
        if self.user:
            self.boilerplate('double-user')
        else:
            requested_access = 3
            params = params.split(' ')
            if len(params)>1 and params[1]:
                request_char = params[1][0]
                if request_char in ('1', '2', '3'):
                    requested_access = int(request_char)
            username = params[0]
            users = configparser.ConfigParser()
            users.read(self.filename('users'))
            if not users.has_section(username):
                self.boilerplate('unknown-user')
                self.exit_program()

            allowed_access = users.getint(username,
                              'access')
            self.user = username

            if not users.has_option(username, 'secret'):
                # Oh, okay; better just let them in, then.
                self.access_level = self.potential_access_level = allowed_access
                self.boilerplate('guest-'+auth_level(allowed_access))
                return

            self.expecting_secret = users.get(username,
                              'secret')
            self.potential_access_level = max(requested_access,
                              allowed_access)

            self.boilerplate('prove-who-you-are')
            self.server_nonce = random_hex_string()
            self.output(333, self.server_nonce)

    def registration_handle_user(self, params):
        "The USER command for creating a new account."

        if not re.match('^[^@\s<>]*@[^.\s<>]*\.[^\s<>]*$',
                params):
            # That's not an email address.
            # (ObPython:
            #   "That's not a part of the body!"
            #   "No, it's a link, though.")

            self.boilerplate('unearthly-email-address')
            return

        users = configparser.ConfigParser()
        users.read(self.filename('users'))

        if users.has_section(params):
            # Getting a case of deja vu here: that person already
            # has an account!

            self.boilerplate('already-have-an-account')
            return

        # FIXME: and we should also check the userid against
        # the REs in the config file. We need three kinds
        # of address:
        #
        #  * People who we give accounts to when they ask
        #  * People who don't get accounts at all when they ask
        #  * People who we have to ask the editors about
        # and for this category, we also need something in UDBM
        # to let the editors say yes or no.
        #
        # Anyway...

        # Okay, looks like they're real. Create them a password...
        new_password = random_hex_string(8)

        # ...and add them to the users file.
        users.add_section(params)
        users.set(params, 'secret', new_password)
        users.set(params, 'access', self.conf('newbie-privs'))

        users.write(open(self.filename('users'), 'w'))
        
        # Now we just have to send them some mail.

        mail_from = None
        if self.config.has_option('main', 'mail-from'):
            mail_from = self.conf('mail-from')
        else:
            mail_from = 'root@' + socket.gethostname()

        mail = smtplib.SMTP(self.conf('smtp-server'))
        mail.sendmail(mail_from,
                  params,
                  ('From: %s\r\n'+
                  'To: %s\r\n'+
                  'Delivered-By-The-Graces-Of: Spurge\r\n'+
                  'Subject: %s\r\n'+
                  '\r\n%s') % (
            mail_from,
            params,
            self.conf('newbie-email-subject'),
            self.conf('newbie-email-body').replace('[SECRET]', new_password)))
        mail.quit()
        
        self.boilerplate('created-user')
        self.exit_program()

        def handle_auth(self, params):
                "0:prove who you are"
        if not self.expecting_secret:
            self.boilerplate('unexpected-auth')
            return

        params = params.split()

        if len(params)!=2:
            self.boilerplate('no-nonce')
            return
        
        if len(params[1])!=32:
            self.boilerplate('short-nonce')
            return

        squished_userid = self.user.lower()[:16]
        while len(squished_userid)<16:
            squished_userid += '\0'

        fingerprint = hashlib.md5()
        fingerprint.update(binascii.unhexlify(params[1]))
        fingerprint.update(binascii.unhexlify(self.server_nonce))
        fingerprint.update(squished_userid)
        fingerprint.update(inverted_bitstring(binascii.unhexlify(self.expecting_secret)))

        if params[0].lower()==fingerprint.hexdigest():
            # yay, they're who we think they are
            response = hashlib.md5()
            response.update(binascii.unhexlify(self.server_nonce))
            response.update(binascii.unhexlify(params[1]))
            response.update(squished_userid)
            response.update(binascii.unhexlify(self.expecting_secret))

            # Grrr. WrenGROGGS only allows the server to respond
            # in uppercase here, in violation of the protocol. :(
            self.output(133, response.hexdigest().upper())

            self.access_level = self.potential_access_level
            self.boilerplate('authorised-' + auth_level(self.access_level))
        else:
            self.boilerplate('auth-failed')
            self.exit_program()

        def handle_alvl(self, params):
                "1:request different privs"
                self.not_implemented()

        def handle_motd(self, params):
                "0:request the message of the day"
        self.dump_file('motd')

        def handle_indx(self, params):
                "1:request a list of all available items"

        class IndexFilter:
            def __init__(self, left_margin, value):
                self.target = value
                self.start = left_margin

            def __call__(self, candidate):
                return int(candidate[self.start:self.start+8],16)>=self.target

        filter = None
        if params!='':
            # okay, we need some filter or other.
            try:
                if params[0]=='#':
                    filter = IndexFilter(0, int(params[1:], 16))
                else:
                    filter = IndexFilter(9, int(params, 16))
            except ValueError:
                self.boilerplate('indx-bad-arguments')
                return
                
        self.dump_file('index', filter, 1)

        def handle_item(self, params):
                "1:request one particular item"
        params = params.upper()
        if self.itemid_regexp.match(params):
            # OK, so it looks like an itemid...
            self.dump_file(params)
        else:
            self.boilerplate('unearthly-itemid')

        def handle_stat(self, params):
                "1:request the status of an item"
        params = params.upper()
        if self.itemid_regexp.match(params):
            filename = self.filename(params)
            if os.path.isfile(filename):
                self.output(211, open(filename).readline()[:-1])
            else:
                self.boilerplate('file-not-found')
        else:
            self.boilerplate('unearthly-itemid')

        def handle_data(self, params):
                "0:provide your name and some data, for a future command"

        self.boilerplate('data-please')
        sys.stdout.flush()
        self.grogname = readln()

        self.data = ''
        while 1:
            line = readln()
            if line=='.':
                break
            self.data += line + '\n'
            
        self.boilerplate('data-thank-you')

        def handle_newi(self, params):
                "2d:create a new item"

        sequence = self.new_sequence()
        itemid = self.new_itemid()
        filename = self.filename(itemid)
        subject = params
        timestamp = int(time.time())
        
        itemfile = open(filename, 'w')

        itemfile.write('%27s%08x %s\n%sSubject: %s\n\n%s\n' % (
            '',
            sequence,
            subject,
            self.item_header(sequence,
                     timestamp,
                     itemid),
            subject,
            self.data
            ))

        self.add_index_record(sequence,
                      timestamp,
                      itemid,
                      'I',
                      params)

        self.data = None
        self.continuing = None

        self.output(120, itemid)
        # FIXME: should be from boilerplate
        self.output(220, '%08x  %s' % (sequence,
                           'OK, posted'))

        def handle_repl(self, params):
                "2d:reply to an item"
        itemid = params.upper()
        sequence = self.new_sequence()
        filename = self.filename(itemid)
        timestamp = int(time.time())

        if not os.path.isfile(filename):
            self.boilerplate('file-not-found')
        elif os.path.getsize(filename) > int(self.conf('max-item-size')):
            self.boilerplate('item-full')
            self.continuing = itemid
        else:
            old = open(filename, 'r')
            baby = open(filename+'.new', 'w')

            temp = old.readline()
            subject = temp[36:-1]
            baby.write('%s%08x %s\n' % (
                temp[:27],
                sequence,
                subject))

            for line in old.xreadlines():
                baby.write(line)

            baby.write('%s\n%s\n' % (
                self.item_header(sequence, timestamp),
                self.data))

            self.graft(filename)

            self.add_index_record(sequence,
                          timestamp,
                          itemid,
                          'R',
                          subject)
            self.data = None
            self.continuing = None
            self.output(220, '%08x  OK, posted' % (sequence))

        def handle_cont(self, params):
                "2d:continue a full item"
        # This is pretty similar to newi; refactor.
        # (is it still? FIXME)

        if not self.continuing:
            self.boilerplate('unexpected-cont')
            return

        subject = params
        sequence = self.new_sequence()
        new_itemid = self.new_itemid()
        old_itemid = self.continuing
        old_filename = self.filename(old_itemid)
        new_filename = self.filename(new_itemid)
        timestamp = int(time.time())
        
        # Consider returning 423 if the title contains the old itemid.

        # First, create our new item.

        open(new_filename, 'w').write('%8s%19s%08x %s\n%sSubject: %s\n\n%s' % (
            old_itemid,
            '',
            sequence,
            subject,
            self.item_header(sequence,
                     timestamp,
                     new_itemid),
            subject,
            self.data))

        # Now we modify the old item to show it's been continued.

        old = open(old_filename, 'r')
        baby = open(old_filename+'.new', 'w')

        statline = old.readline()
        baby.write('%s%s%s' % (statline[:9], new_itemid, statline[17:]))

        # Everything else is the same for a bit...
        for line in old.xreadlines():
            baby.write(line)

        # Add the magic cookie for the continuation, and the human-readable
        # portion.

        baby.write('^%08x %08x\n[Item continued in %s by %s.]\n' % (
            sequence, timestamp, new_itemid, self.user))

        old.close()
        baby.close()

        # Swap it in.
        self.graft(old_filename)

        # Lastly, update the index.
        self.add_index_record(sequence, timestamp, new_itemid, 'C', subject)
        self.add_index_record(sequence, timestamp, old_itemid, 'F', subject)

        # Okay, we're all done!
        self.output(120, new_itemid)
        self.output(220, '%08x  OK, posted' % (sequence))

        self.data = None
        self.continuing = None

        def handle_edlk(self, params):
                "3:get a lock before editing"
                self.not_implemented()

        def handle_edul(self, params):
                "3e:relinquish the edit lock"
                self.not_implemented()

        def handle_edit(self, params):
                "3e:begin editing an item"
                self.not_implemented()

        def handle_edix(self, params):
                "3e:begin editing the index"
                self.not_implemented()

        def handle_edcf(self, params):
                "3e:confirm (finish) an edit"
                self.not_implemented()

        def handle_edab(self, params):
                "3e:abort an edit"
                self.not_implemented()

        def handle_mots(self, params):
                "3d:set the message of the day"
                self.not_implemented()

        def handle_elog(self, params):
                "1:list all administrative edits"
                self.not_implemented()

        def handle_diff(self, params):
                "3x:?"
                self.not_implemented()

        def handle_quit(self, params=None):
                "0:log out"
        self.boilerplate('goodbye')
        self.exit_program()

    def exit_program(self):
        sys.stdout.flush()
        self.flush_log()
        sys.exit()

        def handle_regu(self, params):
                "0:get yourself a new account"
        if self.user:
            self.boilerplate('unexpected-regu')
        elif self.creating_account:
            self.boilerplate('double-regu')
        else:
            self.boilerplate('regu-spiel-begin')
            for line in self.conf('registration-message').split('\n'):
                self.output_line(' '+line)
            self.output_line('Use the command USER <new id> to continue, or QUIT to quit.')
            self.end_output()

            self.creating_account = 1

        def handle_udbm(self, params):
            "3:database maintenance"
            self.not_implemented()

        def handle_noop(self, params):
            "0:does nothing"
            self.boilerplate('noop')

        def handle_xyzz(self, params):
            "0x:magic word"
            self.boilerplate('xyzzy')

        def handle_help(self, params):
            "0:list all the commands"

            self.boilerplate('help-spiel-begin')
            methods = self.__class__.__dict__.keys()
            methods.sort()
            for method in methods:
                if method.startswith('handle_'):
                    docstring = self.__class__.__dict__[method].__doc__

                    if int(docstring[0]) > self.access_level:
                        continue
                
                    colon = docstring.index(':')
                    flags = docstring[1:colon]

                    if 'x' in flags:
                        continue
                    if 'd' in flags:
                        docstring += ' (needs some DATA)'
                    if 'e' in flags:
                        docstring += ' (needs the edit lock)'
                
                    self.output_line('%s - %s' % (
                        method[7:].upper(),
                        docstring[colon+1:]))

            self.end_output()

    def not_implemented(self):
        self.boilerplate('not-implemented')

    def new_sequence(self):
        "Returns a new sequence number."

        # FIXME: need contention control

        result = 0
        filename = self.filename('sequence')
        if (os.path.isfile(filename)):
            # good, we already have a number
            result = int(open(filename).readline(),16)

        # Now, the slightly trickier part:
        # write the number back for the next time.

        open(filename, 'w').write('%08x' % (result+1))

        return result
        
    def new_itemid(self):
        "Returns a GROGGS-style itemid."

        # We may as well use the GROGGS year-lettering system,
        # rather than starting again at A. GROGGS's "A" year was 1985.
        #
        # Note that the spec says that the form of an itemid is:
        #         one letter indicating the year followed by
        #         3 digits for the day and 4 for the time
        #
        # but it's not explained how those digits map to the day or time,
        # so they're necessarily opaque! Given this, we just use the last
        # seven digits of the Unix timestamp to end itemids with. (The spec
        # also says that the letter indicates the year, without saying how
        # it maps to real years; but since the mapping of GROGGS year letters
        # to years is generally recognised by users, we keep to the same
        # system.)
        #
        # UPDATE: Inspection of itemids produced by IWJ's system indicates
        # that the format is Ydddhhmm, where Y is a year letter as above,
        # ddd is the number of days through the year, and hhmm is the time
        # in the 24h clock. This seems a lot of extra work to implement,
        # particularly since it's not obvious until you've read a lot of
        # itemids how it works. I think that, until I find a reason to
        # do otherwise, the numeric part of our itemids will be random.
        # I'm reserving itemids with a 9 in the second place for magic uses,
        # should such a need ever arise.

        while 1:
            result = '%c%07d' % (
                65+(time.gmtime()[0]-1985)%26,
                random.randrange(0,9000000))

            if not os.path.isfile(self.filename(result)):
                return result

    def item_header(self, sequence, timestamp, itemid=None):
        result = '^%08x %08x\n' % (sequence, timestamp)
        date = self.neat_date(timestamp)

        if itemid:
            result += 'Item ' + itemid
        else:
            result += 'Reply'

        result += ' from '

        # There are two equivalent forms we can use here.
        # The choice between them depends on the potential
        # length of the first line.
        
        if len(self.user+self.grogname)>52:
            result += '%s %s\nFrom %s\n' % (
                self.user,
                date,
                self.grogname)
        else:
            result += '%s (%s) %s\n' % (
                self.grogname,
                self.user,
                date)

        return result

    def neat_date(self, timestamp):
        "Returns a date formatted in the traditional GROGGS style."
        return time.strftime('at %H:%M on %a %e %b',
                     time.localtime(timestamp));

    def add_index_record(self, sequence, timestamp,
                 itemid, typecode, subject):
        "Adds a new record to the index."

        # Trim everything down to size
        userid = self.user[:75]

        if len(subject)>94:
            subject = subject[:90]+'...'

        record = '%08x %08x %8s %-75s %s %s' % (
            sequence, timestamp,
            itemid, userid,
            typecode, subject)

        index = open(self.filename('index'), 'a')
        index.write('%-199s\n' % (record))

    def graft(self, filename):
        "Copies the file named |filename|.new over the file |filename|."
        os.rename(filename+'.new', filename)

    def conf(self, field):
        return self.config.get('main', field)

    def confbool(self, field):
        return self.config.getboolean('main', field)

    def filename(self, name):
        return os.path.join(self.directory, name)

    def dump_file(self, name, filter=None, fakeIfMissing=0):
        name = self.filename(name)

        if os.path.isfile(name):
            self.boilerplate('generic-spiel-begin')
            blob(name).spew_into(self, filter)
            self.end_output()
        else:
            if fakeIfMissing:
                self.boilerplate('generic-spiel-begin')
                self.end_output()
            else:
                self.boilerplate('file-not-found')

################################################################

def calling_host():
    name = '(stdin)'
    try:
        name = socket.fromfd(sys.stdin.fileno(),
                     socket.AF_INET,
                     socket.SOCK_STREAM).getpeername()[0]
    except socket.error:
        pass # presumably it's being run from console
    return name

###############################################################

def main():

    config = configparser.ConfigParser()

    try:
        vaultname = None
        
        config.read(basic_config_filename)

        # Don't expect (most of) the switches to do anything yet.
        options, arguments = getopt.getopt(sys.argv[1:], '',
                           ['help',
                            'vault=',
                            'user=',
                            'list',
                            'create',
                            'destroy',
                            'set=',
                            'no-logging',
                            ])

        if arguments!=[]:
            raise "Useless extra stuff on command line " + str(arguments)

        for option, value in options:
            if option=='--help':
                print('%s: no help yet. maybe next time.' % (sys.argv[0]))
                sys.exit()
            elif option=='--vault':
                if value.find('.')!=-1 or value.find('/')!=-1:
                    raise 'illegal characters in vault name'
                vaultname = value
            elif option=='--no-logging':
                config.set('main', 'logging', '0')
            else:
                raise 'known but unhandled option: '+option

        if not vaultname:
            # before now, we might have needed to know when no vault
            # had been specified. but by now, we really need a name,
            # so pick the default
            vaultname = 'default'

        if not os.path.isdir(os.path.join(config.get('main', 'vault-dir'),
                          vaultname)):
            
            # You have to have the directory; even thouhg it doesn't have
            # have anything in it, it must _exist_.
            
            raise 'vault "%s" does not exist' % (vaultname)

        config.read(os.path.join(config.get('main', 'vault-dir'),
                     vaultname,
                     'config'))
        
        connection(config, vaultname).discuss()

    except:
        problem = sys.exc_info()
        if problem[0]!=SystemExit:
            # hmm. make an rgtp fatal error out of it.

            errormessage=problem[1]
            if errormessage==None:
                errormessage=problem[0]
            errormessage = str(errormessage).replace('\n', ' -- ')
            sys.stdout.write('484 %s\r\n' % (errormessage))

            if config.has_option('main', 'tracebacks') and config.getboolean('main', 'tracebacks'):
                trace = '250 Details follow (set tracebacks=0 to turn this off)\r\n'
                for line in traceback.format_tb(problem[2]):
                    trace += ' '+line.replace('\n','\r\n ')

                sys.stdout.write(trace+'\r\n.\r\n')

if __name__=='__main__':
    main()

