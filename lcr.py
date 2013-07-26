#!/usr/bin/python

# Basic functionality to interact with an Elmeg ICT PBX Least Coast Router.
#
#    Copyright (C) 2013  Andreas Thienemann <andreas@bawue.net>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the version 2 of the GNU General Public License
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#

import ict_communication
import optparse
import csv
import pprint


def parse_cmdline():
    parser = optparse.OptionParser()

    usage = "usage: %prog [options] <upload|download|erase> filename"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-i', '--ip', default = "192.168.1.250", dest = "host", help = 'PBX IP address (Default: 192.168.1.250)')
    parser.add_option('-u', '--username', dest = "user", default = "Service", help = 'Username (Default: Service)')
    parser.add_option('-p', '--password', dest = "pass", default = "Service", help = 'Password (Default: Service)')
    parser.add_option('-d', '--debug', dest = "debug", action = "store_true", default = False, help = 'Debug. Dump every packet.')
    (opts, args) = parser.parse_args()

    if len(args) == 0:
        parser.error("Invalid arguments. Need action specification..")

    if len(args) > 0 and args[0].lower() not in ("upload", "download", "erase"):
        parser.error("Invalid action specified. Must bei either upload, download or erase")

    if len(args) !=2 and args[0] not in ("erase"):
        parser.error("Invalid arguments. Upload and download action need a filename.")

    if len(args) == 2:
        (action, file) = args
    elif len(args) == 1:
        action = args[0]
        file = None
    else:
        pass
    return (opts, action, file)


def erase(ict):
    ict.erase_lcr()
    print "LCR Table deleted"

def download(ict, file):
    f = open(file, "w")
    f.write(ict.get_lcr())
    f.close()
    print "LCR Table downloaded to %s" % file

def upload(ict, file):
    f = open(file, "r")
    ict.put_lcr(f.read())
    f.close()
    print "LCR Table uploaded from %s" % file

def main():
    (opts, action, file) = parse_cmdline()

    ict = ict_communication.ICT_PhonebookComm(opts.host)
    ict.debug = opts.debug
    ict.connect()
    ict.init()
    ict.login()
    
    if action == "erase":
        erase(ict)
    elif action == "upload":
        upload(ict, file)
    elif action == "download":
        download(ict, file)

    ict.logout()
    ict.disconnect()


if __name__ == '__main__':
    main()
