#!/usr/bin/env python3

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

import optparse

from . import ict_communication


def parse_cmdline():
    parser = optparse.OptionParser()

    usage = "usage: %prog [options] <upload|download|erase> filename"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option(
        "-i",
        "--ip",
        default="192.168.1.250",
        dest="host",
        help="PBX IP address (Default: 192.168.1.250)",
    )
    parser.add_option(
        "-u",
        "--username",
        dest="user",
        default="Service",
        help="Username (Default: Service)",
    )
    parser.add_option(
        "-p",
        "--password",
        dest="password",
        default="Service",
        help="Password (Default: Service)",
    )
    parser.add_option(
        "-d",
        "--debug",
        dest="debug",
        action="store_true",
        default=False,
        help="Debug. Dump every packet.",
    )
    (opts, args) = parser.parse_args()

    if not args or args[0].lower() not in ("upload", "download", "erase"):
        parser.error("Specify a valid action")
    action = args[0].lower()
    if len(args) != (2 if action in ("upload", "download") else 1):
        parser.error("Upload and download require a filename; other actions take none")
    file = args[1] if len(args) == 2 else None
    return (opts, action, file)


def erase(ict):
    ict.erase_lcr()
    print("LCR Table deleted")


def download(ict, file):
    data = ict.get_lcr()
    if data is False:
        raise RuntimeError("No LCR table available on the PBX")
    with open(file, "wb") as stream:
        stream.write(data)
    print(f"LCR Table downloaded to {file}")


def upload(ict, file):
    with open(file, "rb") as stream:
        if not ict.put_lcr(stream.read()):
            raise RuntimeError("PBX refused the LCR upload")
    print(f"LCR Table uploaded from {file}")


def main():
    (opts, action, file) = parse_cmdline()

    ict = ict_communication.ICT_Comm(opts.host, opts.user, opts.password)
    ict.debug = opts.debug
    ict.connect()
    ict.init()
    ict.login()

    if action == "erase":
        erase(ict)
    elif action == "upload":
        assert file is not None
        upload(ict, file)
    elif action == "download":
        assert file is not None
        download(ict, file)

    ict.logout()
    ict.disconnect()


if __name__ == "__main__":
    main()
