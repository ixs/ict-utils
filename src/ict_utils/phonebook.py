#!/usr/bin/env python3

# Basic functionality to interact with an Elmeg ICT PBX phonebook.
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

import csv
import optparse

from . import ict_communication


def parse_cmdline():
    parser = optparse.OptionParser()

    usage = "usage: %prog [options] <upload|download|erase|print> filename"
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
        "-l", "--local", dest="prefix", default=0, help="Local prefix for your PBX"
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

    if not args or args[0].lower() not in ("upload", "download", "print", "erase"):
        parser.error("Specify a valid action")
    action = args[0].lower()
    if len(args) != (2 if action in ("upload", "download") else 1):
        parser.error("Upload and download require a filename; other actions take none")
    file = args[1] if len(args) == 2 else None
    return (opts, action, file)


def pretty_print(ict):
    print(f"Local prefix: {ict.get_local_prefix()}")
    num_entries = ict.get_count_entries()
    print(f"Phonebook entries: {num_entries:d}")
    print()
    print(
        "No. Name                   Phone number              Speed dial index     Trunk groups    Call Trough  MSN"
    )
    print("=" * 107)
    for i in range(num_entries):
        e = ict.get_entry(i)
        if e["shortdial"] == -1:
            e["shortdial"] = "No speed dial index"
        else:
            e["shortdial"] = str("{:03d}".format(e["shortdial"]))

        if e["bundle"] == -1:
            e["bundle"] = "no trunk group"
        else:
            e["bundle"] = str("{:02d}".format(e["bundle"]))

        if e["callthrough"] == 1:
            e["callthrough"] = "Yes"
        else:
            e["callthrough"] = "No"

        print(
            "{:03d}  {:<20}  {:<24}  {:<19}  {:<14}  {:<11}  {:<4}".format(
                e["id"],
                e["name"],
                e["number"],
                e["shortdial"],
                e["bundle"],
                e["callthrough"],
                e["msn"],
            )
        )


def erase(ict):
    ict.set_count_entries(0)
    print("Phonebook deleted")


def csv_export(ict, file):
    with open(file, "w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            ("name", "number", "shortdial", "bundle", "callthrough", "msn"),
            extrasaction="ignore",
        )
        writer.writeheader()
        for i in range(ict.get_count_entries()):
            writer.writerow(ict.get_entry(i))
    print(f"Phonebook written to {file}")


def csv_import(ict, file, prefix):
    with open(file, encoding="utf-8", newline="") as stream:
        entries = list(csv.DictReader(stream))
    # Validate and encode every row before changing the PBX.
    prepared = []
    for entry in sorted(entries, key=lambda entry: entry["name"].lower()):
        for field in ("name", "number", "msn"):
            entry[field].encode("latin-1")
        prepared.append(
            (
                entry["name"],
                entry["number"],
                int(entry["shortdial"]),
                int(entry["bundle"]),
                int(entry["callthrough"]),
                entry["msn"],
            )
        )
    ict.set_count_entries(len(prepared))
    ict.set_local_prefix(prefix)
    for i, entry in enumerate(prepared):
        ict.set_entry(i, *entry)
    ict.commit_phonebook()
    print(f"Phonebook uploaded from {file}")


def main():
    (opts, action, file) = parse_cmdline()

    ict = ict_communication.ICT_PhonebookComm(opts.host, opts.user, opts.password)
    ict.debug = opts.debug
    ict.connect()
    ict.init()
    ict.login()

    if action == "print":
        pretty_print(ict)
    elif action == "erase":
        erase(ict)
    elif action == "download":
        assert file is not None
        csv_export(ict, file)
    elif action == "upload":
        assert file is not None
        csv_import(ict, file, opts.prefix)

    ict.logout()
    ict.disconnect()


if __name__ == "__main__":
    main()
