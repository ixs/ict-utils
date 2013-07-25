#!/usr/bin/python

import ict_communication
import optparse
import csv
import pprint

def unicode_csv_reader(unicode_csv_data, dialect=csv.excel, **kwargs):
    # csv.py doesn't do Unicode; encode temporarily as UTF-8:
    csv_reader = csv.reader(utf_8_encoder(unicode_csv_data),
                            dialect=dialect, **kwargs)
    for row in csv_reader:
        # decode UTF-8 back to Unicode, cell by cell:
        yield [unicode(cell, 'utf-8') for cell in row]

def utf_8_encoder(unicode_csv_data):
    for line in unicode_csv_data:
        yield line.encode('utf-8')


def parse_cmdline():
    parser = optparse.OptionParser()

    usage = "usage: %prog [options] <upload|download|print> filename"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-i', '--ip', default = "192.168.1.250", dest = "host", help = 'PBX IP address (Default: 192.168.1.250)')
    parser.add_option('-u', '--username', dest = "user", default = "Service", help = 'Username (Default: Service)')
    parser.add_option('-p', '--password', dest = "pass", default = "Service", help = 'Password (Default: Service)')
    parser.add_option('-l', '--local', dest = "prefix", default = 0, help = 'Local prefix for your PBX')
    parser.add_option('-d', '--debug', dest = "debug", action = "store_true", default = False, help = 'Debug. Dump every packet.')
    # parser.add_option('-a', '--action', dest = "action", choices = ("upload", "download"), help = 'Action to take')
    (opts, args) = parser.parse_args()

    if len(args) == 0:
        parser.error("Invalid arguments. Need action specification..")

    if len(args) > 0 and args[0].lower() not in ("upload", "download", "print"):
        parser.error("Invalid action specified. Must bei either upload, download, erase or print.")

    if len(args) !=2 and args[0] not in ("erase", "print"):
        parser.error("Invalid arguments. Upload and download action need a filename.")

    return (opts, args)


def pretty_print(ict):
    print "Local prefix: %s" % ict.get_local_prefix()
    num_entries = ict.get_count_entries()
    print "Phonebook entries: %i" % num_entries
    print 
    print "No. Name                   Phone number              Speed dial index     Trunk groups    Call Trough  MSN"
    print "=" * 107
    for i in range(0, num_entries):
        e = ict.get_entry(i)
        if e['shortdial'] == -1:
            e['shortdial'] = "No speed dial index"
        else: 
            e['shortdial'] = str("%03i" % e['shortdial'])

        if e['bundle'] == -1:
            e['bundle'] = "no trunk group"
        else: 
            e['bundle'] = str("%02i" % e['bundle'])

        if e['callthrough'] == 1:
            e['callthrough'] = "Yes"
        else: 
            e['callthrough'] = "No"


        print "%03i  %-20s  %-24s  %-19s  %-14s  %-11s  %-4s" % (e['id'], e['name'], e['number'], e['shortdial'], e['bundle'], e['callthrough'], e['msn'])


def erase(ict):
    ict.set_count_entries(0)
    print "Phonebook deleted"

def csv_export(ict, file):
    # csv.py doesn't do Unicode; encode temporarily as UTF-8:
#        csv_writer = csv.DictWriter(utf_8_encoder(file),
#                            ("Name", "Number", "Speed dial", "Trunk Group", "Call Through", "MSN"),
#                            dialect=csv.excel)
#        for row in csv_reader:
#            # decode UTF-8 back to Unicode, cell by cell:
#            yield [unicode(cell, 'utf-8') for cell in row]
 
    csv_writer = csv.DictWriter(open(file, "w"), ("name", "number", "shortdial", "bundle", "callthrough", "msn"), extrasaction="ignore")
    csv_writer.writeheader()
    num_entries = ict.get_count_entries()
    for i in range(0, num_entries):
        e = ict.get_entry(i)
        csv_writer.writerow(e)
    print "Phonebook written to %s" % file

def csv_import(ict, file, prefix):
    csv_reader = csv.DictReader(open(file, "r"), ("name", "number", "shortdial", "bundle", "callthrough", "msn"))
    entries = list()
    for row in csv_reader:
        entries.append(row)

    ict.set_count_entries(len(entries) - 1)
    ict.set_local_prefix(prefix)

    i = 0
    for e in sorted(entries[1:], key=lambda entry: str(entry["name"]).lower()):
        ict.set_entry(i, e["name"], e["number"], int(e["shortdial"]), int(e["bundle"]), int(e["callthrough"]), e["msn"])
        i += 1
    ict.commit_phonebook()
    print "Phonebook uploaded from %s" % file


def main():
    (opts, args) = parse_cmdline()
    if len(args) == 2:
        (action, file) = args
    elif len(args) == 1:
        action = args[0]
    else:
        raise RuntimeError()
    ict = ict_communication.ICT_PhonebookComm(opts.host)
    ict.debug = opts.debug
    ict.connect()
    ict.init()
    ict.login()
    
    if action == "print":
        pretty_print(ict)
    elif action == "download":
        csv_export(ict, file)
    elif action == "upload":
        csv_import(ict, file, opts.prefix)

    ict.logout()
    ict.disconnect()


if __name__ == '__main__':
    main()
