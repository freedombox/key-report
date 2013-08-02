#! /usr/bin/env python
# -*- mode: python; mode: auto-fill; fill-column: 80 -*-

"""Key Report is a tool to report on when PGP keys expire.

Displays details about your keyring:

- Displays keys that have expired (error).
- Displays keys that are nearly expired (critical).
- Displays keys that are will expire soon (warning).
- Displays keys that are valid.
- Displays keys that never expire.
- Displays keys that have been revoked.

FIXME: 82: Localize date format if necessary.
TODO: 135: Write draft emails to files.

Copyright (C) 2013  Nick Daly <nick.m.daly@gmail.com>

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along
with this program.  If not, see <http://www.gnu.org/licenses/>.

"""

import argparse
from datetime import date, timedelta
from collections import defaultdict as DefaultDict
import subprocess

def read_pgp():
    """Get list of keys from gpg."""

    listkeys = subprocess.Popen(
        "gpg --list-keys".split(), stdout=subprocess.PIPE)

    solution = listkeys.communicate()

    return solution

def sort_keys(output):
    """Parse gpg lines."""

    valid = DefaultDict(list)
    revoked = DefaultDict(list)
    indefinite = list()
    today = date.today()

    for line in output.splitlines():
        if not line.startswith("pub"):
            continue

        key, status, created, expires = parse(line)

        if expires <= today:
            status = "revoked"
        elif created >= expires:
            status = "revoked"
            
        if ("expires" or "expired") in status:
            valid[expires].append(key)

        elif status == "revoked":
            revoked[expires].append(key)

        elif status == "indefinite":
            indefinite.append(key)

    return valid, indefinite, revoked

def parse(line):
    """Split PGP lines.

    FIXME: assumes date format is always bigendian.
    
    >>> parse("pub   4096R/00000000 2013-07-31 [expires: 2013-08-01]")
    ('00000000', 'expires', datetime.date(2013, 7, 31), datetime.date(2013, 8, 1))

    """
    key = line.split("/")[1].split(" ")[0]
    created = date(*[int(x) for x in line.split("/")[1].split(" ")[1].split("-")])

    try:
        status = line.split("[")[1].split(":")[0]
    except IndexError:
        status = "indefinite"

    try:
        expires = date(*[int(x) for x in line.split("[")[1].split(" ")[1][:-1].split("-")])
    except IndexError:
        expires = date.max

    return (key, status, created, expires)

def display_valid_keys(keys, critical, warning):
    """Displays valid keys and when they expire."""
    
    today = date.today()

    for adate, keys in sorted(keys.iteritems()):

        if adate <= today:
            status = "error"
        elif adate - timedelta(days=critical) <= today:
            status = "critical"
        elif adate - timedelta(days=warning) <= today:
            status = "warning"
        else:
            status = "valid"
        
        for key in keys:
            print status, key, adate

def display_indefinite_keys(keys):
    """Display data about keys that never expire."""

    for key in keys:
        print "indefinite", key, ""

def display_revoked_keys(keys):
    """Displays revoked keys and the day they were revoked."""

    for adate, keys in sorted(keys.iteritems()):
        for key in keys:
            print "revoked", key, adate

def draft_emails(keys, critical, warning):
    """Write out email drafts for folks to inform them of their expiration.

    TODO Finish this some day.

    """

    return

    draft = """\
From: {0}
To: {1}
Subject: PGP Key Expiring

<#secure method=pgpmime mode=signencrypt>
Hi {2}, I just wanted to let you know that your PGP key is going to
expire within the next {3} days:

{4} {5}

You should publish another key (with a transitional signing statement)
or extend your current key's expiration date (if your key hasn't been
compromised).

Thanks for your time,
{6}
"""

    print(draft.format(from, to, to_name, expire_days,
                       key_id, expire_date, from_name))

def main(critical, warning):
    """Show key status."""

    data = read_pgp()

    valid, indefinite, revoked = sort_keys(data[0])

    print "Status", "ID", "Date"

    display_valid_keys(valid, critical, warning)
    display_indefinite_keys(indefinite)
    display_revoked_keys(revoked)

    draft_emails(valid, critical, warning)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Display the expirations of known keys.")

    parser.add_argument("--warning", default=90, type=int,
                        help="Number of days before expiration to warn user.")
    parser.add_argument("--critical", default=30, type=int,
                        help="Number of days before expiration to freak out.")
    parser.add_argument("--test", action="store_const", const=True,
                        help="Run tests.")

    args = parser.parse_args()

    if args.test:
        import doctest
        doctest.testmod()
    else:
        main(args.critical, args.warning)
