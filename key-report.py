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

COMMANDS = { "list-keys": "gpg --list-keys --fixed-list-mode --with-colons" }
TRUSTWORTHY_STATES = ("expired", "unknown", "undefined", "marginal", "full",
                      "ultimate", )

def read_pgp():
    """Get list of keys from gpg."""

    listkeys = subprocess.Popen(COMMANDS["list-keys"].split(),
                                stdout=subprocess.PIPE)

    solution = listkeys.communicate()

    return solution

def sort_keys(output):
    """Parse gpg lines."""

    valid = DefaultDict(list)
    invalid = DefaultDict(list)
    unknown = DefaultDict(list)
    today = date.today()

    for line in output.splitlines():
        # process lines that start with "pub" or "sub"
        if not True in map(line.startswith, ("pub", "sub")):
            continue

        key, status, created, expires = parse(line)

        if status in TRUSTWORTHY_STATES:
            valid[expires].append(key)
        else:
            invalid[expires].append(key)

    return valid, invalid, unknown

def parse(line):
    """Split PGP lines: returns key ID, status, creation date, and expiration.

    >>> parse("pub:f:4096:1:0000000000000001:0:86400::q:::scESC:")
    ('0000000000000001', 'full', datetime.date(1969, 12, 31), datetime.date(1970, 1, 1))

    """
    key = line.split(":")[4]
    created = date.fromtimestamp(float(line.split(":")[5]))
    try:
        expires = date.fromtimestamp(float(line.split(":")[6]))
    except ValueError:
        expires = date.max

    try:
        status = { "o" : "unknown",
                   "i" : "invalid",
                   "r" : "revoked",
                   "e" : "expired",
                   "-" : "unknown",
                   "q" : "undefined",
                   "n" : "untrusted",
                   "m" : "marginal",
                   "f" : "full",
                   "u" : "ultimate",
            }[line.split(":")[1]]
    except KeyError:
        status = "unknown"

    return (key, status, created, expires)

def display_keys_dates(keys, status, critical, warning):
    """Displays valid keys and when they expire."""
    
    today = date.today()

    for adate, keys in sorted(keys.iteritems()):

        if adate <= today:
            date_goodness = "error"
        elif adate - timedelta(days=critical) <= today:
            date_goodness = "critical"
        elif adate - timedelta(days=warning) <= today:
            date_goodness = "warning"
        else:
            date_goodness = "valid"
        
        for key in keys:
            print date_goodness, status, key, adate

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

    print(draft.format(from_, to, to_name, expire_days,
                       key_id, expire_date, from_name))

def show_expiry(critical, warning):
    """Show expiry data."""

    data = read_pgp()

    valid, invalid, unknown = sort_keys(data[0])

    print "Status", "Trustworthiness", "ID", "Expires"

    for keys, status in ((valid, "valid"),
                         (invalid, "invalid"),
                         (unknown, "unknown")):
        display_keys_dates(keys, status, critical, warning)

    draft_emails(valid, critical, warning)

def test(*args, **kwargs):
    import doctest
    doctest.testmod()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Display key details.")

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
        show_expiry(args.critical, args.warning)
