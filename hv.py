#!/usr/bin/env python3

import os
import json
import subprocess
import email.utils
import click
import requests


def is_valid_fingerprint(fingerprint):
    """
    Verifies that the fingerprint is a valid, 40 digit hex number
    """
    if len(fingerprint) != 40:
        return False
    allowed = '0123456789ABCDEF'
    for c in fingerprint.upper():
        if c not in allowed:
            return False
    return True


def get_emails(fingerprint):
    """
    Query gpg keyring for this key, and return a list of emails extracted from UIDs
    """
    out = subprocess.check_output(['gpg2', '--batch', '--no-tty', '--with-colons', '--list-keys', fingerprint])
    addrs = []
    for line in out.decode().split('\n'):
        if line.startswith('uid:'):
            uid = line.split(':')[9]
            addr = email.utils.parseaddr(uid)[1]
            if '@' not in addr:
                addr = uid
            addrs.append(addr)
    return addrs


@click.command()
@click.argument('keylist_filename')
def main(keylist_filename):
    # Verify that keylist_filename is a valid keylist
    if not os.path.exists(keylist_filename):
        click.echo('Invalid keylist_filename')
        return
    try:
        with open(keylist_filename) as f:
            keylist = json.load(f)
    except:
        click.echo('Not a valid JSON file')
        return
    invalid = False
    if 'keys' not in keylist:
        invalid = True
    else:
        if type(keylist['keys']) != list:
            invalid = True
    if invalid:
        click.echo('Not a valid keylist')
        return
    
    # Make a dictionary of fingerprints to UIDs, by querying your gpg keyring
    emails = {}
    for key in keylist['keys']:
        fingerprint = key['fingerprint']
        if not is_valid_fingerprint(fingerprint):
            click.echo('Skipping invalid fingerprint: {}'.format(fingerprint))
        else:
            emails[fingerprint] = get_emails(fingerprint)


if __name__ == '__main__':
    main()