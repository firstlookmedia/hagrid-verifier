#!/usr/bin/env python3

import os
import json
import subprocess
import click
import requests


def is_valid_fingerprint(fingerprint):
    """
    Verifies that the fingerprint is a valid, 40 digit hex number
    """
    if len(fingerprint) != 40:
        return False
    allowed = "0123456789ABCDEF"
    for c in fingerprint.upper():
        if c not in allowed:
            return False
    return True


def get_pubkey(fingerprint):
    """
    Query the gpg keyring and returns an ASCII armored public key
    """
    out = subprocess.check_output(["gpg2", "--armor", "--export", fingerprint])
    return out.decode()


@click.command()
@click.argument("keylist_filename")
def main(keylist_filename):
    api_endpoint = "https://keys.openpgp.org/vks/v1"

    # Verify that keylist_filename is a valid keylist
    if not os.path.exists(keylist_filename):
        click.echo("Invalid keylist_filename")
        return
    try:
        with open(keylist_filename) as f:
            keylist = json.load(f)
    except:
        click.echo("Not a valid JSON file")
        return
    invalid = False
    if "keys" not in keylist:
        invalid = True
    else:
        if type(keylist["keys"]) != list:
            invalid = True
    if invalid:
        click.echo("Not a valid keylist")
        return

    # Make a dictionary mapping fingerprints to emails and ASCII-armored pubkeys, by querying your gpg keyring
    keys = {}
    for key in keylist["keys"]:
        fingerprint = key["fingerprint"]
        if not is_valid_fingerprint(fingerprint):
            click.echo("Skipping invalid fingerprint: {}".format(fingerprint))
        else:
            keys[fingerprint] = {"pubkey": get_pubkey(fingerprint)}

    # Upload each key to the keyserver
    for fingerprint in keys:
        if keys[fingerprint]["pubkey"] != "":
            click.echo("uploading {}".format(fingerprint))

            # Upload the pubkey
            r = requests.post(
                "{}/upload".format(api_endpoint),
                json={"keytext": keys[fingerprint]["pubkey"]},
            )
            response = r.json()

            # Add the token and status to keys dict
            try:
                keys[fingerprint]["token"] = response["token"]
                keys[fingerprint]["status"] = response["status"]
            except KeyError:
                print("KeyError ({}): {}".format(fingerprint, response))

    click.echo()

    # Loop through each key, displaying the verification status
    needs_verification_statuses = ["unpublished", "pending"]
    for fingerprint in keys:
        if keys[fingerprint]["pubkey"] == "":
            click.echo(f"{fingerprint} not found in local keyring, skipping")

        addresses = []
        if "status" in keys[fingerprint]:
            for address in keys[fingerprint]["status"]:
                if keys[fingerprint]["status"][address] in needs_verification_statuses:
                    addresses.append(address)

            keys[fingerprint]["addresses"] = addresses

        if len(addresses) > 0:
            click.echo(f"{fingerprint} needs verification: {addresses}")

    click.echo()

    if click.confirm(
        "Do you want to request verification emails for all of these keys?"
    ):
        for fingerprint in keys:
            if len(keys[fingerprint]["addresses"]) > 0:
                click.echo(
                    "requesting verification for {}".format(
                        keys[fingerprint]["addresses"]
                    )
                )

                # Request verification
                r = requests.post(
                    "{}/request-verify".format(api_endpoint),
                    json={
                        "token": keys[fingerprint]["token"],
                        "addresses": keys[fingerprint]["addresses"],
                    },
                )

                # Gracefully handle errors
                if r.status_code != 200:
                    click.echo("status_code: {}".format(r.status_code))

                response = r.json()
                if "error" in response:
                    click.echo("Error: {}".format(response["error"]))


if __name__ == "__main__":
    main()
