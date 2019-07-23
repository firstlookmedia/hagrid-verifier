#!/usr/bin/env python3

import click
import requests

@click.command()
@click.argument('keylist_filename')
def main(keylist_filename):
    pass


if __name__ == '__main__':
    main()