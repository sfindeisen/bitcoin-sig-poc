#!/usr/bin/env python3

import argparse

import ecdsa

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        add_help=True, allow_abbrev=False, epilog="""This program comes with ABSOLUTELY NO WARRANTY.""")

    parser.add_argument("--addr",    required=True, help="Bitcoin address")
    parser.add_argument("--message", required=True, help="Message (ASCII)")
    parser.add_argument("--sig",     required=True, help="signature (base64 encoded)")
    args = parser.parse_args()
