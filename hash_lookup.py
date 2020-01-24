#! /usr/bin/env python3

"""

Umbrella hash lookup - 2020, Nien Huei Chang

hash_lookup.py - main program

"""

import re
import sys
import select
import requests
import argparse


UMBRELLA_TOKEN_FILENAME = "umbrella_token.txt"
UMBRELLA_URL = "https://investigate.api.umbrella.com"


def load_umbrella_token():
    """ Load umbrella token from text file. """

    try:
        with open(UMBRELLA_TOKEN_FILENAME, "r") as umbrella_token_file:
            return umbrella_token_file.readline().strip()

    except (IOError):
        print(f"\nError: Unable to read token from '{UMBRELLA_TOKEN_FILENAME}'...\n", file=sys.stderr)
        sys.exit(1)


def load_hash_samples(hash_filename):
    """ Load hash(es) from text file containing one hash per line. """

    try:
        with open(hash_filename, "r") as hash_file:
            return hash_file.readlines()

    except (IOError):
        print(f"\nError: Unable to read data from '{hash_filename}'...\n", file=sys.stderr)
        sys.exit(2)


def collect_hash_samples():
    """ Ask user to manually provide each of the hashes. """

    print("\nUmbrella Hash Lookup - 2020, Nien Huei Chang")
    print("Type 'hash_lookup.py --help' to see all available options")

    hash_samples = []

    print()

    while True:
        hash_sample = input("Enter SHA256/SHA1/MD5 hash sample (empty to cancel): ").strip().lower()

        if hash_sample == "":
            break

        if not validate_hash_format(hash_sample):
            print("Incorrect hash format...")
            continue

        hash_samples.append(hash_sample)

    print()

    return hash_samples


def validate_hash_format(hash_sample):
    """ Check if given string is made up from 32 (md5), 40 (sha1), 64 (sha256) hex characters. """

    return re.search(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", hash_sample)


def query_umbrella(hash_samples, print_unknown=False, minimum_score=0):
    """ Querry umbrella and print data retrieved from it. """

    umbrella_headers = {
        "accept": "application/json",
        "Authorization": "Bearer " + load_umbrella_token(),
    }

    print()

    for hash_sample in hash_samples:

        try:
            response = requests.get(f"{UMBRELLA_URL}/sample/{hash_sample}", headers=umbrella_headers)

        except requests.exceptions.ConnectionError:
            print(f"Error: Unable to connect to Umbrella service using '{UMBRELLA_URL}' url...\n", file=sys.stderr)
            sys.exit(3)

        if response.status_code != 200:
            print(f"Error: Received not OK status code '{response.status_code}' from Umbrella service...\n", file=sys.stderr)
            sys.exit(4)

        if "application/json" not in response.headers.get("Content-Type"):
            print(f"Error: Received not json formatted content '{response.headers.get('Content-Type')}' from Umbrella service...\n", file=sys.stderr)
            sys.exit(5)

        if not print_unknown and "Could not find sample for" in response.json().get("error", ""):
            continue

        if int(response.json().get("threatScore", "0")) < minimum_score:
            continue

        key_list = {"sha256", "sha1", "md5", "magicType", "size", "threatScore", "error"}

        max_key_len = len(max(key_list, key=len))

        for key, value in response.json().items():
            if key in key_list:
                print(f"[ {key:{max_key_len}} ]  {value}")

        print()


def parse_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser()

    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument("-u", "--print-unknown", action="store_true", help="print error message for hashes that are not found in Umbrella")
    filter_group.add_argument("-m", "--minimum-score", action="store", type=int, default=0, help="print only results with scores equal or higher than the provided number")

    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("-f", "--filename", action="store", help="read hash samples from file")
    input_group.add_argument("-s", "--hash-sample", action="store", nargs="+", help="provide hash samples in command line")
    input_group.add_argument("-i", "--force-stdin", action="store_true", help="force to read hash samples from standard input")

    return parser.parse_args()


def main():
    """ Main program function. Parse arguments, get input data and run queries. """

    arguments = parse_arguments()

    if select.select([sys.stdin, ], [], [], 0.0)[0] or arguments.force_stdin:
        hash_samples = sys.stdin.readlines()

    elif arguments.filename:
        hash_samples = load_hash_samples(arguments.filename)

    elif arguments.hash_sample:
        hash_samples = arguments.hash_sample

    else:
        hash_samples = collect_hash_samples()

    valid_hash_samples = [hash_sample.strip().lower() for hash_sample in hash_samples if validate_hash_format(hash_sample.strip().lower())]

    if not valid_hash_samples:
        print(f"\nError: No valid hash samples provided...\n", file=sys.stderr)
        sys.exit(6)
    
    query_umbrella(valid_hash_samples, print_unknown=arguments.print_unknown, minimum_score=arguments.minimum_score)


if __name__ == "__main__":
    sys.exit(main())



