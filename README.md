# advanced-xss-injector
Advanced XSS Payload Injector: Automates XSS vulnerability testing in web apps. Features WAF evasion (URL encoding, HTML entities, Unicode, randomized payloads), customizable payloads (single/multiple file support), dynamic HTTP options (headers, cookies, GET/POST), and automated analysis of server responses to detect vulnerabilities.

How to configure:
1.You need to create a payloads file which call payloads.txt and add all XXS payloads Scripts.

Usage Examples:
Single Payload with WAF Evasion (GET):
python3 advanced_xss_injector.py -u "http://example.com/vulnerable" -p "q" -m GET --payload "<script>alert('XSS');</script>" --evade
Multiple Payloads with Evasion (POST):
python3 advanced_xss_injector.py -u "http://example.com/vulnerable" -p "q" -m POST --payload-file payloads.txt --evade
