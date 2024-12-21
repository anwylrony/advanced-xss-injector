# advanced-xss-injector
Advanced XSS Payload Injector: Automates XSS vulnerability testing in web apps. Features WAF evasion (URL encoding, HTML entities, Unicode, randomized payloads), customizable payloads (single/multiple file support), dynamic HTTP options (headers, cookies, GET/POST), and automated analysis of server responses to detect vulnerabilities.

---

## How to Configure

1. **Create a Payloads File**:  
   - Name the file `payloads.txt`.  
   - Add all your desired XSS payload scripts, each on a new line.  
   - Example:  
     ```
     <script>alert('XSS');</script>
     <img src="x" onerror="alert('XSS')">
     <svg onload=alert('XSS')>
     ```

2. **Install Required Dependencies**:  
   - Ensure you have Python 3 installed.  
   - Install necessary Python libraries using:
     ```bash
     pip install requests
     ```

---

## Usage Examples

### 1. **Single Payload with WAF Evasion (GET Method)**  
Run the tool to test a single payload with WAF evasion:  
```bash
python3 advanced_xss_injector.py -u "http://example.com/vulnerable" -p "q" -m GET --payload "<script>alert('XSS');</script>" --evade
```

### 2. **Multiple Payloads with Evasion (POST Method)**  
Test multiple payloads from the `payloads.txt` file using POST requests with evasion techniques:  
```bash
python3 advanced_xss_injector.py -u "http://example.com/vulnerable" -p "q" -m POST --payload-file payloads.txt --evade
```

---

## Additional Options
- **Custom Headers**: Add headers using `--headers`. Example:
  ```bash
  --headers "User-Agent: CustomAgent, Authorization: BearerToken"
  ```
- **Custom Cookies**: Add cookies using `--cookies`. Example:
  ```bash
  --cookies "sessionid=abc123; csrftoken=xyz456"
  ```

---
