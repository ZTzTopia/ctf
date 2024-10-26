---
category: Web Exploitation
tags: 
credits: 
  - [HackAndQuack](spookyctf/web/cryptid-hunters/README.md)
---

# paranormal-picture

## Scenario

> One of our recruits is a massive conspiracy theorist. Strangely enough, he has expressed not only that everything is the bite of 87 but also that there's something strange going on in the dark web that involves Dr. Tom Lei. Though he is a little bit nuts, we think he may be on to something. Figure out what's going on before it's too late!

## Solution

![Submit a Blog](submit_a_blog.png)

There is a form on the website that allows you to submit a URL. The website will then request the URL and display the website's content.

```py
@app.route('/', methods=['GET', 'POST'])
def index():

    if request.method == 'POST':
        url = request.form['url']
        try:
            result = verifyBlog(url)
            if not result:
                return render_template('index.html', error=f"Please submit a blog!")
        except:
            return render_template('index.html', error=f"Please submit a blog!")

        r = requests.get(url)

        return render_template('index.html', result=r.text)
    return render_template('index.html')
```

The website will only display the content if the URL contains the words `blog`, `cryptid`, `real`, `666`, and `.org`.

```py
def verifyBlog(url):
    blog_list = ["blog","cryptid","real","666",".org"]
    for word in blog_list:
        if word not in url:
            return False
    return True
```

The website will only display the flag if the request is from the local server. We can use this to request the flag from the local server.

```py
@app.route('/flag')
def flag():
    if request.remote_addr == '::ffff:127.0.0.1' or request.remote_addr == '::1':
        return render_template('flag.html', FLAG=os.environ.get("FLAG"))

    else:
        return render_template('alarm.html'), 403
```

We can use the following URL to get the flag:

```plaintext
http://127.0.0.1/flag?blogcryptidreal666.org
```

## Flag

`NICC{tHe_crYptIds_aRe_waIting_t0_sTrike}`
