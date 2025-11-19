from flask import Flask, render_template, redirect, url_for, session, flash, request
from internal import internal_bp
import psycopg2
import psycopg2.extras
import os
import re
import uuid
import subprocess
import time

app = Flask(__name__)
app.secret_key = os.urandom(32)

app.register_blueprint(internal_bp)

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
            # os.system(f'/usr/bin/rm -rf /tmp/*')
            time.sleep(5)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337)
