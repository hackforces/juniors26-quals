import urllib.request

# "/" renders the index template without touching the database, so the
# healthcheck does not race the schema creation on first boot.
urllib.request.urlopen("http://127.0.0.1:8080/", timeout=2).read()
