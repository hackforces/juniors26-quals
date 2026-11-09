import urllib.request

# /login renders directly (no redirect), proving Flask is up.
urllib.request.urlopen("http://127.0.0.1:8080/login", timeout=2).read()
