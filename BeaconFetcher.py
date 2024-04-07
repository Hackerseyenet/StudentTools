#!/usr/bin/python3

import requests
import rstr
import sys
import urllib3

if len(sys.argv) < 2:
    print("Usage: %s http[s]://<server_address>" % (sys.argv[0]))
    sys.exit(1)

url = sys.argv[1]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
headers = {""}

def generate_checksum8_uri(arch):
    # x86 = 92
    # x64 = 93
    value = 0
    while value != arch:
        rand = rstr.xeger(r'[A-Za-z0-9]{4}')
        value = (sum([ord(ch) for ch in rand]) % 0x100)

    return "/" + rand

def get_shellcode(url,uri):
    f_url = url + uri
    try:
            resp = requests.get(f_url, timeout=5, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
            print('[!] Connection error %s' % (e))
            sys.exit(1)

    if(resp.status_code==200):
        print('[+] Got response from %s' % (url))
        with open("/tmp/out","wb") as output:
            output.write(resp.content)
        print('[+] Response written to /tmp/out, response might be shellcode')
    else:
        print('[!] Server returned non-200 response')
        sys.exit(1)

print('[+] Generating x86 check8 uri')
# Just x86 for this example
uri = generate_checksum8_uri(92)

print('[+] Making request to suspected C2 server')
get_shellcode(url,uri)
