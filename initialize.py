#!/usr/bin/env python
#coding: utf-8
from passgen import Authentication

def require_masterpassword():
    import getpass
    masterpass = getpass.getpass("enter your master password: ")
    confirmation = getpass.getpass("enter your master password for confirmation: ")

    if masterpass == confirmation:
        return masterpass
    else:
        return None

def generate_salt():
    import os
    import binascii

    length = 21
    num = int(binascii.hexlify(os.urandom(length)), 16)

    import string
    alphabets = string.ascii_lowercase + string.ascii_uppercase + string.digits
    card = len(alphabets)
    rev = []
    while num:
        num, rem = divmod(num, card)
        rev.append(alphabets[rem])
    salt= "".join(rev)
    salt = salt[:length]
    return salt

import os
import os.path
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
CREDENTIAL_FILE = os.path.join(BASE_DIR, "credentials.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

def halt_due_to_duplicated_configs(path):
    print "there already exists %s" % path
    print "remove it and try again."
    sys.exit()

if __name__=="__main__":
    import os
    import os.path
    import sys
    if os.path.exists(CREDENTIAL_FILE):
        halt_due_to_duplicated_configs(CREDENTIAL_FILE)
    if os.path.exists(CONFIG_FILE):
        halt_due_to_duplicated_configs(CONFIG_FILE)

    print "initializing configulation files."
    salt = generate_salt()
    masterpass = require_masterpassword()

    auth = Authentication(salt,None)
    digest = auth.generate_digest(masterpass)

    digest_head,digest_tail = digest[:len(digest)/2], digest[len(digest)/2:]

    password_config = {
        "salt":salt,
        "digest_head":digest_head,
        "digest_tail":digest_tail
    }

    import json
    with open(CREDENTIAL_FILE,'w+') as f:
        f.write( json.dumps(password_config,indent=4) )

    with open(CONFIG_FILE,'w+') as f:
        init_conf = {}
        f.write( json.dumps( init_conf, indent=4 ))

