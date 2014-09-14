#!/usr/bin/env python
#coding: utf-8
import sys
import os
import os.path

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
CREDENTIAL_FILE = os.path.join(BASE_DIR, "credentials.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

import json
def load_config():
    config = None
    with open(CONFIG_FILE) as f:
        content = f.read()
        config = json.loads(content)
    return config

def load_password_config():
    with open(CREDENTIAL_FILE) as f:
        content = f.read()
        password_config = json.loads(content)
    return password_config


class PasswordGenerator:
    iteration = 30000

    def _get_alphabet_types(self,lower_case,upper_case,digits,symbols):
        import string
        str_symbols = "#$-=?@[]_"

        alphabet_types = []
        if lower_case: alphabet_types.append(string.ascii_lowercase)
        if upper_case: alphabet_types.append(string.ascii_uppercase)
        if digits:     alphabet_types.append(string.digits)
        if symbols:    alphabet_types.append(str_symbols)
        return alphabet_types


    def __init__(self,salt,length,args=None):
        self.salt = salt

        if args and (args.lower_case or args.upper_case or args.digits or args.symbols):
            self.alphabet_types = \
                self._get_alphabet_types(args.lower_case,args.upper_case,args.digits,args.symbols)
        else:
            self.alphabet_types = \
                self._get_alphabet_types(True,True,True,False)

        self.length = max(length, len(self.alphabet_types)+2 )


    def _encode_number(self,num):
        alphabets = "".join(self.alphabet_types)
        card = len(alphabets)
        rev = []
        while num:
            num, rem = divmod(num, card)
            rev.append(alphabets[rem])
        return "".join(rev)

    def _generate_hashed_integer(self,service):
        import hashlib

        digest = ""
        for i in xrange(self.iteration):
            digest = digest + service + self.salt
            digest = hashlib.sha512(digest).hexdigest()

        return int(digest, 16)

    def _password(self,service):
        hashint = self._generate_hashed_integer(service)
        password = self._encode_number(hashint)
        return password[-self.length:]

    def _contains_all_alphabet_types(self,password):
        if not password:
            return False

        def contains_any(string):
            for char in string:
                if char in password:
                    return True
            return False
        for alphabet_type in self.alphabet_types:
            if not contains_any(alphabet_type):
                return False
        return True

    def generate(self, service):
        password = ""
        sugared_service = service
        while not self._contains_all_alphabet_types(password):
            password = self._password(sugared_service)
            sugared_service = password + service
        return password

class Authentication:
    true_digest = ""
    streathing =  30000
    def __init__(self, salt, true_digest=None):
        self.true_digest = true_digest
        self.salt = salt

    def generate_digest(self,password):
        import hashlib
        digest = ""
        for i in xrange(self.streathing):
            digest = digest + password + self.salt
            digest = hashlib.sha512(digest).hexdigest()
        return digest

    def confirm(self,password):
        if not self.true_digest or not self.salt:
            return False
        digest = self.generate_digest(password)

        return digest == self.true_digest


def require_salt():
    import getpass
    masterpass = getpass.getpass("enter your master password: ")

    password_config = load_password_config()
    salt = password_config["salt"]
    true_digest = password_config["digest_head"] + password_config["digest_tail"]
    authentication = Authentication(salt,true_digest)
    if not authentication.confirm(masterpass):
        print "master password do not match."
        print "Bye."
        sys.exit()
    return masterpass

def require_service():
    service = raw_input("input service name: ")
    return service


def load_arguments(service):
    import sys,argparse
    args = {}
    parser = argparse.ArgumentParser(description="password generator")

    parser.add_argument("--length","-l", metavar="length",type=int,default=20)
    parser.add_argument("--service", metavar="service")
    parser.add_argument("-A", "--upper_case", action='store_const', const=True, default=True)
    parser.add_argument("-a", "--lower_case", action='store_const', const=True, default=True)
    parser.add_argument("-d", "--digits", action='store_const', const=True, default=True)
    parser.add_argument("-s", "--symbols", action='store_const', const=True, default=False)

    parser.add_argument("-S", "--strong", action='store_const', const=True, default=False)
    parser.add_argument("-L", "--long", action='store_const', const=True, default=False)
    args = parser.parse_args()

    if len(sys.argv) <= 1:
        setting = load_config()
        if service in setting:
            args.__dict__.update(setting[service])

    if hasattr(args,"strong") and args.strong:
        args.upper_case = True
        args.lower_case = True
        args.symbols = True
        args.digits = True
    if hasattr(args,"long") and args.long:
        args.length = 30
    return args


def main():
    salt = require_salt()
    service = require_service()

    args = load_arguments(service)

    passgen = PasswordGenerator(salt,args.length,args)
    password = passgen.generate(service)

    print ""
    print "passphrase for %s is" % service
    print password


if __name__ == "__main__":
    main()
