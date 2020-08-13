#!/usr/local/bin python
#_*_ coding: utf8 _*_

import re
import dns.resolver
import os
from os import path

class SubdomainScan(object):
    def __init__(self, hostname, debug = 0):
        if re.match(r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+", hostname):
            self.hostname = hostname
            self.debug = debug
        else:
            raise Exception("that's not a valid hostname")
    
    def get(self):
        if self.debug != 0:
            print("\033[96m [+] \033[97mPerforming \033[96mSubdomain \033[97mscan")

        result = []
        wordlist = "wordlists/subdomains.txt"
        wordlist = os.path.join(os.getcwd(), wordlist)
        
        if path.exists(wordlist):            
            file = open(wordlist)
            subdomains = file.read().split("\n")

            for s in subdomains:
                try:
                    arecord = dns.resolver.query("{}.{}".format(s, self.hostname), "A")
                    if isinstance(arecord, dns.resolver.Answer):
                        result.append("{}.{}".format(s, self.hostname))                    
                except Exception:
                    pass
        
            file.close()            
        else:
            raise Exception("subdomains.txt file is missing")

        return result