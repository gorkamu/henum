#!/usr/local/bin python
#_*_ coding: utf8 _*_

import re
import whois

class WHOISScan(object):
    def __init__(self, hostname, debug=0):
        if re.match(r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+", hostname):
            self.hostname = hostname.strip()
            self.debug = debug
        else:
            raise Exception("that's not a valid hostname")

    def get(self):
        try:
            if self.debug != 0:
                print("\033[96m [+] \033[97mPerforming \033[96mWhois \033[97mscan")

            results = {}
            domain = whois.whois(self.hostname)
            for n in domain:
                if domain[n] is not None:
                    results.update({n: domain[n]})
            
            return results
        except Exception:
            raise Exception("error retrieving WHOIS information")