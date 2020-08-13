#!/usr/local/bin python
#_*_ coding: utf8 _*_

import re
import dns.resolver

class DNSScan(object):
    def __init__(self, hostname, debug = 0):
        if re.match(r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+", hostname):
            self.hostname = hostname.strip()
            self.debug = debug
        else:
            raise Exception("that's not a valid hostname")

    def get(self):
        results = {}
        try:
            if self.debug != 0:
                print(" [+] Performing a DNS Records scan")

            for qtype in 'A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'MF','MD':
                answer = dns.resolver.query(self.hostname, qtype, raise_on_no_answer=False)		    
                if answer.rrset is not None:
                    if self.debug > 1:
                        print("     ╰─ Getting {} DNS Record".format(qtype))

                    results.update({qtype: answer.rrset.to_text().split("\n")})

            return results                

        except Exception:
            raise Exception("error retrieving DNS records")