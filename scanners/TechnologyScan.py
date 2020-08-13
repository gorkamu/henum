#!/usr/local/bin python
#_*_ coding: utf8 _*_

import re
from Wappalyzer import Wappalyzer

class TechnologyScan(object):
    def __init__(self, hostname, debug = 0):
        if re.match(r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+", hostname):
            self.hostname = hostname
            self.schema = 'http://'
            self.user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36'}
            self.debug = debug
        else:
            raise Exception("that's not a valid hostname")

    def get(self):
        try:
            if self.debug != 0:
                print("\033[96m [+] \033[97mPerforming \033[96mTechnology \033[97mscan")
            
            result = {}
            w = Wappalyzer()
            data = w.analyze(self.schema + self.hostname)
            
            if isinstance(data, dict) and len(data) > 0:
                result = data
            
            return result
        except Exception:
            raise Exception("error recovering used technology")