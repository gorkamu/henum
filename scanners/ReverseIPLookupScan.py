#!/usr/local/bin python
#_*_ coding: utf8 _*_

import re
import requests

class ReverseIPLookupScan(object):
    def __init__(self, ip, debug = 0):
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            self.ip = ip.strip()
            self.debug = debug
            self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36'}
        else:
            raise Exception("that's not a valid IP Address")

    def scan(self):
        if self.debug != 0:
            print("\033[96m [+] \033[97mPerforming \033[96mReverse IP Lookup \033[97mscan")

        result = []
        try:
            req = requests.post("https://domains.yougetsignal.com/domains.php", headers=self.headers, data={ "remoteAddress": "37.59.219.148"})            
            if req.json() and isinstance(req.json(), dict):
                data = req.json()

                if data.has_key("domainArray") and len(data["domainArray"]) > 0:
                    result = data["domainArray"]
        except Exception:
            print(Exception)

        return result
            
