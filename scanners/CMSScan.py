#!/usr/local/bin python
#_*_ coding: utf8 _*_

import re
from scanners.cms.WordpressScan import WordpressScan
from scanners.cms.JoomlaScan import JoomlaScan
from scanners.cms.DrupalScan import DrupalScan
from scanners.cms.MagentoScan import MagentoScan

class CMSScan(object):
    def __init__(self, hostname, debug = 0, intense = False, wpvuln_apikey = None):
        if re.match(r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+", hostname):
            self.hostname = hostname.strip()
            self.debug = debug
            self.intense = intense
            self.schema = 'http://'
            self.user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36'}
            self.scan_result = {}
            self.scanner = None
            self.wpvuln_apikey = wpvuln_apikey
        else:
            raise Exception("that's not a valid hostname")

    def scan(self):
        if self.debug != 0:
            print("\033[96m [+] \033[97mPerforming \033[96mCMS \033[97mscan")

        result = {}
        self.get_provider()

        if {} != self.scan_result and self.scanner is not None:
            if "get_version" in dir(self.scanner):
                result.update({'version': self.scanner.get_version()})

            if "get_theme" in dir(self.scanner):
                result.update({'theme': self.scanner.get_theme()})
            
            if "get_users" in dir(self.scanner):
                result.update({'users': self.scanner.get_users()})
            
            if "get_plugins" in dir(self.scanner):
                result.update({'plugins': self.scanner.get_plugins()})            
        
        return self.merge_two_dicts(self.scan_result, result)

    def merge_two_dicts(self, x, y):
      z = x.copy()
      z.update(y)

      return z

    def get_provider(self):
        scanners = ['WordpressScan', 'JoomlaScan', 'DrupalScan', 'MagentoScan']
        for scannername in scanners:
            scanner = globals()[scannername]

            key = None
            if 'WordpressScan' == scannername:
                key = self.wpvuln_apikey

            data = scanner(self.hostname, self.debug, self.intense, key)
            scan_data = data.scan()

            if len(scan_data) > 0 and scan_data.has_key("provider"):
                self.scanner = data
                self.scan_result = scan_data
                
                return scan_data['provider']        
 