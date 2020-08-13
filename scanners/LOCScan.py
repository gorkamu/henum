#!/usr/local/bin python
#_*_ coding: utf8 _*_

import re
import urllib
import urllib2
import json


class LOCScan(object):
    def __init__(self, ip, debug=0):
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            self.ip = ip
            self.debug = debug
        else:
            raise Exception("that's not a valid IP address")

    def get(self):
        if self.debug != 0:
            print(" [+] Performing a Location scan")
        
        result = {}
        data = urllib.urlopen("https://ipinfo.io/{}/json".format(self.ip))
        data = json.loads(data.read())
        for d in data:
            if d != 'readme':
                result.update({d: data[d]})

        return result