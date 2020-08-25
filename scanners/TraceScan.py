#!/usr/local/bin python
#_*_ coding: utf8 _*_

import re
import requests
from bs4 import BeautifulSoup
from scanners.LOCScan import LOCScan

class TraceScan(object):
    def __init__(self, ip, debug = 0):
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            self.ip = ip
            self.debug = debug
            self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36'}
        else:
            raise Exception("that's not a valid IP address")

    def get(self):
        if self.debug != 0:
            print("\033[96m [+] \033[97mPerforming \033[96mTraceRoute \033[97mscan")
        
        hops = []
        try:
            url = "https://www.telstra.net/cgi-bin/trace"
            req = requests.post(url, headers=self.headers, data={"destination": self.ip})
            if req.status_code == 200:
                data = BeautifulSoup(req.text, 'lxml')
                data = data.findAll('pre')[1]
                data = str(data.contents[0])

                for line in data.split("\n"):
                    if line != '':
                        trd = {}
                        if len(hops) == 0:
                            trd['ip'] = requests.get('https://api.ipify.org').text
                            trd['host'] = ''
                            trd['ttl'] = ''
                            trd['loc'] = self.get_location(trd['ip'])
                            hops.append(trd)
                        else:
                            line = line.split()
                            ip = line[2].replace("(","").replace(")","")

                            trd['ip'] = ip
                            trd['host'] = line[1]                     

                            if "telstra" not in trd["host"] and "reach.com" not in trd["host"]:
                                trd['ttl'] = line[3] + 'ms'
                                trd['loc'] = self.get_location(trd['ip'])
                            
                                hops.append(trd)

            return hops                                   
        except Exception:
            pass

    def get_location(self, ip):
        trd = {}
        try:
            loc = LOCScan(ip=ip, debug=0).get()
            if loc['loc']:
                lng, lat = loc['loc'].split(',')
                trd = {
                    'lng': lng,
                    'lat': lat,
                    'city': loc['city'],
                    'country': loc['country'],
                    'region': loc['region']
                }
        except Exception:
            pass
        
        return trd