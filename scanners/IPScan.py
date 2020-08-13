#!/usr/local/bin python
#_*_ coding: utf8 _*_

import re
import socket

class IPScan(object):
    def __init__(self, hostname, debug=0):
        self.hostname = hostname.strip()
        self.ip = None
        self.debug = debug

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.hostname):
            self.ip = self.hostname
        elif re.match(r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+", self.hostname):
            try:
                self.ip = socket.gethostbyname(self.hostname)
            except Exception:
                raise Exception("Cannot get a valid IP address for that hostname")
        else:			
            raise Exception("No hostname or IP address given")

    def get(self):
        if self.debug != 0:
            print(" [+] Performing an IP Address scan")
        
        return self.ip