#!/usr/local/bin python
#_*_ coding: utf8 _*_

import re
import requests

class JoomlaScan(object):
    def __init__(self, hostname, debug = 0, intense = False):
        if re.match(r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+", hostname):
            self.hostname = hostname
            self.debug = debug
            self.schema = 'http://'
            self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36'}
            self.intense = False
        else:
            raise Exception("that's not a valid hostname")

    def scan(self):
        if self.debug > 1 and self.debug <= 4:
            print("     ╰─ Performing \033[96mJoomla \033[97mscan")

        if self.debug > 2 and self.debug <= 4:
            print("        ╰─ Looking for leaked pages")

        if self.debug > 3:    
            print("           ╰─ Looking for login page")
    
        results = {}
        pages = []

        joomlaAdminCheck = requests.get(self.schema + self.hostname + '/administrator/')
        if joomlaAdminCheck.status_code == 200 and "mod-login-username" in joomlaAdminCheck.text and "404" not in joomlaAdminCheck.text:
            results.update({'provider': 'Joomla'})
            pages.append(self.schema + self.hostname + '/administrator/')            

        if self.debug > 3:
            print("           ╰─ Looking for readme page")

        joomlaReadMeCheck = requests.get(self.schema + self.hostname + '/readme.txt')
        if joomlaReadMeCheck.status_code == 200 and "joomla" in joomlaReadMeCheck.text and "404" not in joomlaReadMeCheck.text:
            results.update({'provider': 'Joomla'})
            pages.append(self.schema + self.hostname + '/readme.txt')

        if self.debug > 3:	
            print("           ╰─ Looking for update system")

        joomlaDirCheck = requests.get(self.schema + self.hostname + '/media/com_joomlaupdate/')
        if joomlaDirCheck.status_code == 403 and "404" not in joomlaDirCheck.text:
            results.update({'provider': 'Joomla'})
            pages.append(self.schema + self.hostname + '/media/com_joomlaupdate/')

        if len(pages) > 0:
            results.update({'results': pages})
                
        return results