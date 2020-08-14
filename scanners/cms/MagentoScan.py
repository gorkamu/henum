#!/usr/local/bin python
#_*_ coding: utf8 _*_

import re
import requests

class MagentoScan(object):
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
            print("     ╰─ Performing \033[96mMagento \033[97mscan")

        if self.debug > 2 and self.debug <= 4:
            print("        ╰─ Looking for leaked pages")

        if self.debug > 3:      
            print("           ╰─ Looking for login page")
    
        results = {}
        pages = []

        magentoRelNotesCheck = requests.get(self.schema + self.hostname + '/RELEASE_NOTES.txt')
        if magentoRelNotesCheck.status_code == 200 and 'magento' in magentoRelNotesCheck.text:
            results.update({'provider': 'Magento'})
            pages.append(self.schema + self.hostname + '/RELEASE_NOTES.txt')
        
        if self.debug > 3:	
            print("           ╰─ Looking for Magento cookies script")

        magentoCookieCheck = requests.get(self.schema + self.hostname + '/js/mage/cookies.js')
        if magentoCookieCheck.status_code == 200 and "404" not in magentoCookieCheck.text:
            results.update({'provider': 'Magento'})
            pages.append(self.schema + self.hostname + '/js/mage/cookies.js')

        if self.debug > 3:
            print("           ╰─ Looking for index page")

        magStringCheck = requests.get(self.schema + self.hostname + '/index.php')
        if magStringCheck.status_code == 200 and '/mage/' in magStringCheck.text or 'magento' in magStringCheck.text:
            results.update({'provider': 'Magento'})
            pages.append(self.schema + self.hostname + '/index.php')

        if self.debug > 3:
            print("           ╰─ Looking for Magento default styles file")

        magentoStylesCSSCheck = requests.get(self.schema + self.hostname + '/skin/frontend/default/default/css/styles.css')
        if magentoStylesCSSCheck.status_code == 200 and "404" not in magentoStylesCSSCheck.text:
            results.update({'provider': 'Magento'})
            pages.append(self.schema + self.hostname + '/skin/frontend/default/default/css/styles.css')

        if self.debug > 3:
            print("           ╰─ Looking for Magento errors design XML file")
        
        mag404Check = requests.get(self.schema + self.hostname + '/errors/design.xml')
        if mag404Check.status_code == 200 and "magento" in mag404Check.text:
            results.update({'provider': 'Magento'})
            pages.append(self.schema + self.hostname + '/errors/design.xml')

        if len(pages) > 0:
            results.update({'results': pages})
                
        return results        
