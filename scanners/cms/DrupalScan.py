#!/usr/local/bin python
#_*_ coding: utf8 _*_

import re
import requests

class DrupalScan(object):
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
            print("     ╰─ Performing \033[96mDrupal \033[97mscan")

        if self.debug > 2 and self.debug <= 4:
            print("        ╰─ Looking for leaked pages")

        if self.debug > 3:    
            print("           ╰─ Looking for login page")

        results = {}
        pages = []

        drupalReadMeCheck = requests.get(self.schema + self.hostname + '/readme.txt')
        if drupalReadMeCheck.status_code == 200 and 'drupal' in drupalReadMeCheck.text and '404' not in drupalReadMeCheck.text:
            results.update({'provider': 'Drupal'})
            pages.append(self.schema + self.hostname + '/readme.txt/')

        if self.debug > 3:	
            print("           ╰─ Looking for Drupal meta tag")

        drupalTagCheck = requests.get(self.schema + self.hostname)
        if drupalTagCheck.status_code == 200 and 'name="Generator" content="Drupal' in drupalTagCheck.text:
            results.update({'provider': 'Drupal'})
            pages.append(self.schema + self.hostname)

        if self.debug > 3:
            print("           ╰─ Looking for copyright file")

        drupalCopyrightCheck = requests.get(self.schema + self.hostname + '/core/COPYRIGHT.txt')
        if drupalCopyrightCheck.status_code == 200 and 'Drupal' in drupalCopyrightCheck.text and '404' not in drupalCopyrightCheck.text:            
            results.update({'provider': 'Drupal'})
            pages.append(self.schema + self.hostname + '/core/COPYRIGHT.txt')

        if self.debug > 3:
            print("           ╰─ Looking for Drupal modules readme file")

        drupalReadme2Check = requests.get(self.schema + self.hostname + '/modules/README.txt')
        if drupalReadme2Check.status_code == 200 and 'drupal' in drupalReadme2Check.text and '404' not in drupalReadme2Check.text:
            results.update({'provider': 'Drupal'})
            pages.append(self.schema + self.hostname + '/modules/README.txt')

        if len(pages) > 0:
            results.update({'results': pages})
                
        return results            

    def get_version(self):
        pass

    def get_theme(self):
        pass

    def get_users(self):
        pass

    def get_plugins(self):
        pass