#!/usr/local/bin python
#_*_ coding: utf8 _*_

import re
import json
import requests
import urllib
import urllib2
import os
import os.path
from bs4 import BeautifulSoup

class WordpressScan(object):
    def __init__(self, hostname, debug = 0, intense = False):
        if re.match(r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+", hostname):
            self.hostname = hostname
            self.debug = debug
            self.schema = 'http://'
            self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36'}
            self.intense = intense
        else:
            raise Exception("that's not a valid hostname")

    def get_version(self):
        if self.debug > 2 and self.debug <= 4:
            print("        ╰─ Enumerating used version")

        if self.debug > 3:
            print("           ╰─ Getting version from meta tag")

        req = requests.get(self.schema + self.hostname, headers = self.headers)
        data = BeautifulSoup(req.text, 'html5lib')
        version = data.find('meta', attrs={'name':'generator', 'content': re.compile('^WordPress.*$')})
        
        if version is not None:
            version = version["content"].split('WordPress ')[1]
        else:
            if self.debug > 3:
                print("           ╰─ Getting version from feed")

            feed = requests.get(self.schema + self.hostname + "/feed/", headers=self.headers)
            if isinstance(feed, requests.models.Response) and 200 == feed.status_code:
                version = re.findall(r'<generator>https://wordpress.org/\?v=(.*?)</generator>', feed.text)
                if version != []:
                    version = version[0]
                else:
                    if self.debug > 3:
                        print("           ╰─ Getting version from wp-links-opml")

                    opml = requests.get(self.schema + self.hostname + "/wp-links-opml.php", headers = self.headers)                    
                    if isinstance(opml, requests.models.Response) and 200 == opml.status_code:
                        version = re.findall(r'generator=\"WordPress/(.*?)\"', opml.text)
                        if version != []:
                            version = version[0]
                        else:
                            version = "0"
        
        return version
                
    def get_users(self):
        if self.debug > 2 and self.debug <= 4:
            print("        ╰─ Enumerating users")
        
        if self.debug > 3:
            print("           ╰─ Getting users from wp-json api")

        users = []
        req = urllib.request.Request(self.schema + self.hostname + "/wp-json/wp/v2/users", headers = self.headers)
        data = urllib.request.urlopen(req)
        
        try:
            for n in json.loads(data.read()):
                users.append({
                    'id': n['id'],
                    'name': n['name'],
                    'slug': n['slug'],
                    'link': n['link']
                })
        except Exception:
            pass        
        
        if len(users) < 0:
            if self.debug > 3:
                print("           ╰─ Getting users from Jetpack API")

            jetpack = requests.get('https://public-api.wordpress.com/rest/v1.1/sites/'+ self.hostname + '/posts?number=100&pretty=true&fields=author', headers = self.headers)
            if isinstance(jetpack, requests.models.Response) and jetpack.status_code == 403:
                print(jetpack.text)               
            else:                
                data = jetpack.json()
                if data.has_key("error"):
                    users = []
                elif data.has_key("found") and data["found"] > 0:
                    uids = []
                    for n in data["posts"]:
                        uids.append(n["author"]["ID"])
                    
                    uids = list(dict.fromkeys(uids))
                    
                    for uid in uids:
                        user = filter(lambda obj: obj["author"]["ID"] == uid, data["posts"])[0]["author"]
                        users.append({
                            'id': user['ID'],
                            'name': user['name'],
                            'login': user['login'],
                            'slug': '',
                            'link': ''
                        })
                else:
                    users = []

        return users

    def get_theme(self):
        if self.debug > 2 and self.debug <= 4:
            print("        ╰─ Enumerating used theme")

        if self.debug > 3:
            print("           ╰─ Getting theme from link meta-tag")

        default_theme = ''
        req = requests.get(self.schema + self.hostname, headers = self.headers)
        matches = re.finditer(r"wp-content\/themes\/([a-z0-9\-]+)\/([a-z]+)", req.text, re.MULTILINE)
        
        for matchNum, match in enumerate(matches, start=1):
            mm = match.group()
            if isinstance(mm, unicode):
                url = str(mm)
                url = url.split("/")

                if "themes" in url:
                    pos = url.index("themes")
                    t = url[pos+1]
                    if "child" in t:
                        default_theme = t
                        break
                    else:
                        default_theme = t    
        
        return default_theme

    def get_plugins(self):
        if self.debug > 2 and self.debug <= 4:
            print("        ╰─ Enumerating used plugins")
            
        plugins = []
        results = []

        if self.intense:
            plugins = self.get_bruteforce_plugins()        
        else:
            if self.debug > 3:
                print("           ╰─ Getting plugins from source")
            
            req = requests.get(self.schema + self.hostname, headers = self.headers)
            plug_regex = re.compile('wp-content/plugins/([^/]+)/.+')
            plugins = plug_regex.findall(req.text)

        if len(plugins) > 0:
            for plugin in plugins:
                vulns = self.get_vulnerabilities(plugin)
                if len(vulns) > 0:
                    results.append({'name': plugin, 'vulnerabilities': vulns})
                else:
                    results.append({'name': plugin})

        return results
    
    def get_bruteforce_plugins(self):
        if self.debug > 3:
            print("           ╰─ Enumerating WordPress plugins by bruteforce attack")

        results = []
        plugins_wordlist_path = "wordlists/wp_plugins.txt"
        plugins_wordlist_path = os.path.join(os.getcwd(), plugins_wordlist_path)
        
        if os.path.exists(plugins_wordlist_path):
            file = open(plugins_wordlist_path)
            plugins = file.read().split("\n")            

            for plugin in plugins:
                plug_path = self.schema+self.hostname+"/wp-content/plugins/"+plugin
                p = requests.get(url=plug_path)
                if 200 == p.status_code or 403 == p.status_code:
                    results.append(plugin)
        else:
            raise Exception("wp_plugins.txt file is missing")

        return results
        
    def get_vulnerabilities(self, plugin):
        vulns = []
        vulnpage = requests.get("https://wpvulndb.com/search?text={}&vuln_type=".format(plugin), headers=self.headers)
        if 200 == vulnpage.status_code and "No results found." not in vulnpage.text:
            data = BeautifulSoup(vulnpage.text, 'html.parser')
            data = data.find(id='search-results').find('table').find('tbody').find_all('tr')

            for row in data:
				vuln = {}
				cols = row.find_all('td')
				cols = [ele.text.strip() for ele in cols]
				vuln_url = "https://wpvulndb.com/vulnerabilities/{}".format(cols[0])				
				vuln_name = cols[2].strip()
				vuln_info = requests.get(vuln_url, headers=self.user_agent)				
				
				if vuln_info.status_code == 200:
					vuln_site = BeautifulSoup(vuln_info.content, 'html.parser')
					vuln_fixed = vuln_site.findAll("div", {"class": "fixed-in"})				
					if len(vuln_fixed) > 0:
						vuln_fixed = vuln_fixed[0].text
						if "fixed in version" in vuln_fixed:
							vuln_fixed = vuln_fixed[17:len(vuln_fixed)].strip()

					vuln = {
						'name': vuln_name,
						'fixed_in': vuln_fixed
					}

					for link in vuln_site.findAll('a', attrs={'href': re.compile("^https://")}):
						if "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE" in link.get('href'):
							cve_link = link.get('href')
							cve_no = cve_link[51:len(cve_link)]
							vuln.update({'cve_link': cve_link})
							vuln.update({'cve': cve_no})
			    		
						if "https://www.exploit-db.com" in link.get('href'):
							exploit_link = link.get('href')
							exploit_no = exploit_link.split("/")[-2]							
							vuln.update({'exploit_link': exploit_link})
							vuln.update({'exploit': exploit_no})

						if "https://cwe.mitre.org/data/definitions" in link.get('href'):
							cwe_link = link.get('href')
							cwe = cwe_link[39:len(cwe_link)-5]
							vuln.update({'cwe_link': cwe_link})
							vuln.update({'cwe': cwe})

					vuln_type = vuln_site.findAll("td", string="Type")[0].findNext("td")
					if vuln_type is not None:
						vuln.update({'type': vuln_type.text})					
						
					vulns.append(vuln)

        return vulns

    def scan(self):
        if self.debug > 1 and self.debug <= 4:
            print("     ╰─ Performing \033[96mWordPress \033[97mscan")

        if self.debug > 2 and self.debug <= 4:
            print("        ╰─ Looking for leaked pages")

        if self.debug > 3:
            print("           ╰─ Looking for login page")

        results = {}
        pages = []

        wpLoginCheck = requests.get(self.schema + self.hostname + '/wp-login.php', headers=self.headers)
        if wpLoginCheck.status_code == 200 and "user_login" in wpLoginCheck.text and "404" not in wpLoginCheck.text:
            results.update({'provider': 'WordPress'})
            pages.append(self.schema + self.hostname + '/wp-login.php')

        if self.debug > 3:
            print("           ╰─ Looking for admin page")

        wpAdminCheck = requests.get(self.schema + self.hostname + '/wp-admin', headers=self.headers)
        if wpAdminCheck.status_code == 200 and "user_login" in wpAdminCheck.text and "404" not in wpLoginCheck.text:
            results.update({'provider': 'WordPress'})
            pages.append(self.schema + self.hostname + '/wp-admin')

        if self.debug > 3:	
            print("           ╰─ Looking for update system")

        wpAdminUpgradeCheck = requests.get(self.schema + self.hostname + '/wp-admin/upgrade.php', headers=self.headers)
        if wpAdminUpgradeCheck.status_code == 200 and "404" not in wpAdminUpgradeCheck.text and "WordPress" in wpAdminUpgradeCheck.text:
            results.update({'provider': 'WordPress'})
            pages.append(self.schema + self.hostname + '/wp-admin/upgrade.php')

        if self.debug > 3:
            print("           ╰─ Looking for readme page")

        wpAdminReadMeCheck = requests.get(self.schema + self.hostname + '/readme.html', headers=self.headers)
        if wpAdminReadMeCheck.status_code == 200 and "404" not in wpAdminReadMeCheck.text and "WordPress" in wpAdminReadMeCheck.text:
            results.update({'provider': 'WordPress'})
            pages.append(self.schema + self.hostname + '/readme.html')

        if len(pages) > 0:
            results.update({'results': pages})

        return results