#!/usr/local/bin python
#_*_ coding: utf8 _*_

import dns.resolver
import argparse
import socket
import re
import requests
import json
import whois
import urllib
import urllib2
import time
from os import path, system
from bson import json_util
from bs4 import BeautifulSoup
from Wappalyzer import Wappalyzer
from colored import fg, bg, attr

class IP(object):
	def __init__(self, hostname, log_level=0):
		self.hostname = hostname.strip()
		self.ip = None
		self.log_level = log_level

		if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.hostname):
			self.ip = self.hostname
		elif re.match(r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+", self.hostname):
			try:
				self.ip = socket.gethostbyname(self.hostname)
			except Exception as e:
				raise Exception("Cannot get a valid IP address for that hostname")
		else:			
			raise Exception("No hostname or IP address given")

	def get(self):
		if self.log_level != 0:
			print("	%s[%s+%s] Performing an %sIP Address %sscan" % (fg(45), fg(46), fg(45), fg(15), fg(45)))

		return self.ip

class DNS(object):
	def __init__(self, hostname, log_level=0):
		if re.match(r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+", hostname):
			self.hostname = hostname.strip()
			self.log_level = log_level
		else:
			raise Exception("that's not a valid hostname")

	def get(self):
		results = {}
		try:
			if self.log_level != 0:
				print("	%s[%s+%s] Performing a %sDNS Records %sscan" % (fg(45), fg(46), fg(45), fg(15), fg(45)))

			for qtype in 'A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'MF','MD':
			    answer = dns.resolver.query(self.hostname, qtype, raise_on_no_answer=False)		    
			    if answer.rrset is not None:
			    	if self.log_level > 1:
						print("		%s| Getting %s{} %sDNS Record".format(qtype) % (fg(43), fg(15), fg(43))	)

			        results.update({qtype: answer.rrset.to_text().split("\n")})

			return results
		except Exception as e:
			raise Exception("error retrieving DNS records")

class CMSSCAN(object):
	def __init__(self, hostname, log_level=0, intense_scan=False):
		if re.match(r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+", hostname):
			self.hostname = hostname.strip()
			self.schema = 'http://'
			self.user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36'}
			self.results = {}
			self.pages = {}
			self.provider = None
			self.log_level = log_level
			self.intense_scan = intense_scan
		else:
			raise Exception("that's not a valid hostname")

	def wpscan(self):
		if self.log_level > 1:
			print("		%s| Performing a %sWordpress %sscan" % (fg(43), fg(15), fg(43)))
			print("			%s| Checking for %sWordpress login page" % (fg(158), fg(15)))

		wpLoginCheck = requests.get(self.schema + self.hostname + '/wp-login.php', headers=self.user_agent)
		if wpLoginCheck.status_code == 200 and "user_login" in wpLoginCheck.text and "404" not in wpLoginCheck.text:
			self.provider = 'Wordpress'
			self.results.update({'provider': self.provider})
			self.pages.update({'login': self.schema + self.hostname + '/wp-login.php'})

		if self.log_level > 1:
			print("			%s| Checking for %sWordpress admin page" % (fg(158), fg(15)))	

		wpAdminCheck = requests.get(self.schema + self.hostname + '/wp-admin', headers=self.user_agent)
		if wpAdminCheck.status_code == 200 and "user_login" in wpAdminCheck.text and "404" not in wpLoginCheck.text:
			self.provider = 'Wordpress'
			self.results.update({'provider': self.provider})
			self.pages.update({'admin': self.schema + self.hostname + '/wp-admin'})

		if self.log_level > 1:		
			print("			%s| Checking for %sWordpress upgrade system" % (fg(158), fg(15)))

		wpAdminUpgradeCheck = requests.get(self.schema + self.hostname + '/wp-admin/upgrade.php', headers = self.user_agent)
		if wpAdminUpgradeCheck.status_code == 200 and "404" not in wpAdminUpgradeCheck.text:
			self.provider = 'Wordpress'
			self.results.update({'provider': self.provider})
			self.pages.update({'upgrade': self.schema + self.hostname + '/wp-admin/upgrade.php'})

		if self.log_level > 1:
			print("			%s| Checking for %sWordpress readme page" % (fg(158), fg(15)))

		wpAdminReadMeCheck = requests.get(self.schema + self.hostname + '/readme.html', headers=self.user_agent)
		if wpAdminReadMeCheck.status_code == 200 and "404" not in wpAdminReadMeCheck.text:
			self.provider = 'Wordpress'
			self.results.update({'provider': self.provider})
			self.pages.update({'readme': self.schema + self.hostname + '/readme.html'})

		if len(self.pages) > 0:
			self.results.update({'results': self.pages})

	def joomlascan(self):
		if self.log_level > 1:
			print("		%s| Performing a %sJoomla %sscan" % (fg(43), fg(15), fg(43)))
			print("			%s| Checking for %sJoomla administrator page" % (fg(158), fg(15)))

		joomlaAdminCheck = requests.get(self.schema + self.hostname + '/administrator/')
		if joomlaAdminCheck.status_code == 200 and "mod-login-username" in joomlaAdminCheck.text and "404" not in joomlaAdminCheck.text:
			self.provider = 'Joomla'
			self.results.update({'provider': self.provider})
			self.pages.update({'admin': self.schema + self.hostname + '/administrator/'})

		if self.log_level > 1:
			print("			%s| Checking for %sJoomla readme file" % (fg(158), fg(15)))

		joomlaReadMeCheck = requests.get(self.schema + self.hostname + '/readme.txt')
		if joomlaReadMeCheck.status_code == 200 and "joomla" in joomlaReadMeCheck.text and "404" not in joomlaReadMeCheck.text:
			self.provider = 'Joomla'
			self.results.update({'provider': self.provider})
			self.pages.update({'readme': self.schema + self.hostname + '/readme.txt'})

		if self.log_level > 1:		
			print("			%s| Checking for %sJoomla update system" % (fg(158), fg(15)))

		joomlaDirCheck = requests.get(self.schema + self.hostname + '/media/com_joomlaupdate/')
		if joomlaDirCheck.status_code == 403 and "404" not in joomlaDirCheck.text:
			self.provider = 'Joomla'
			self.results.update({'provider': self.provider})
			self.pages.update({'upgrade': self.schema + self.hostname + '/media/com_joomlaupdate/'})
		
		if len(self.pages) > 0:
			self.results.update({'results': self.pages})

	def magentoscan(self):
		if self.log_level > 1:
			print("		%s| Performing a %sMagento %sscan" % (fg(43), fg(15), fg(43)))
			print("			%s| Checking for %sMagento releases notes" % (fg(158), fg(15)))

		magentoRelNotesCheck = requests.get(self.schema + self.hostname + '/RELEASE_NOTES.txt')
		if magentoRelNotesCheck.status_code == 200 and 'magento' in magentoRelNotesCheck.text:
			self.provider = 'Magento'
			self.results.update({'provider': self.provider})
			self.pages.update({'release': self.schema + self.hostname + '/RELEASE_NOTES.txt'})

		if self.log_level > 1:		
			print("			%s| Checking for %sMagento cookies script" % (fg(158), fg(15)))

		magentoCookieCheck = requests.get(self.schema + self.hostname + '/js/mage/cookies.js')
		if magentoCookieCheck.status_code == 200 and "404" not in magentoCookieCheck.text:
			self.provider = 'Magento'
			self.results.update({'provider': self.provider})
			self.pages.update({'cookies': self.schema + self.hostname + '/js/mage/cookies.js'})

		if self.log_level > 1:		
			print("			%s| Checking for %sMagento index page" % (fg(158), fg(15)))

		magStringCheck = requests.get(self.schema + self.hostname + '/index.php')
		if magStringCheck.status_code == 200 and '/mage/' in magStringCheck.text or 'magento' in magStringCheck.text:
			self.provider = 'Magento'
			self.results.update({'provider': self.provider})
			self.pages.update({'index': self.schema + self.hostname + '/index.php'})

		if self.log_level > 1:		
			print("			%s| Checking for %sMagento default styles file" % (fg(158), fg(15)))	

		magentoStylesCSSCheck = requests.get(self.schema + self.hostname + '/skin/frontend/default/default/css/styles.css')
		if magentoStylesCSSCheck.status_code == 200 and "404" not in magentoStylesCSSCheck.text:
			self.provider = 'Magento'
			self.results.update({'provider': self.provider})
			self.pages.update({'styles': self.schema + self.hostname + '/skin/frontend/default/default/css/styles.css'})

		if self.log_level > 1:		
			print("			%s| Checking for %sMagento errors design XML file" % (fg(158), fg(15)))	
		
		mag404Check = requests.get(self.schema + self.hostname + '/errors/design.xml')
		if mag404Check.status_code == 200 and "magento" in mag404Check.text:
			self.provider = 'Magento'
			self.results.update({'provider': self.provider})
			self.pages.update({'error': self.schema + self.hostname + '/errors/design.xml'})

		if len(self.pages) > 0:
			self.results.update({'results': self.pages})

	def drupalscan(self):
		try:
			if self.log_level > 1:
				print("		%s| Performing a %sDrupal %sscan" % (fg(43), fg(15), fg(43)))
				print("			%s| Checking for %sDrupal readme file" % (fg(158), fg(15)))

			drupalReadMeCheck = requests.get(self.schema + self.hostname + '/readme.txt')
			if drupalReadMeCheck.status_code == 200 and 'drupal' in drupalReadMeCheck.text and '404' not in drupalReadMeCheck.text:
				self.provider = 'Drupal'
				self.results.update({'provider': self.provider})
				self.pages.update({'readme': self.schema + self.hostname + '/readme.txt'})

			if self.log_level > 1:		
				print("			%s| Checking for %sDrupal meta tag" % (fg(158), fg(15)))	

			drupalTagCheck = requests.get(self.schema + self.hostname)
			if drupalTagCheck.status_code == 200 and 'name="Generator" content="Drupal' in drupalTagCheck.text:
				self.provider = 'Drupal'
				self.results.update({'provider': self.provider})
				self.pages.update({'index': self.schema + self.hostname})

			if self.log_level > 1:
				print("			%s| Checking for %sDrupal copyright file" % (fg(158), fg(15)))		

			drupalCopyrightCheck = requests.get(self.schema + self.hostname + '/core/COPYRIGHT.txt')
			if drupalCopyrightCheck.status_code == 200 and 'Drupal' in drupalCopyrightCheck.text and '404' not in drupalCopyrightCheck.text:
				self.provider = 'Drupal'
				self.results.update({'provider': self.provider})
				self.pages.update({'copyright': self.schema + self.hostname + '/core/COPYRIGHT.txt'})

			if self.log_level > 1:
				print("			%s| Checking for %sDrupal modules readme file" % (fg(158), fg(15)))	

			drupalReadme2Check = requests.get(self.schema + self.hostname + '/modules/README.txt')
			if drupalReadme2Check.status_code == 200 and 'drupal' in drupalReadme2Check.text and '404' not in drupalReadme2Check.text:
				self.provider = 'Drupal'
				self.results.update({'provider': self.provider})
				self.pages.update({'modules': self.schema + self.hostname + '/modules/README.txt'})
		except Exception as e:
			pass
		
		if len(self.pages) > 0:
			self.results.update({'results': self.pages})

	def get_users(self):
		if self.provider == 'Wordpress':
			if self.log_level > 1:
				print("		%s| Getting CMS users" % (fg(43)))
				
			users = []
			req = urllib.request.Request(self.schema + self.hostname + '/wp-json/wp/v2/users', headers={"User-Agent": "Chrome"})
			url = urllib.request.urlopen(req)

			try:
				for n in json.loads(url.read()):
					users.append({
						'id': n['id'],
						'name': n['name'],
						'slug': n['slug'],
						'link': n['link']
					})	
			except Exception as e:
				pass
			
			if len(users) > 0:
				self.results.update({'users': users})
	
	def get_plugins(self):
		if self.provider == 'Wordpress':
			if self.log_level > 1:
				print("		%s| Getting CMS plugins" % (fg(43)))

			if path.exists("wp_plugins.txt"):
				file = open("wp_plugins.txt")
				plugins = file.read().split("\n")
				list = []

				for plugin in plugins:
					try:
						plug_path = self.schema+self.hostname+"/wp-content/plugins/"+plugin	
						p = requests.get(url=plug_path)						
						if 200 == p.status_code or 403 == p.status_code:
							list.append(plug_path.split("/")[-1])
					except Exception as e:
						pass

				file.close()

				if len(list) > 0:
					self.results.update({'plugins': list})
			else:
				raise Exception("wp_plugins.txt file is missing")

	def get_theme(self):
		if self.provider == 'Wordpress':			
			if self.log_level > 1:
				print("		%s| Getting CMS theme" % (fg(43)))

			req = requests.get(url = self.schema+self.hostname, headers = {'User-Agent': 'Firefox'})
			soup = BeautifulSoup(req.text, 'html5lib')
			default_theme = ''

			for n in soup.find_all('link'):
				if '/wp-content/themes' in n.get('href'):
					theme = n.get('href')
					theme = theme.split('/')
					if 'themes' in theme:
						pos = theme.index('themes')
						t = theme[pos+1]
						if 'child' in t:
							default_theme = t
							break
						else:
							default_theme = t

			if len(default_theme) > 0:
				self.results.update({'theme': default_theme})

	def scan(self):
		if self.log_level != 0:
			print("	%s[%s+%s] Performing a %sCMS %sscan" % (fg(45), fg(46), fg(45), fg(15), fg(45)))

		while self.provider is None:
			self.wpscan()	
			self.joomlascan()
			self.magentoscan()
			self.drupalscan()

			if self.provider is None:
				self.provider = 'undefined'
				self.results.update({'provider': self.provider})
				break		

		self.get_users()
		self.get_theme()

		if self.intense_scan:
			self.get_plugins()

		return self.results

class WHOIS(object):
	def __init__(self, hostname, log_level=0):
		if re.match(r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+", hostname):
			self.hostname = hostname.strip()
			self.log_level = log_level
		else:
			raise Exception("that's not a valid hostname")

	def get(self):
		try:
			if self.log_level != 0:
				print("	%s[%s+%s] Performing a %sWhois %sscan" % (fg(45), fg(46), fg(45), fg(15), fg(45)))

			results = {}
			domain = whois.whois(self.hostname)
			for n in domain:
				if domain[n] is not None:
					results.update({n: domain[n]})

			return results
		except Exception as e:
			raise Exception("error retrieving WHOIS information")

class Wappa(object):
	def __init__(self, hostname, log_level=0):
		if re.match(r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+", hostname):
			self.hostname = hostname.strip()
			self.schema = 'http://'
			self.user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36'}
			self.log_level = log_level
		else:
			raise Exception("that's not a valid hostname")

	def get(self):
		try:
			if self.log_level != 0:				
				print("	%s[%s+%s] Performing a %sTechnologies %sscan" % (fg(45), fg(46), fg(45), fg(15), fg(45)))

			w = Wappalyzer()
			return w.analyze(self.schema + self.hostname)
		except Exception as e:
			raise Exception("error recovering used technology")

class LOC(object):
	def __init__(self, ip, log_level=0):
		if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
			self.ip = ip
			self.log_level = log_level
		else:
			raise Exception("that's not a valid IP address")

	def get(self):
		if self.log_level != 0:
			print("	%s[%s+%s] Performing a %sLocation %sscan" % (fg(45), fg(46), fg(45), fg(15), fg(45)))

		result = {}
		data = urllib.urlopen("https://ipinfo.io/{}/json".format(self.ip))
		data = json.loads(data.read())
		for d in data:
			if d != 'readme':
				result.update({d: data[d]})

		return result

class Subdomains(object):
	def __init__(self, hostname, log_level=0):
		if re.match(r"[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+", hostname):
			self.hostname = hostname.strip()
			self.log_level = log_level
		else:
			raise Exception("that's not a valid hostname")

	def get(self):
		if self.log_level != 0:
			print("	%s[%s+%s] Performing a %sSubdomain %sscan" % (fg(45), fg(46), fg(45), fg(15), fg(45)))
				
		if path.exists("subdomains.txt"):				
			file = open("subdomains.txt", "r")
			subdomains = file.read().split("\n")
			list = []

			for f in subdomains:
				try:					
					a = dns.resolver.query("{}.{}".format(f, self.hostname), "A")
					list.append("{}.{}".format(f, self.hostname))
				except Exception as e:
					pass

			file.close()

			return list
		else:
			raise Exception("subdomains.txt file is missing")



def banner():
	light = 175
	dark = 197
	
	system('clear')

	print("")
	print("                 %sx%s.    %s.                  %s.%sd``                     " % (fg(dark), fg(light), fg(light), fg(dark), fg(light)))
	print("       %su%sL       %s8%s88k  %sz%s88u         %su      %s@%s8Ne.   %s.%su         %su     " % (fg(dark), fg(light), fg(dark), fg(light), fg(dark), fg(light), fg(dark), fg(dark), fg(light),fg(dark), fg(light), fg(light)))
	print("   %s.u%se888Nc..   %s8%s888  %s8%s888      %su%ss888u.   %s8%s8888:u@88N     %su%ss888u.  " % (fg(dark), fg(light), fg(dark), fg(light), fg(dark), fg(light), fg(dark), fg(light), fg(dark), fg(light), fg(dark), fg(light)) )
	print("  %sd%s88E`\"888E`   %s8%s888  %s8%s88R   %s.@%s88  %s8%s888\"   %s`%s888I  %s8%s88.  %s.@%s88  %s8%s888\" " % (fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light)))
	print("  %s8%s88E  %s8%s88E    %s8%s888  %s8%s88R   %s9%s888  %s9%s888     %s8%s88I  %s8%s88I  %s9%s888  %s9%s888  " % (fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light)))
	print("  %s8%s88E  %s8%s88E    %s8%s888  %s8%s88R   %s9%s888  %s9%s888     %s8%s88I  %s8%s88I  %s9%s888  %s9%s888  " % (fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light)))
	print("  %s8%s88E  %s8%s88E    %s8%s888 %s,%s888B   %s9%s888  %s9%s888   %su%sW888L  %s8%s88'  %s9%s888  %s9%s888  " % (fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light)))
	print("  %s8%s88& %s.%s888E   %s\"%s8888Y %s8%s888\"  %s9%s888  %s9%s888  %s'*%s88888Nu88P   %s9%s888  %s9%s888  " % (fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light)))
	print("  %s*%s888\" %s8%s88&    %s`%sY\"   %s'%sYP    %s\"%s888*\"%s\"%s888\" ~ %s'%s88888F`     %s\"%s888*%s\"\"%s888\"  " % (fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light)))
	print("   %s`%s\"   %s\"%s888E                 %s^%sY\"   %s^%sY'     %s8%s88 ^       %s^%sY\"   %s^%sY'  " % (fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light)))
	print("  %s.%sdWi   %s`%s88E                               %s*%s8E                    " % (fg(dark), fg(light),fg(dark), fg(light),fg(dark), fg(light)))
	print("  %s4%s888~  %sJ%s8P                                %s'%s8>                    " % (fg(dark), fg(light),fg(dark), fg(light), fg(dark), fg(light)))
	print("   %s^%s\"===*\"`                                  \"                     " % (fg(dark), fg(light)))
	print("")
	print("   %s------%s-- [ Guapa %sScan v1.0.0 - %sBy okBo%somer 2%s020 ] --%s------\n" % (fg(196),fg(208),fg(226),fg(118),fg(45),fg(19),fg(5)))

def arg_parser():
	parser = argparse.ArgumentParser(description="Find information about a hostname or ip address")
	parser.add_argument('-t', '--target', type=str, required=True, action='store', help='target to get info')
	parser.add_argument('-l', '--log', type=int, required=False, default=0, action='store', help='log level | 1=general response | 2=specific response')	
	parser.add_argument('-o', '--output', type=str, required=False, action='store', help='path to output the json response')
	parser.add_argument('-i', '--intense', default=False, action='store_true', help='intense scan')
	parser.add_argument('-s', '-scan', type=str, required=False, action='store', default='all', help="type of scans to perform [dns|whois|loc|cms|technologies|subdomains] comma separated")

	return parser.parse_args()

def output_print(data):
	if data.has_key('ip'):
		print("%s [+] IP: {}".format(data['ip']) % fg(15))

	if data.has_key('loc') and len(data["loc"]) > 0:
		time.sleep(0.5)
		print(" [+] Location")
		for n in data['loc']:
			time.sleep(0.5)
			loc_data = data['loc'][n].encode('utf-8')			
			print("    {}: {}".format(n, loc_data))

	if data.has_key('dns') and len(data["dns"]) > 0:
		time.sleep(0.5)
		print(" [+] DNS")
		for n in data['dns']:
			if data['dns'].has_key(n):
				time.sleep(0.5)
				if len(data["dns"][n]) == 1:
					dns_data = data["dns"][n][0].encode('utf-8')
					print("    {} record: {}".format(n, dns_data))
				else:
					print("    {} record: ".format(n))
					for i in data['dns'][n]:
						print("        {}".format(i))

	if data.has_key("cms") and len(data["cms"]) > 0:
		time.sleep(0.5)
		print(" [+] CMS")		

		if data["cms"].has_key("provider"):
			time.sleep(0.5)
			print("    provider: {}".format(data["cms"]["provider"]))

		if data["cms"].has_key("theme"):
			time.sleep(0.5)
			print("    theme: {}".format(data["cms"]["theme"]))			
		
		if data["cms"].has_key("results") and len(data["cms"]["results"]) > 0:
			for r in data["cms"]["results"]:
				time.sleep(0.5)
				results_data = data["cms"]["results"][r].encode('utf-8')				
				print("    {}: {}".format(r, results_data))

		if data["cms"].has_key("plugins") and len(data["cms"]["plugins"]) > 0:
			time.sleep(0.5)
			print("    plugins: ")
			for plug in data["cms"]["plugins"]:
				time.sleep(0.5)
				print("        {}".format(plug))

		if data["cms"].has_key("users") and len(data["cms"]["users"]) > 0:
			time.sleep(0.5)
			print("    users: ")
			for user in data["cms"]["users"]:				
				for user_prop in user:
					time.sleep(0.5)
					user_data =  str(user[user_prop]).encode('utf-8')
					print("        {}: {}".format(user_prop, user_data))

				if len(data["cms"]["users"]) > 1:
					print("\n")

	if data.has_key("whois") and len(data["whois"]) > 0:
		time.sleep(0.5)
		print(" [+] WHOIS")
		for w in data["whois"]:
			time.sleep(0.5)
			if isinstance(data["whois"][w], list):			
				print("    {}:".format(w))
				for wp in data["whois"][w]:
					time.sleep(0.5)
					print("        {}".format(wp))
			else:
				whois_data = data["whois"][w]
				if isinstance(whois_data, str) and whois_data.find('%') != -1:
					whois_data = urllib2.unquote(whois_data)
					whois_data = whois_data.replace('%u','\\u').decode('unicode_escape')
					whois_data = whois_data.encode('utf-8')
								
				print("    {}: {}".format(w, whois_data))

	if data.has_key("technologies") and len(data["technologies"]) > 0:
		time.sleep(0.5)
		print(" [+] Technologies")
		for tech in data["technologies"]:
			time.sleep(0.5)
			if data["technologies"][tech].has_key("version") and data["technologies"][tech]["version"] != "":				
				print("    {} ~ {}".format(tech, data["technologies"][tech]["version"]))
			else:
				print("    {}".format(tech))

	if data.has_key("subdomains") and len(data["subdomains"]) > 0:
		time.sleep(0.5)
		print(" [+] Subdomains")
		for sub in data["subdomains"]:
			time.sleep(0.5)
			print("    {}".format(sub))

def output_print2(data):
	if data.has_key('ip'):
		print((" %s%s IP Address %s%s▶   %s{}\n".format(data['ip'])) %(fg(232), bg(196), bg(0), fg(196), fg(196)))

	if data.has_key('loc') and len(data["loc"]) > 0:
		time.sleep(0.5)
		print(" %s%s Location %s%s▶%s" %(fg(232), bg(202), bg(0), fg(202), fg(15)))
		for n in data['loc']:
			loc_data = data['loc'][n]
			spaces = ""
			if len(n) < 10:
				for i in range(0, 10-len(n)):
					spaces = spaces + " "
				loc_data = (spaces + data['loc'][n]).encode('utf-8')

			time.sleep(0.5)
			print(("    %s%s {} %s %s{}".format(n, loc_data)) %(fg(232), bg(208), bg(0), fg(208)))

	if data.has_key('dns') and len(data["dns"]) > 0:
		time.sleep(0.5)
		print("\n %s%s DNS %s%s▶%s" %(fg(232), bg(226), bg(0), fg(226), fg(15)))
		for n in data['dns']:
			if data['dns'].has_key(n):				
				if len(data["dns"][n]) == 1:
					dns_data = data["dns"][n][0]
					spaces = ""
					if len(n) < 3:
						for i in range(0, 3-len(n)):
							spaces = spaces + " "
						dns_data = (spaces + data["dns"][n][0]).encode('utf-8')

					time.sleep(0.5)
					print(("    %s%s {} %s%s {}%s".format(n, dns_data)) %(fg(232), bg(228), bg(0), fg(228), bg(0)))
				else:
					time.sleep(0.5)
					print(("    %s%s {} %s".format(n)) %(fg(232), bg(228), bg(0)))
					for i in data['dns'][n]:
						time.sleep(0.5)
						print(("%s%s          {}".format(i)) % (bg(0), fg(228)))

	if data.has_key("cms") and len(data["cms"]) > 0:
		time.sleep(0.5)
		print("\n %s%s CMS %s%s▶ %s" %(fg(232), bg(118), bg(0), fg(118), fg(15)))
		time.sleep(0.5)
		print(("    %s%s provider %s%s {}".format(data["cms"]["provider"])) %(fg(232), bg(120), bg(0), fg(120)))
		if data["cms"].has_key("theme"):
			time.sleep(0.5)
			print(("    %s%s theme %s%s    {}".format(data["cms"]["theme"])) %(fg(232), bg(120), bg(0), fg(120)))
		
		if data["cms"].has_key("results") and len(data["cms"]["results"]) > 0:
			for r in data["cms"]["results"]:
				results_data = data["cms"]["results"][r]
				spaces = ""
				if len(r) < 8:
					for i in range(0, 8-len(r)):
						spaces = spaces + " "
					results_data = (spaces + data["cms"]["results"][r]).encode('utf-8')

				time.sleep(0.5)
				print(("    %s%s {} %s%s {}".format(r, results_data)) %(fg(232), bg(120), bg(0), fg(120)))

		if data["cms"].has_key("plugins") and len(data["cms"]["plugins"]) > 0:
			time.sleep(0.5)
			print("    %s%s plugins %s%s" %(fg(232), bg(120), bg(0), fg(15)))
			for plug in data["cms"]["plugins"]:
				time.sleep(0.5)
				print(("%s%s               {}".format(plug)) % (bg(0), fg(120)))

		if data["cms"].has_key("users") and len(data["cms"]["users"]) > 0:
			time.sleep(0.5)
			print("    %s%s users %s%s" %(fg(232), bg(120), bg(0), fg(15)))
			for user in data["cms"]["users"]:				
				for user_prop in user:
					user_data = user_prop
					spaces = ""
					if len(user) < 5:
						for i in range(0, 5-len(user_prop)):
							spaces = spaces + " "
						user_data = (spaces + str(user[user_prop])).encode('utf-8')

					time.sleep(0.5)
					print(("       %s%s {} %s%s {}".format(user_prop, user_data)) % (bg(121), fg(232), bg(0), fg(121)))

				if len(data["cms"]["users"]) > 1:
					print("\n")
	
	if data.has_key("whois") and len(data["whois"]) > 0:
		time.sleep(0.5)
		print("\n %s%s WHOIS %s%s▶%s" %(fg(232), bg(45), bg(0), fg(45), fg(15)))
		for w in data["whois"]:
			if isinstance(data["whois"][w], list):			
				time.sleep(0.5)	
				print(("    %s%s {} %s%s".format(w)) %(fg(232), bg(45), bg(0), fg(45)))
				for wp in data["whois"][w]:
					time.sleep(0.5)
					print(("%s%s                   {}".format(wp)) % (bg(0), fg(45)))
			else:
				whois_data = data["whois"][w]
				spaces = ""
				if len(w) < 12:
					for i in range(0, 12-len(w)):
						spaces = spaces + " "

					whois_data = (spaces + data["whois"][w]).encode("utf-8")

				time.sleep(0.5)

				if isinstance(whois_data, str) and whois_data.find('%') != -1:
					whois_data = urllib2.unquote(whois_data)
					whois_data = whois_data.replace('%u','\\u').decode('unicode_escape')
					whois_data = whois_data.encode('utf-8')
								
				print(("    %s%s {} %s%s {}".format(w, whois_data)) %(fg(232), bg(45), bg(0), fg(45)))		
		
	if data.has_key("technologies") and len(data["technologies"]) > 0:
		time.sleep(0.5)
		print("\n %s%s Technologies %s%s▶%s" %(fg(15), bg(21), bg(0), fg(21), fg(15)))
		for tech in data["technologies"]:
			if data["technologies"][tech].has_key("version") and data["technologies"][tech]["version"] != "":
				time.sleep(0.5)
				print(("%s%s                   {} ~ {}".format(tech, data["technologies"][tech]["version"])) % (bg(0), fg(33)))
			else:
				time.sleep(0.5)
				print(("%s%s                   {}".format(tech)) % (bg(0), fg(33)))
	
	if data.has_key("subdomains") and len(data["subdomains"]) > 0:
		time.sleep(0.5)
		print("\n %s%s Subdomains %s%s▶%s" %(fg(15), bg(5), bg(0), fg(5), fg(15)))
		for sub in data["subdomains"]:
			time.sleep(0.5)
			print(("%s%s                   {}".format(sub)) % (bg(0), fg(13)))

def get_data(arg):
	ip = IP(arg.target, log_level=arg.log).get()
	if arg.s == 'all':
		data = { 
			'ip': ip,
			'dns': DNS(arg.target, log_level=arg.log).get(),
			'whois': WHOIS(arg.target, log_level=arg.log).get(),
			'loc': LOC(ip, log_level=arg.log).get(),
			'cms': CMSSCAN(arg.target, log_level=arg.log, intense_scan=arg.intense).scan(),
			'technologies': Wappa(arg.target, log_level=arg.log).get()
		}

		if arg.intense:
			data.update({'subdomains': Subdomains(arg.target, log_level=arg.log).get() })
	else:
		data = {'ip': ip}
		for scan in arg.s.split(","):
			if scan == 'dns':
				data.update({'dns': DNS(arg.target, log_level=arg.log).get()})
			elif scan == 'whois':
				data.update({'whois': WHOIS(arg.target, log_level=arg.log).get()})
			elif scan == 'loc':
				data.update({'loc': LOC(ip, log_level=arg.log).get()})
			elif scan == 'cms':
				data.update({'cms': CMSSCAN(arg.target, log_level=arg.log, intense_scan=arg.intense).scan()})
			elif scan == 'technologies':
				data.update({'technologies': Wappa(arg.target, log_level=arg.log).get()})
			elif scan == 'subdomains':
				if arg.intense:
					data.update({'subdomains': Subdomains(arg.target, log_level=arg.log).get() })
				else:
					raise Exception("You have to specify the intense scan option with this scan type")
			else:
				continue

	return data

def main():
	banner()
	arg = arg_parser()

	if arg.intense:
		print(" %s[%s+%s] Warning: %sYou have chosen an %sintense scan. %sThis option will take %ssome time to be completed%s.\n" % (fg(208), fg(196), fg(208), fg(15), fg(208), fg(15), attr(4), attr(0)))

	if arg.log == 0:
		print(" %s[%s+%s] Wait until the scan will be complete...%s%s" % (fg(45), fg(46), fg(45), fg(15), bg(0)))

	data = get_data(arg)	

	print("\n %s[%s+%s] Scan completed\n" % (fg(46), fg(85), fg(46)))

	if arg.output:
		with open(arg.output, "w+") as f:
			json.dump(data, f, ensure_ascii=False, indent=4, default=json_util.default)
	else:
		output_print(data)
	


if __name__ == '__main__':
	try:
		main()
	except Exception as ex:
		msg = "\n %s[%s+%s] Error: %s{}\n".format(str(ex))
		print(msg % (fg(9), fg(208), fg(9), fg(15)))
		exit()
	except KeyboardInterrupt as e:
		exit()


