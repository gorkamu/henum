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

		self.results.update({'results': self.pages})

	def drupalscan(self):
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

		self.results.update({'results': self.pages})

	def get_users(self):
		if self.provider == 'Wordpress':
			if self.log_level > 1:
				print("		%s| Getting CMS users" % (fg(43)))
				
			users = []
			url = urllib.urlopen(self.schema + self.hostname + '/wp-json/wp/v2/users')
			for n in json.loads(url.read()):
				users.append({
					'id': n['id'],
					'name': n['name'],
					'slug': n['slug'],
					'link': n['link']
				})				

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
			#self.joomlascan()
			#self.magentoscan()
			#self.drupalscan()

			if self.provider is None:
				self.provider = 'undefined'
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
				
			if len(list):
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
	parser.add_argument('-l', '--log', type=int, required=True, action='store', help='log level')
	parser.add_argument('-i', '--intense', default=False, action='store_true', help='intense scan')
	parser.add_argument('-o', '--output', type=str, required=False, action='store', help='path to output the json response')

	return parser.parse_args()

def main():
	banner()
	arg = arg_parser()

	#output_print(1)
	#exit()

	if arg.intense:
		print(" %s[%s+%s] Warning: %sYou have chosen an %sintense scan. %sThis option will take %ssome time to be completed%s.\n" % (fg(208), fg(196), fg(208), fg(15), fg(208), fg(15), attr(4), attr(0)))
	
	ip = IP(arg.target, log_level=arg.log).get()
	
	data = { 
		'ip': ip,
		'dns': DNS(arg.target, log_level=arg.log).get(),
		'whois': WHOIS(arg.target, log_level=arg.log).get(),
		'loc': LOC(ip, log_level=arg.log).get(),
		'cms': CMSSCAN(arg.target, log_level=arg.log, intense_scan=arg.intense).scan(),
		#'technologies': Wappa(arg.target, log_level=arg.log).get()
	}

	if arg.intense:
		data.update({'subdomains': Subdomains(arg.target, log_level=arg.log).get() })

	print("\n %s[%s+%s] Scan completed\n" % (fg(46), fg(85), fg(46)))
	
	if arg.output:
		with open(arg.output, "w+") as f:
			json.dump(data, f, ensure_ascii=False, indent=4, default=json_util.default)
	else:
		output_print(data)
	

def output_print(data):
	if data['ip']:
		print((" %s%s IP Address %s%s▶ %s{}".format(data['ip'])) %(fg(232), bg(196), bg(0), fg(196), fg(15)))	

	if data['loc']:
		print(" %s%s Location %s%s▶%s" %(fg(232), bg(202), bg(0), fg(202), fg(15)))
		for n in data['loc']:
			print(("    %s%s {} %s %s{}".format(n, data['loc'][n])) %(fg(232), bg(208), bg(0), fg(15)))

	if data['dns']:
		print(" %s%s DNS %s%s▶%s" %(fg(232), bg(226), bg(0), fg(226), fg(15)))
		for n in data['dns']:
			if type(data['dns'][n]):
				print(("    %s%s {} %s".format(n)) %(fg(232), bg(228), bg(0)))
				for i in data['dns'][n]:
					print(("%s%s       {}".format(i)) % (bg(0), fg(15)))
			else:
				print(("    %s%s {} %s %s{}".format(n, data['dns'][n])) %(fg(232), bg(209), bg(0), fg(15)))

	if data["cms"]:
		print((" %s%s CMS %s%s▶ %s{}".format(data['cms']['provider'])) %(fg(232), bg(118), bg(0), fg(118), fg(15)))	
		if data["cms"]["theme"]:
			print(("    %s%s theme %s%s {}".format(data["cms"]["theme"])) %(fg(232), bg(120), bg(0), fg(15)))
		
		if data["cms"]["results"]:
			for r in data["cms"]["results"]:
				print(("    %s%s {} %s%s {}".format(r, data["cms"]["results"][r])) %(fg(232), bg(120), bg(0), fg(15)))

		#TODO: USERS
		#TODO: PLUGINS
		

if __name__ == '__main__':
	try:
		main()
	except Exception as ex:
		msg = "\n %s[%s+%s] Error: %s{}\n".format(str(ex))
		print(msg % (fg(9), fg(208), fg(9), fg(15)))
		exit()
	except KeyboardInterrupt as e:
		exit()


