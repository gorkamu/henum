#!/usr/local/bin python
#_*_ coding: utf8 _*_

import argparse
import json
import urllib2
import time
import unicodedata
from os import system
from bson import json_util

from scanners.IPScan import IPScan
from scanners.DNSScan import DNSScan
from scanners.WHOISScan import WHOISScan
from scanners.LOCScan import LOCScan
from scanners.SubdomainScan import SubdomainScan
from scanners.TechnologyScan import TechnologyScan
from scanners.CMSScan import CMSScan

global version
version = "1.1.0"

def banner():
	system('clear')

	print("""
	
 ██╗  ██╗ ███████╗ ███╗   ██╗ ██╗   ██╗ ███╗   ███╗
 ██║  ██║ ██╔════╝ ████╗  ██║ ██║   ██║ ████╗ ████║
 ███████║ █████╗   ██╔██╗ ██║ ██║   ██║ ██╔████╔██║
 ██╔══██║ ██╔══╝   ██║╚██╗██║ ██║   ██║ ██║╚██╔╝██║
 ██║  ██║ ███████╗ ██║ ╚████║ ╚██████╔╝ ██║ ╚═╝ ██║
 ╚═╝  ╚═╝ ╚══════╝ ╚═╝  ╚═══╝  ╚═════╝  ╚═╝     ╚═╝

 Henum Scan v.{} - By Gorkamu - 2020
	""".format(version))
	
def arg_parser():
	parser = argparse.ArgumentParser(description="Find information about a hostname or ip address")
	parser.add_argument('-t', '--target', type=str, required=True, action='store', help='target to get info')
	parser.add_argument('-d', '--debug', type=int, required=False, default=0, action='store', help='debug level | 1=general response | 2=specific response')	
	parser.add_argument('-o', '--output', type=str, required=False, action='store', help='path to output the json response')
	parser.add_argument('-i', '--intense', default=False, action='store_true', help='intense scan')
	parser.add_argument('-s', '-scan', type=str, required=False, action='store', default='all', help="type of scans to perform [dns|whois|loc|cms|technologies|subdomains] comma separated")

	return parser.parse_args()

def output_print(data):
	if data.has_key('ip'):
		print((" %s[%s+%s] IP: %s%s{}".format(data['ip'])) % (fg(45), fg(46), fg(45), bg(0), fg(15)))

	if data.has_key('loc') and len(data["loc"]) > 0:
		time.sleep(0.5)
		print(" %s[%s+%s] Location" % (fg(45), fg(46), fg(45)))
		for n in data['loc']:
			time.sleep(0.5)
			loc_data = data['loc'][n].encode('utf-8')			
			print("  %s| {}: %s{} %s".format(n.capitalize(), loc_data) % (fg(43), fg(15), fg(43)))

	if data.has_key('dns') and len(data["dns"]) > 0:
		time.sleep(0.5)
		print(" %s[%s+%s] DNS" % (fg(45), fg(46), fg(45)))
		for n in data['dns']:
			if data['dns'].has_key(n):
				time.sleep(0.5)
				if len(data["dns"][n]) == 1:
					dns_data = data["dns"][n][0].encode('utf-8')
					print("  %s| {} record: %s{} %s".format(n.upper(), dns_data) % (fg(43), fg(15), fg(43)))
				else:
					print("  %s+ {} record:".format(n.upper()) % (fg(43)))
					for i in data['dns'][n]:
						print("    %s| {}".format(i) % (fg(15)))

	if data.has_key("cms") and len(data["cms"]) > 0:
		time.sleep(0.5)
		print(" %s[%s+%s] CMS" % (fg(45), fg(46), fg(45)))

		if data["cms"].has_key("provider"):
			time.sleep(0.5)
			print("  %s| Provider: %s{} %s".format(data["cms"]["provider"]) % (fg(43), fg(15), fg(43)))

		if data["cms"].has_key("wp_version"):
			time.sleep(0.5)
			print("  %s| {} Version: %s{} %s".format(data["cms"]["provider"], data["cms"]["wp_version"]) % (fg(43), fg(15), fg(43)))

		if data["cms"].has_key("theme"):
			time.sleep(0.5)
			print("  %s| Theme: %s{} %s".format(data["cms"]["theme"]) % (fg(43), fg(15), fg(43)))
		
		if data["cms"].has_key("results") and len(data["cms"]["results"]) > 0:
			for r in data["cms"]["results"]:
				time.sleep(0.5)
				results_data = data["cms"]["results"][r].encode('utf-8')				
				print("  %s| {}: %s{} %s".format(r.capitalize(), results_data) % (fg(43), fg(15), fg(43)))

		if data["cms"].has_key("plugins") and len(data["cms"]["plugins"]) > 0:
			time.sleep(0.5)
			print("  %s+ Plugins: " % (fg(43)))
			for plug in data["cms"]["plugins"]:				
				time.sleep(0.5)		
				print("    %s + {}".format(plug["name"]) % (fg(15)))
				if plug.has_key("vulnerabilities") and len(plug["vulnerabilities"]) > 0:
					for vuln in plug["vulnerabilities"]:
						time.sleep(0.5)
						for prop in vuln:
							print("          %s| {}: %s{} %s".format(prop, vuln[prop]) % (fg(158), fg(15), fg(43)))
						print(" ")

		if data["cms"].has_key("users") and len(data["cms"]["users"]) > 0:
			time.sleep(0.5)
			print("  %s+ Users: " % (fg(43)))
			for user in data["cms"]["users"]:
				print("      %s+" % fg(43))
				for user_prop in user:
					user_data =  unicode(user[user_prop]).encode('utf8')
					print("          %s| {}: %s{} %s".format(user_prop, user_data) % (fg(158), fg(15), fg(43)))

	if data.has_key("whois") and len(data["whois"]) > 0:
		time.sleep(0.5)
		print(" %s[%s+%s] WHOIS" % (fg(45), fg(46), fg(45)))
		for w in data["whois"]:
			time.sleep(0.5)
			if isinstance(data["whois"][w], list):
				print("  %s+ {}".format(w.capitalize()) % (fg(43)))	
				for wp in data["whois"][w]:
					time.sleep(0.5)					
					print("    %s| {}".format(wp) % (fg(15)))	
			else:
				whois_data = data["whois"][w]
				if isinstance(whois_data, unicode):
					whois_data = unicodedata.normalize('NFKD', whois_data).encode('ascii', 'ignore')
					whois_data = urllib2.unquote(whois_data)
					whois_data = whois_data.replace('%u','\\u').decode('unicode_escape')
					whois_data = whois_data.encode('utf-8')
												
				print("  %s| {}: %s{} %s".format(w.capitalize(), whois_data) % (fg(43), fg(15), fg(43)))

	if data.has_key("technologies") and len(data["technologies"]) > 0:
		time.sleep(0.5)
		print(" %s[%s+%s] Technologies" % (fg(45), fg(46), fg(45)))
		for tech in data["technologies"]:
			time.sleep(0.5)
			if data["technologies"][tech].has_key("version") and data["technologies"][tech]["version"] != "":
				print("  %s| {} ~ %s{} %s".format(tech, data["technologies"][tech]["version"]) % (fg(43), fg(15), fg(43)))
			else:
				print("  %s| {}".format(tech) % fg(43))

	if data.has_key("subdomains") and len(data["subdomains"]) > 0:
		time.sleep(0.5)
		print(" %s[%s+%s] Subdomains" % (fg(45), fg(46), fg(45)))
		for sub in data["subdomains"]:
			time.sleep(0.5)
			print("  %s| {}".format(sub) % fg(43))

def get_data(arg):
	ip = IPScan(arg.target, debug=arg.debug).get()
	if arg.s == 'all':
		data = { 
			'ip': ip,
			'dns': DNSScan(hostname=arg.target, debug=arg.debug).get(),
			'whois': WHOISScan(hostname=arg.target, debug=arg.debug).get(),
			'loc': LOCScan(ip=ip, debug=arg.debug).get(),
			'cms': CMSScan(hostname=arg.target, debug=arg.debug, intense=arg.intense).scan(),
			'technologies': TechnologyScan(hostname=arg.target, debug=arg.debug).get()
		}

		if arg.intense:
			data.update({'subdomains': SubdomainScan(arg.target, debug=arg.debug).get() })
	else:
		data = {'ip': ip}
		for scan in arg.s.split(","):
			if scan == 'dns':
				data.update({'dns': DNSScan(hostname=arg.target, debug=arg.debug).get()})
			elif scan == 'whois':
				data.update({'whois': WHOISScan(hostname=arg.target, debug=arg.debug).get()})
			elif scan == 'loc':
				data.update({'loc': LOCScan(ip=ip, debug=arg.debug).get()})
			elif scan == 'cms':
				data.update({'cms': CMSScan(hostname=arg.target, debug=arg.debug, intense=arg.intense).scan()} )
			elif scan == 'technologies':
				data.update({'technologies': TechnologyScan(hostname=arg.target, debug=arg.debug).get()})
			elif scan == 'subdomains':
				if arg.intense:
					data.update({'subdomains': SubdomainScan(hostname=arg.target, debug=arg.debug).get() })
				else:
					raise Exception("You have to specify the intense scan option with this scan type")
			else:
				continue

	return data

def main():
	banner()
	arg = arg_parser()

	print("\033[92m [+] \033[97mTargeting: \033[92m{}".format(arg.target))

	if arg.output:
		print("\033[96m [+] \033[97mSaving results on: \033[96m{}".format(arg.output))

	if arg.intense:
		print("\033[93m [+] \033[97mWarning: You have chosen an intense scan. This option will take some time to be completed.")

	if arg.debug == 0:
		print("\033[96m [+] \033[97mWait until the scan will be completed...")

	data = get_data(arg)

	print("\n\033[92m [+] \033[97mScan completed")

	if arg.output:
		with open(arg.output, "w+") as f:
			json.dump(data, f, ensure_ascii=True, indent=4, default=json_util.default)
	#else:
		#output_print(data)
	


if __name__ == '__main__':
	try:
		main()
	except Exception as ex:
		print("\033[91m[+] \033[97mError: {}".format(str(ex)))
		exit()
	except KeyboardInterrupt as e:
		exit()


