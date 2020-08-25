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
from scanners.ReverseIPLookupScan import ReverseIPLookupScan
from scanners.TraceScan import TraceScan

global version
version = "1.1.1"

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
	parser.add_argument('-k', '--key', type=str, required=False, action='store', help='wpvulndb.com API Key to find WordPress plugin vulnerabilities')
	parser.add_argument('-i', '--intense', default=False, action='store_true', help='intense scan')
	parser.add_argument('-s', '-scan', type=str, required=False, action='store', default='all', help="type of scans to perform [ip|dns|whois|traceroute|reverse_ip_lookup|loc|cms|technologies|subdomains] comma separated")

	return parser.parse_args()

def get_data(arg):
	ip = IPScan(arg.target, debug=arg.debug).get()

	if arg.s == 'all':
		data = { 
			'ip': ip,
			'dns': DNSScan(hostname=arg.target, debug=arg.debug).get(),
			'whois': WHOISScan(hostname=arg.target, debug=arg.debug).get(),
			'loc': LOCScan(ip=ip, debug=arg.debug).get(),
			'cms': CMSScan(hostname=arg.target, debug=arg.debug, intense=arg.intense, wpvuln_apikey=arg.key).scan(),
			'technologies': TechnologyScan(hostname=arg.target, debug=arg.debug).get(),
			'traceroute': TraceScan(ip, debug=arg.debug).get(),
			'reverse_ip_lookup': ReverseIPLookupScan(ip=ip, debug=arg.debug).scan()
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
				data.update({'cms': CMSScan(hostname=arg.target, debug=arg.debug, intense=arg.intense, wpvuln_apikey=arg.key).scan()} )
			elif scan == 'technologies':
				data.update({'technologies': TechnologyScan(hostname=arg.target, debug=arg.debug).get()})			
			elif scan == 'subdomains':
				if arg.intense:
					data.update({'subdomains': SubdomainScan(hostname=arg.target, debug=arg.debug).get() })
				else:
					raise Exception("You have to specify the intense scan option with this scan type")
			elif scan == 'traceroute':
				data.update({'traceroute': TraceScan(ip, debug=arg.debug).get()})
			elif scan == 'reverse_ip_lookup':
				data.update({'reverse_ip_lookup': ReverseIPLookupScan(ip=ip, debug=arg.debug).scan()})
			else:
				continue

	return data

def main():
	banner()
	arg = arg_parser()	

	print("\033[92m [+] \033[97mTargeting: \033[92m{}".format(arg.target))

	if arg.output:
		print("\033[96m [+] \033[97mSaving results on: \033[96m{}".format(arg.output))

	if arg.key:
		print("\033[96m [+] \033[97mWP Vuln API Key: \033[96m{}".format(arg.key))		

	if arg.intense:
		print("\033[93m [+] \033[97mWarning: You have chosen an intense scan. This option will take some time to be completed.")

	if arg.debug == 0:
		print("\033[96m [+] \033[97mWait until the scan will be completed...")

	data = get_data(arg)

	print("\n\033[92m [+] \033[97mScan completed")

	if arg.output:
		with open(arg.output, "w+") as f:
			json.dump(data, f, ensure_ascii=True, indent=4, default=json_util.default)
	else:
		print(json.dumps(data, indent=4))
		

if __name__ == '__main__':
	try:		
		main()
	except Exception as ex:
		print("\033[91m [+] \033[97mError: {}".format(str(ex)))
		exit()
	except KeyboardInterrupt as e:
		exit()


