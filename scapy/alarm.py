#! /usr/bin/python

from scapy.all import *


import sys


alert_number = 0
intrface = "eth0"

def raise_alert(incident, p, alert_number):
	global alert_number
	alert_number += 1
	print ('ALERT #%d: %s is detected from %s (%s) (%s)!'.format(alert_number, incident, p[IP].src, p[IP].proto, p[Raw].load))

def raise_alert_decode(incident, p, alert_number):
	alert_number += 1
	temp = base64.b64decode(p[Raw].load)
	print ('ALERT #%d: %s is detected from %s (%s) (%s)!'.format(alert_number, incident, p[IP].src, p[IP].proto, temp))


def help_interface():
	x = '  '
	print ('usage: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]\n')
	print ('A network sniffer that identifies basic vulnerabilities\n')
	print ('optional arguments:')
	print (x + '-h, --help    show this help message and exit')
	print (x + '-i INTERFACE  Network interface to sniff on')
	print (x + 'A PCAP file to read')

def checkNull(p):
	if p[TCP].flags == "":
		return true
	return false

def checkFin(p):
	if p[TCP].flags == "F":
		return true
	return false

def checkXmas(p):
	if p[TCP].flags == "FPU":
		return true
	return false

def checkPassword(p):
	if p.haslayer(Raw):
		try:
			temp = base64.b64decode(p[Raw].load)
			if "USER" in temp:
				raise_alert_decode("Username and password sent in the clear", p, alert_number)
			if "PASS" in temp:
				raise_alert_decode("Username and password sent in the clear", p, alert_number)
			if "USER" in p[Raw].load:
				raise_alert("Username and password sent in the clear", p, alert_number)
			if "PASS" in p.[Raw].load:
				raise_alert("Username and password sent in the clear", p, alert_number)

def checkCreditCard(p):
	temp = p[Raw].load
	visa = re.search('(?:\D|^)(4[0-9]{3}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)', temp, re.IGNORECASE)
	master = re.search('(?:\D|^)(5[1-5][0-9]{2}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)', temp, re.IGNORECASE)
	discover = re.search('(?:\D|^)((?:6011)(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)', temp, re.IGNORECASE)
	america = re.search('(?:\D|^)((?:3)[0-9]{3}(?:\ |\-|)[0-9]{6}(?:\ |\-|)[0-9]{5})(?:\D|$)', temp, re.IGNORECASE)

	if visa == true || master == true || discover == true || america == true:
		return true
	else:
		return false


def checkNmap(p):
	if p.haslayer(Raw):
		try:
			temp = base64.b64decode(p[Raw].load)
			if re.search('nmap', temp, re.IGNORECASE):
				raise_alert_decode("Nmap scan", p, alert_number)
			if re.search('nmap', p[Raw].load, re.IGNORECASE):
				raise_alert("Nmap scan", p, alert_number)

def checkNikto(p):
	if p.haslayer(Raw):
		try:
			temp = base64.b64decode(p[Raw].load)
			if re.search('nikto', temp, re.IGNORECASE):
				raise_alert_decode("Nikto scan", p, alert_number)
			if re.search('nikto', p[Raw].load, re.IGNORECASE):
				raise_alert("Nikto scan", p, alert_number)


def checkMasscan(p):
	if p.haslayer(Raw):
		try:
			temp = base64.b64decode(p[Raw].load)
			if re.search('masscan', temp, re.IGNORECASE):
				raise_alert_decode("Masscan", p, alert_number)
			if re.search('masscan', p[Raw].load, re.IGNORECASE):
				raise_alert("Masscan", p, alert_number)

def checkShellshock:
	if p.haslayer(ICMP):
		if p[ICMP].type == echo-request || p[ICMP].type == echo-reply:
			raise_alert("Shellshock", p, alert_number)

def checkphpMyAdmin(p):
	if p.haslayer(Raw):
		try:
			temp = base64.b64decode(p[Raw].load)
			if re.search('phpmyadmin', temp, re.IGNORECASE) || re.search('mysql', temp, re.IGNORECASE):
				raise_alert_decode("Someone accessing phpMyAdmin", p, alert_number)
			if re.search('phpmyadmin', p[Raw].load, re.IGNORECASE) || re.search('mysql', p[Raw].load, re.IGNORECASE):
				raise_alert("Someone accessing phpMyAdmin", p, alert_number)

def checkIncidents(p):
	if checkNull(p) == true:
		raise_alert('Null scan', p, alert_number)
	if checkFin(p) == true:
		raise_alert('Fin scan', p, alert_number)
	if checkXmas(p) == true:
		raise_alert('Xmas scan', p, alert_number)
	checkPassword(p)
	if checkCreditCard(p) == true:
		raise_alert('Credit card numbers sent in-the-clear', p, alert_number)
	checkNmap(p)
	checkNikto(p)
	checkMasscan(p)
	checkShellshock(p)
	checkphpMyAdmin(p)

if len(sys.argv) == 1:
	sniff(iface = intrface, prn = checkIncidents)
if str(sys.argv[1]) == '-h':
	help_interface()
if str(sys.argv[1]) == '-r':
	pkts = rdpcap(sys.argv[2])
	for p in pkts:
		checkIncidents(p)
if str(sys.argv[1]) == '-i':
	global intrface
	intrface = sys.argv[2]
	sniff(iface = intrface, prn = checkIncidents) 
