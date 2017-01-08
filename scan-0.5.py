#!/usr/bin/python3

# + a tester
# x testé

# TODO
# - arguments to nmap
# - Check same range than in rules

import re
import sys
import nmap
from optparse import OptionParser
from multiprocessing.dummy import Pool as ThreadPool

# Arguments ###################################################################
usage = "usage: %prog [options]"
parser = OptionParser(usage=usage)
#parser.add_option("-v", "--verbose",
#                  action="store_true", dest="verbose", default=True,
#                  help="make lots of noise [default]")
parser.add_option("-g", "--range", default="100",
                  action="store", 
                  help="Last port scanned. from 1 to [RANGE]")
parser.add_option("-i", "--ip", default="IPs.txt",
                  action="store", help="read IPs from IP")
parser.add_option("-r", "--rules",default="rules.txt",
                  action="store", help="read rules from RULES")
parser.add_option("-a", "--arguments",default="",
                  action="store", help="supplementary ARGUMENTS for nmap")
parser.add_option("-n", "--nthreads",default="4",
                  action="store", help="number of threads")
(options, args) = parser.parse_args()


begin = 1
end = int(options.range)
etendue = end

# Fonctions ###################################################################

def nmapScan(tgtHost, tgtPort=str(begin)+"-"+str(etendue)):
	

	nmScan = nmap.PortScanner()
	nmScan.scan(tgtHost, tgtPort, arguments = options.arguments)

	print(nmScan.command_line())

	resultats = {}
	
	if nmScan.all_hosts() == []:
		for port in range(int(begin),int(etendue)):
			resultats[str(port)] = "filtered"
		return([tgtHost,resultats])

	for port in nmScan[tgtHost]['tcp'].keys():
		resultats[port] = [nmScan[tgtHost]['tcp'][port]['state'], nmScan[tgtHost]['tcp'][port]['reason']]

	return([tgtHost,resultats])

# Lecture des rules ###########################################################

lines = [line.rstrip('\n').replace(" ","") for line in open(options.rules)]
lines = [line.rstrip('\t').replace(" ","") for line in lines]

try:
	lines.remove("")
except:
	pass

lines = [line.split(":") for line in lines]

rules = [None] * (etendue + 1)

pattern = re.compile("\\-")

for line in lines:
	if pattern.search(line[0]):
		begin, end = line[0].split("-")
		for ii in range(int(begin),int(end)+1):
			rules[ii] = line[1]
	else :
		rules[int(line[0])] = line[1]


for ii in range(1,etendue+1):
	try:
		error = True
		if rules[ii] == "closed":
			error = False  
		if rules[ii] == "open":
			error = False 
		if rules[ii] == "filtered":
			error = False 
		
		if error:
			raise Exception()
		
		a = str(ii) + " ; " + rules[ii]
		
	except :
		print("Port " + str(ii) + " Vide ou mauvais mot-clef")
		exit(1)

# Lecture des IPs #############################################################
lines = [line.rstrip('\n').replace(" ","") for line in open(options.ip)]
lines = [line.rstrip('\t').replace(" ","") for line in lines]

try :
	lines.remove("")
except:
	pass

correspondance = {}
for line in lines:
	if re.match(".*:.*",line) != None:
		ip, user = line.split(":")
		correspondance[ip] = user
	else:
		ip = line
		correspondance[ip] = "Not named"

ips = list(correspondance.keys())

# Scanning ####################################################################

resultats = {}

pool = ThreadPool(int(options.nthreads))

if options.arguments == "":
	res = pool.map(nmapScan, ips)
else:
	res = pool.map(nmapScan, ips)
	
pool.close() 
pool.join() 

for r in res:
	resultats[r[0]] = r[1]

for ip in resultats.keys():
	for port in range(1, etendue + 1):
		if port in resultats[ip].keys():
			pass
		else:
			resultats[ip][port] = ['filtered',"time-out"] 
		
# Comparaison #################################################################

for ip in resultats.keys():
	print("### " + ip + ", " + correspondance[ip] + " ####################")
	for port in range(1, etendue + 1):
		if rules[port] != resultats[ip][port][0]:
			print(str(port) + ": " + resultats[ip][port][0])
	print("")
