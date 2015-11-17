import requests
from outputs import OutputTypes
from sys import exit, argv
import argparse 
import csv
import re

parser= argparse.ArgumentParser(description='desc')
parser.add_argument("-t","--target", nargs='*',help="Target IP")
parser.add_argument("-k","--key",nargs='?',help="API key")
parser.add_argument("-u","--user", nargs='?', help="API user")
parser.add_argument("-c",'--csv',nargs="?",help="CSV file as the output")
args=parser.parse_args()

'''apiuser=''
apikey=''
'''
query_api_url="https://api.threatstream.com/api/v2"
resource='intelligence'

def callurl(urltouse,pos):
	try:
		http_req=requests.get(urltouse, headers={'ACCEPT':'application/json, text/html'})
		if http_req.status_code==200:
			rblob=http_req.json()['objects']
			if args.csv and pos==0:
				output_obj= OutputTypes(args.csv, rblob)
				output_obj.csvoutfile()
			elif args.csv and pos>0:
				output_obj=OutputTypes(args.csv, rblob)
				output_obj.csvoutfile()
		elif http_req.status_code == 401:
			print 'Check API credentials, access has been denied'
		else:
			print 'API connection failure. Status code: {}'.format(http_req.status_code)
	except Exception as err:
		print 'API access error: {}'.format(err)
		exit(0)

ips=[]
if len(args.target)>1:
	for i in range(0,len(args.target)):
		ips.append(args.target[i])
else:
	ips.append(args.target[0])

for j in range(0, len(ips)):
	ipregfind=re.search("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ips[j])
	cidregfind=re.search("^\d{1,3}\.\d{1,3}\.$", ips[j])
	if ipregfind is not None:
		url= '{}/{}/?username={}&api_key={}&ip={}'.format(query_api_url,resource,apiuser,apikey,ips[j])
		callurl(url,j)
	elif cidregfind is not None:
		url='{}/{}/?username={}&api_key={}&q=(status="active")and(value startswith "{}")'.format(query_api_url,resource,apiuser,apikey,ips[j])
		callurl(url,j)
	else:
		print ips[j], "inavlid input"
		exit(0)