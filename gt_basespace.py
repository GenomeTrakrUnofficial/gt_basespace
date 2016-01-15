#!/usr/bin/env python

import xmlrpclib
import requests
import datetime
import webbrowser
from time import sleep
import os
import shutil
from os.path import join as j
import sys
import platform
import gzip
import json
import zlib
import subprocess

class TextMessageDelegate():

	
	@staticmethod
	def open(url):
		print url
		print requests.post('https://api.twilio.com/2010-04-01/Accounts/AC3f7c357ce6c7d7e89779c1194df54697/Messages.json',
					  data={'From':'+14025133392', 'To':'2408995786', 'Body':url}, 
					  auth=('AC3f7c357ce6c7d7e89779c1194df54697', 'aa6932304a28f23e0eb09235f41b2c94'))
					  
					  
if '-token-only' not in sys.argv:					  
	webbrowser = TextMessageDelegate


server = xmlrpclib.ServerProxy('http://cfe1019692:8080')
gnome2 = "/Volumes/dna/gnome2/"

def_block_size = 20971520

if 'Darwin' in platform.system():
	gnome2 = "/Volumes/dna/gnome2/"
elif 'Linux' in platform.system():
	gnome2 = "/shared/gn2/"
else: #Windows
	gnome2 = "Z:/"
	
def sizeof_fmt(num):
    for x in ['bytes','KB','MB','GB','TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0

try:
	api_token = os.environ['BASESPACE']
except KeyError:
	api_token = "63ede5360bcf447a8f453e68f494e587"
	
class DownloadExitException(Exception):
	pass
	
class DownloadIncompleteException(Exception):
	pass
	
#SSL TLS1.1 monkeypatch, see
#http://stackoverflow.com/questions/14102416/python-requests-requests-exceptions-sslerror-errno-8-ssl-c504-eof-occurred?rq=1
#and
#https://bugs.launchpad.net/ubuntu/+source/openssl/+bug/965371
	
	
# import ssl
# from functools import wraps
# def sslwrap(func):
#     @wraps(func)
#     def bar(*args, **kw):
#         kw['ssl_version'] = ssl.PROTOCOL_TLSv1
#         return func(*args, **kw)
#     return bar
# 
# ssl.wrap_socket = sslwrap(ssl.wrap_socket)
# import requests

get = requests.get

def get_wrapper(endpoint, *args, **kwargs):
	try:
		return get(endpoint, *args, **kwargs)
	except:
		print "Get failed. Endpoint was:"
		print endpoint
		raise
		
requests.get = get_wrapper


def format_json(j, indent=0):
	"Convenience function for printing json objects."
	if isinstance(j, dict):
		print "  "*indent, "{"
		for (key, value) in j.iteritems():
			print "  "*indent, key+":"
			format_json(value, indent+1)
		print "  "*indent, "}"
	elif isinstance(j, list):
		print "  "*indent, "["
		for value in j:
			format_json(value, indent+1)
		print "  "*indent, "]"
	else:
		print "  "*indent, j
		
def get_api_key(callback=lambda l: None, oauth2=lambda r: r, debug=False, webbrowser=webbrowser):
	"API function to collect access key from BaseSpace. Webbrowser can be any object that implements an 'open' method that takes a URL as argument."
	callback("Collecting BaseSpace API key...")
	
	try:
		callback("Getting projects list")
		r3 = requests.get("https://api.basespace.illumina.com/v1pre3/users/current/projects?Limit=1024", auth=oauth2).json()
		callback("Requesting token")
		req = "https://api.basespace.illumina.com/v1pre3/oauthv2/deviceauthorization"
		data = {'client_id':'32bcf80e0ec2454aba86300b5babda39',
				'response_type':'device_code',
				'scope':", ".join(['browse global'] + ["read project {}".format(p['Id']) for p in r3['Response']['Items']])}
		#req = "https://api.basespace.illumina.com/v1pre3/oauthv2/deviceauthorization?client_id=32bcf80e0ec2454aba86300b5babda39&response_type=device_code&scope={}".format(", ".join(['browse global'] + ["read project {}".format(p['Id']) for p in r3['Response']['Items']]))
		#req = "https://api.basespace.illumina.com/v1pre3/oauthv2/deviceauthorization?client_id=32bcf80e0ec2454aba86300b5babda39&response_type=device_code&scope=browse global"		
		r = requests.post(req, data=data)
		r.raise_for_status()
		r = r.json()
	except Exception:
		format_json(r3)
		print req
		raise	
	
	if 'error' in r:
		raise ValueError(r['error'] + ": " + r['error_description'])
	
	webbrowser.open(r['verification_with_code_uri'])
	start_time = datetime.datetime.today()

	if debug:
		[sys.stdout.write("\n{:<30}".format(s)) for s in sample_names]

	callback("Waiting for user acceptance (code {})...".format(r['user_code']))
	now = datetime.datetime.now()
	while(1):
	
		sleep(r['interval'])
		r2 = requests.post("https://api.basespace.illumina.com/v1pre3/oauthv2/token"
						  "?client_id=32bcf80e0ec2454aba86300b5babda39"
						  "&client_secret=a7d4b110a38f4a259f2164a47bcc9c1e"
						  "&code={device_code}"
						  "&grant_type=device".format(**r)).json()
						  
		if datetime.datetime.now() - now > datetime.timedelta(minutes=30):
			raw_input("Waited too long; return to retry.")
			return get_api_key(callback, oauth2, debug, webbrowser)

		#print r2
		if 'error' in r2:
			if 'pending' in r2['error']:
				sys.stdout.write('.')
				sys.stdout.flush()
				continue
			if 'denied' in r2['error']:
				callback("User denied access request.")
				return
		elif 'access_token' in r2:
			token = r2['access_token']
			callback("accepted.")
			break
	
	callback('export BASESPACE="{}"'.format(token))
	
	try:
		with open("basespace_api.key", 'w') as keyfile:
			keyfile.write(token)
	except Exception as e:
		callback("Error writing api keyfile: {}".format(str(e)))
	
	def oauth2(request): #closure to handle OAuth2 authentication via returned token
		request.headers['x-access-token'] = token
		return request
	
	return oauth2
	
def search(callback=lambda s: None, download_progress_callback=lambda p, q: None, debug=False, webbrowser=webbrowser):
	"Main search function. Takes a pair of UI callbacks for status and progress reporting."
	# build exclusion list and search list
	exclusion_set = set()
	search_set = set()
# 	callback("Building search and exclusion lists.")
# 	key_list = server.query_cfsan("""
# FdaAccession IN 
# 	(SELECT FdaAccession FROM dbo.ENTRYTABLE 
# 	WHERE DataProviderToNCBI LIKE 'GenomeTrakr') 
# AND RawFile NOT LIKE '' 
# AND SequenceRunDate NOT LIKE '' 
# AND SequencingTechnology LIKE '%MiSeq%'
# 	""")
# 	for key in key_list:
# 		entry = server.get(key)
# 		try:
# 			for raw_file in entry['RawFile'].split(','):
# 				exclusion_set.add("{}:{}".format(raw_file, entry['SequenceRunDate']))
# 		except KeyError:
# 			try:
# 				for run in entry['Runs']:
# 					for raw_file in run['RawFile'].split(','):
# 						exclusion_set.add("{}:{}".format(raw_file, run['SequenceRunDate']))
# 			except:
# 				pass
# 		if key_list.index(key) % 100 == 0:
# 			download_progress_callback(key_list.index(key), len(key_list))
# 	key_list = server.query_cfsan("DataProviderToNCBI LIKE 'GenomeTrakr'")
# 	for key in key_list:
# 		entry = server.get(key)
# 		for token in ('StrainName', 'PrivateStrainSynonyms', 'NCBI_BioSample'):
# 			if entry[token]:
# 				for s in entry[token].split(','):
# 					search_set.add(s)
# 		if key_list.index(key) % 100 == 0:
# 			download_progress_callback(key_list.index(key), len(key_list))
# 			
# 	callback("{} sample identifiers to find, {} run-cells excluded.\n".format(len(search_set), len(exclusion_set)))
# 	
# 	if debug:
# 		for x in list(exclusion_set)[0:20]:
# 			print x
# 		for x in list(search_set)[0:20]:
# 			print x
# 		raw_input("Return to continue")		
# 	
	#build Oauth2 method and try it
	try:
		def oauth2(request):
			request.headers['x-access-token'] = api_token
			return request
		#Enumerate projects
		r1 = requests.get("https://api.basespace.illumina.com/v1pre3/users/current/projects?Limit=1024", auth=oauth2)
		r1.raise_for_status()
		r1 = r1.json()
	except (KeyError, UnboundLocalError, requests.HTTPError):
		oauth2 = get_api_key(callback, oauth2, debug, webbrowser)
		r1 = requests.get("https://api.basespace.illumina.com/v1pre3/users/current/projects?Limit=1024", auth=oauth2).json()
	except Exception:
		#Exception hook to print response object, if available, on failure
		if debug:
			try:
				json.dumps(r1, sort_keys=True, indent=4, separators=(',', ':'))
			except:
				pass
		raise
	
	#either we have a list structure of Projects or we've thrown something
	for project in r1['Response']['Items']:
		proj_id = project['Id']
		#get a list of samples in each project
		r2 = requests.get("https://api.basespace.illumina.com/v1pre3/projects/{}/samples?Limit=1024&SortBy=DateCreated&SortDir=Desc".format(proj_id), auth=oauth2).json()
		callback("{:<30}({:<7})  {:>3} samples".format(project["Name"], proj_id, len(r2['Response']['Items'])))
		for sample_stub in r2['Response']['Items']:
			try:
				sample = requests.get("https://api.basespace.illumina.com/v1pre3/samples/{}".format(sample_stub['Id']), auth=oauth2).json()['Response']
			except:
				callback("Exception on https://api.basespace.illumina.com/v1pre3/samples/{}".format(sample_stub['Id']))
				raise
			#if sample['SampleId'] in search_set or sample['Name'] in search_set:
			if len(server.query_cfsan("[BasespaceObjectID] LIKE '{Id}'".format(**sample))) == 0:
				r4 = requests.get("https://api.basespace.illumina.com/v1pre3/samples/{}/files?SortBy=DateCreated".format(sample['Id']), auth=oauth2).json()
				repeat = True
				retries = 0
				for i in range(0, len(r4['Response']['Items']), 2):
					file_right = r4['Response']['Items'][i]
					file_left = r4['Response']['Items'][i+1]
					if True: # ("{}:{}".format(file_right['Name'], sample['DateCreated'].split('T')[0]) not in exclusion_set) and ("{}:{}".format(file_left['Name'], sample['DateCreated'].split('T')[0]) not in exclusion_set): #files aren't in DB already
						while repeat: #repeat until successful or terminal error
							try:
								if file_right['Size'] < 1024 or file_left['Size'] < 1024:
									repeat = False
									raise DownloadExitException('File size is too small.')
								session_key = server.open_deferred_accept('', {}, False)
								if session_key:
									## if sample['Name'] in search_set: #need to be robust, different labs put the identifier we track in different parts of the sample sheet
# 										sample_name = sample['Name']
# 									#elif sample['SampleId'] in search_set:
									#	sample_name = sample['SampleId']
									sample_name = sample['Name']
									if server.find_cfsan(sample['Name']) or server.find_cfsan(sample['SampleId']):
										sample_name = server.find_cfsan(sample['Name']) or server.find_cfsan(sample['SampleId'])
									else:
										repeat = False
										raise DownloadExitException('Sample "{}" ({}) not identifiable in GenomicsDB (find_cfsan returned no results.)'.format(sample['Name'], sample['Id']))
									runid, path = server.deferred_accept(sample_name, {'data_type':'Illumina MiSeq sequence',
																					   'library_kit':'Nextera XT',
																					   'version':'RTA 1.18',
																					   'raw_file':'{},{}'.format(file_right['Name'], file_left['Name']),
																					   'job_type':'SPAdes',
																					   'k_value':'61',
																					   'trimmer':'basic_trimmer',
																					   'file0':file_right['Name'],
																					   'file1':file_left['Name'],
																					   'assemble':True},
																		  session_key)
									#if debug:
									#	raw_input("Return to continue")
									for file in (file_right, file_left):
										r4 = requests.get("https://api.basespace.illumina.com/v1pre3/files/{}/content".format(file['Id']), 
														  auth=oauth2, stream=True)
										r4.raise_for_status()
										zstream = zlib.decompressobj(16+zlib.MAX_WBITS)
										first_bytes = r4.iter_content(128).next()
										header = str(zstream.decompress(first_bytes))
										runcell = header.split("\n")[0].split(":")[2]
										if debug:
											print runcell, file['Name']
# 										prev_runs = server.query_cfsan("RunCell='{}' AND FdaAccession LIKE '{}' AND Basespace".format(runcell, server.find_cfsan(sample_name)))
# 										if len(prev_runs):
# 											#We actually do have these already, abort
# 											repeat = False
# 											try:
# 												prev = server.get(prev_runs[0])
# 												if prev['SequenceRunDate'] not in sample['DateCreated']:
# 													server.update_cfsan(prev_runs[0], 'SequenceRunDate', sample['DateCreated'].split('T')[0])
# 												if sample['Id'] not in prev['BasespaceObjectID']:
# 													server.update_cfsan(prev['KEY'], 'BasespaceObjectID', sample['Id'])
# 											except:
# 												import traceback
# 												callback(traceback.print_exc())
# 											raise DownloadExitException('Already downloaded. ({}:{})'.format(file['Name'], sample['DateCreated'].split('T')[0]))
											
										#make dirs if necessary
										if not os.path.exists(j(gnome2, path)):
											os.makedirs(j(gnome2, path))
										#download
										callback("Downloading {} ({} from {}, {})".format(file['Name'], runid, runcell, sizeof_fmt(file['Size'])))
										if debug:
											raw_input("Return to download {} to {}".format(file['Name'], path))
										num_blocks = 1
										with open(j(gnome2, path, file['Name']), 'wb') as fastq:
											fastq.write(first_bytes)
											for block in r4.iter_content(def_block_size):
												fastq.write(block)
												download_progress_callback(num_blocks * def_block_size, file['Size'])
												num_blocks += 1
											#File completion check
				
										try:
											subprocess.check_call("gzip -t {}".format(fastq.name), shell=True)
											if file['Size'] - os.stat(fastq.name).st_size > 0:
												print "File {} download terminated early ({} of {}). Retrying...".format(file['Name'], os.stat(fastq.name).st_size, file['Size'])
												raise DownloadIncompleteException()
											
										except (subprocess.CalledProcessError, DownloadIncompleteException):
											if retries > 3:
												repeat = False
												try:
													server.fire_event('CorruptBasespaceEvent', data={'sample_name':sample_name, 'cfsan_number':runid, 'filename':file['Name']})
												except:
													pass
												raise DownloadExitException("Maximum retries exceeded. Skipping {}...".format(sample['Name']))
											raise DownloadIncompleteException()
								
												
											
								else:
									callback("Couldn't link to sample in database. Aborting...")
									break
									
									
							except requests.HTTPError:
								oauth2 = get_api_key(callback, oauth2, debug, webbrowser)
								continue #while repeat
							except DownloadExitException as e:
								try:
									server.deferred_accept_rollback(session_key)
								except:
									pass
								if debug:
									print e
							except (IOError, OSError) as e:
								if e.errno == 104: #connection reset by peer
									callback("Connection reset by peer: retrying.")
									continue
								try:
									server.deferred_accept_rollback(session_key)
								except:
									pass
								callback("Session rolled back on exception: {}\n".format(e))	
								import traceback
								traceback.print_exc()
								if debug:
									raw_input("Return to continue.")
									
							except DownloadIncompleteException:
								retries += 1
									
							except IndexError as e:
								import traceback
								traceback.print_exc()
								try:
									print header
								except:
									pass
								print file_left
								print file_right
								try:
									server.deferred_accept_rollback(session_key)
									callback("Session rolled back on exception: {}\n".format(e))
								except:
									pass
								if debug:
									raw_input("Return to continue.")
								
							except (Exception, KeyboardInterrupt) as e:
								try:
									server.deferred_accept_rollback(session_key)
									callback("Session rolled back on exception: {}\n".format(e))
									print "Samplename:", sample_name
									print json.dumps(sample, indent=2)
									print json.dumps(r4, indent=2)
									print json.dumps(file_right)
									print json.dumps(file_left)
								except:
									pass
								raise
								#if debug:
							else:
								repeat = False
								try:
									server.close_deferred_accept(session_key)
								except xmlrpclib.Fault:
									try:
										server.deferred_accept_rollback(session_key)
									except:
										pass
									if debug:
										raise
								try:
									key = server.get(runid)['KEY']
									server.update_cfsan(key, 'SequenceRunDate', sample['DateCreated'].split('T')[0])
									try:
										for item in sample['Properties']['Items']:
											if 'Input.Runs' in item.get('Name', ''):
												for sub_item in item['Items']:
													server.update_cfsan(key, 'SequenceRunDate', sub_item['DateCreated'].split('T')[0])
													server.update_cfsan(key, 'SequencedBy', sub_item['UserOwnedBy']['Name'])
									except (KeyError, IndexError) as e:
										print "Couldn't get run reference."
										print e
									server.update_cfsan(key, 'RunCell', runcell)
									server.update_cfsan(key, 'RawFileSize', sizeof_fmt(sample['TotalSize']))
									server.update_cfsan(key, 'SequenceMachineID', header.split(':')[0].replace('@', ''))
									server.update_cfsan(key, 'BasespaceObjectID', sample['Id'])
								except TypeError:
									print "New RunID KEY retreival threw TypeError; server is probably in 'test' mode."
									if not debug:
										raise
								del session_key
			else:
				# run = server.get(server.query_cfsan("[BasespaceObjectID] LIKE '{Id}'".format(**sample))[0])
# 				key = run['KEY']
# 				#added this to collect information we didn't get on the first pass
# 				try:
# 					for item in sample['Properties']['Items']:
# 						if 'Input.Runs' in item.get('Name', ''):
# 							for sub_item in item['Items']:
# 								if sub_item['UserOwnedBy']['Name'] not in run['SequencedBy']:
# 									if debug:
# 										raw_input('{} Seq by {}'.format(key, sub_item['UserOwnedBy']['Name']))
# 									server.update_cfsan(key, 'SequenceRunDate', sub_item['DateCreated'].split('T')[0])
# 									server.update_cfsan(key, 'SequencedBy', sub_item['UserOwnedBy']['Name'])
# 				except (KeyError, IndexError) as e:
# 					if debug:
# 						print "Couldn't get run reference for sample {}".format(sample['Id'])
# 						print e
				if debug:
					print "{} {} excluded (dupe Object ID)".format(sample['SampleId'], sample['Name'])
							
		
	
if __name__ == "__main__":
	import sys
	import datetime
	#build UI callback functions
	def cb(s):
		sys.stdout.write("\n[{}] {}".format(datetime.datetime.today().ctime(), s))
		sys.stdout.flush()
		
	def dl_ucb(p, q):
		sys.stdout.write('.')
		sys.stdout.flush()
		
	if '-token-only' in sys.argv:
		global oauth2
		def oauth2(request):
			request.headers['x-access-token'] = api_token
			return request

		get_api_key(callback=cb, oauth2=oauth2)
		quit()
	
	#invoke search of basespace
	search(cb, dl_ucb, '-debug' in sys.argv)
