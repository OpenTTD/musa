#! /usr/bin/env python

from ConfigParser import ConfigParser
from tempfile import TemporaryFile
from optparse import OptionParser
from struct import pack, unpack
import tarfile
import ssl
import socket
import os
import glob
import re
from getpass import getpass
from tempfile import NamedTemporaryFile
from validate import validate

from exception import MusaException
from license import package_license
from misc import package_misc
from type import package_type
from text import package_text

def match_excluders(excluders, path):
	for excluder in excluders:
		if excluder.search(path):
			return True
	return False

def main():
	cmd_parser = OptionParser(usage="%prog -c <config> [-dhqv] [-x <regexp>] [-u username] [-p password] <files>", version="%prog 0.0")
	cmd_parser.add_option("-r", "--recursive", dest="recursive", action="store_true", default=False, help="search for files recursively")
	cmd_parser.add_option("-v", "--verbose",   dest="verbose",   action="store_true", default=False, help="print extra debug information")
	cmd_parser.add_option("-c", "--config",    dest="config",    metavar="FILE",                     help="the configuration file")
	cmd_parser.add_option("-x", "--exclude",   dest="exclude",   action="append",                    help="regular expressions of files to not include")
	cmd_parser.add_option("-d", "--dryrun",    dest="dryrun",    action="store_true", default=False, help="perform a dry run where all tests, including remote tests, are performed but the content is not uploaded into the content system")
	cmd_parser.add_option("-u", "--username",  dest="username",  metavar="USERNAME",                 help="the username for uploading content")
	cmd_parser.add_option("-p", "--password",  dest="password",  metavar="PASSWORD",                 help="the password for uploading content")

	(options, args) = cmd_parser.parse_args()

	if options.config is None:
		cmd_parser.error("you must pass a configuration file")

	if options.verbose:
		print "reading configuration file %s..." % options.config

	ini_parser = ConfigParser()
	if len(ini_parser.read([ options.config ])) != 1:
		cmd_parser.error("could not read the configuration file")

	if not ini_parser.has_section("musa"):
		cmd_parser.error("configuration file missed musa section")

	try:
		excluders = [ re.compile("(\.svn|\.hg|\.git)") ]
		if options.exclude is not None:
			for exclude in options.exclude:
				excluders.append(re.compile(exclude))
	except:
		cmd_parser.error("regular expression is invalid")

	tar = None
	tar_file = None
	try:
		if options.verbose: print "creating temporary tarball..."
		# In Windows the temporary file will get removed when the tar
		# is closed the first time, if delete is not set to False.
		tar_file = NamedTemporaryFile(dir=".", delete=False)
		tar = tarfile.open(tar_file.name, mode='w:gz')
		metadata = {}

		if options.verbose: print "packaging name/version information..."
		metadata.update(package_misc(ini_parser))

		if options.verbose: print "packaging license information..."
		metadata.update(package_license(ini_parser, tar, metadata['safe_name']))

		if options.verbose: print "packaging type information..."
		package_files = set()
		for arg in args:
			for path in glob.glob(arg):
				if os.path.isfile(path):
					if not match_excluders(excluders, path):
						package_files.add(path)
				if os.path.isdir(path) and options.recursive:
					for root, dirs, files in os.walk(path):
						for file in files:
							path = os.path.join(root, file)
							if not match_excluders(excluders, path):
								package_files.add(path)
		if options.verbose:
			print "the following files will be added:"
			for file in package_files:
				print "  - %s" % file

		if options.verbose: print "packaging text information..."
		metadata.update(package_text(ini_parser, tar, metadata['safe_name'], package_files))

		print "packaging files... (might take a while)"
		metadata.update(package_type(ini_parser, tar, metadata['safe_name'], package_files))

		if len(package_files) != 0:
			print "the following files remained unpackaged:"
			for pf in package_files:
				print " - %s" % pf
			raise MusaException("unpackagable files in directory")

		if options.verbose: print "validating files locally... "
		tar.close()

		tar = tarfile.open(tar_file.name, mode='r')

		validate(metadata, tar, options.verbose)
		if options.verbose: print "temporary tarball validated..."
		tar.close()
	except MusaException, inst:
		print inst.args[0]
		return
	finally:
		if tar != None and not tar.closed:
			tar.close()
		if tar_file != None:
			tar_file.close()
			os.remove(tar_file.name)

	def send_data(sock, data, binary=False):
		if binary:
			sock.send(pack('!H', len(data)))
			if len(data) != 0:
				sock.send(data)
		else:
			repr_data = repr(data)
			sock.send(pack('!H', len(repr_data)))
			sock.send(repr_data)

	def send_file(sock, tar_file):
		amount = 0
		size = os.stat(tar_file.name).st_size

		fd = open(tar_file.name, "rb", 51200)
		while True:
			data = fd.read(51200)
			if data is None or len(data) == 0:
				break

			send_data(sock, data, True)
			amount += len(data)
			print "\ruploaded %d bytes of %d bytes (%d%%)" % (amount, size, (amount * 100 / size)),

		send_data(sock, "", True)
		fd.close()
		print ""

	if options.username is None:
		options.username = raw_input("Please enter your username: ")
	if options.password is None:
		options.password = getpass("Please enter your password: ")
	check = raw_input("are you one of the authors of this content, if so answer 'yes I am': ")

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(("content.openttd.org", 3980))
	sock = ssl.wrap_socket(sock, server_side=False, ssl_version=ssl.PROTOCOL_TLSv1)

	send_data(sock, "0.0.0")
	send_data(sock, { 'username': options.username, 'password': options.password, 'check': check })

	if options.verbose: print "validating metadata at server..."
	send_data(sock, metadata)
	data = sock.recv(8192)
	print data

	if data.startswith("error"):
		print "an error occurred and the content is not uploaded"
	elif not options.dryrun:
		send_file(sock, tar_file)

		if options.verbose: print "validating files at server..."
		if options.verbose: print "waiting for acknowledgement..."
		print sock.recv(8192)
	else:
		send_data(sock, "", True)
		print "not uploading tarball due to dry run"

	tar_file.close()
	sock.close()

main()
