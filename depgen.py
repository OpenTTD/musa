#! /usr/bin/env python

from ConfigParser import ConfigParser
from optparse import OptionParser
import tarfile
import os
import glob
import re

from exception import MusaException
from misc import parse_file_args
from type import validate_md5, types
from scriptid import get_script_short_name, get_script_type
from grfid import get_grfid

# Examines the content of a tar to determine its type, md5sum and uniqueid
def get_tar_info(tar):

	md5sum = 0
	uniquid = ''

	n_matched_files = 0
	for file in tar.getnames():
		ext = file.split('.')[-1].lower()
		matched_file = True
		if ext == "obg":
			type = "Base Graphic"
			raise MusaException("depgen do not support Base Graphics")
		elif ext == "obs":
			type = "Base Sound"
			raise MusaException("depgen do not support Base Sound")
		elif ext == "obm":
			type = "Base Music"
			raise MusaException("depgen do not support Base Music")
		elif ext == "scn":
			type = "Scenario"
			md5sum = validate_md5(tar.extractfile(file), None, tar.getmember(file).size)
			uniqueid = '<copy uniqueid from BaNaNaS web UI>' # Scenarios do not carry uniqueid. It has to be obtained from the Bananas server
		elif ext == "grf":
			type = "NewGRF"
			md5sum = validate_md5(tar.extractfile(file), None, tar.getmember(file).size)
			uniqueid_int = get_grfid(tar.extractfile(file))
			if uniqueid_int >> 24 == 0xFF:
				raise MusaException("Invalid/system GRF")
			uniqueid = ("%08x" % uniqueid_int).upper()
		elif ext == "png" or ext == "bmp":
			md5sum = validate_md5(tar.extractfile(file), None, tar.getmember(file).size)
			uniqueid = '<copy uniqueid from BaNaNaS web UI>' # Heightmaps do not carry uniqueid. It has to be obtained from the Bananas server
			type = "Heightmap"
		elif os.path.basename(file) == "info.nut":
			short_name = get_script_short_name(tar.extractfile(file))
			type = get_script_type(tar.extractfile(file))

		elif os.path.basename(file) == "library.nut":
			short_name = get_script_short_name(tar.extractfile(file))
			type = get_script_type(tar.extractfile(file))
			type += " Library"
		else:
			matched_file = False

		if matched_file:
			n_matched_files += 1

	if n_matched_files == 0:
		raise MusaException("Unknown content type of tar file")
	elif n_matched_files > 1:
		raise MusaException("Multiple content types inside tar file")

	# Common uniquid+md5sum determination for all script based content
	if type in ['AI', 'GS', 'AI Library', 'GS Library']:
		if len(short_name) != 4:
			raise MusaException("Invalid short name")
		uniqueid = short_name # dependencies in musa .ini uses the literal short name and not the encoded uniqueid

		md5sum = 0
		for file in tar.getnames():
			ext = file.split(".")[-1].lower()
			if ext == "nut":
				md5sum ^= validate_md5(tar.extractfile(file), None, tar.getmember(file).size)

	return type, uniqueid, "%032x" % md5sum


def main():
	cmd_parser = OptionParser(usage="%prog [-hv] <tar files>", version="%prog 0.0")
	cmd_parser.add_option("-v", "--verbose",   dest="verbose",   action="store_true", default=False, help="print extra debug information")
	cmd_parser.add_option("-x", "--exclude",   dest="exclude",   action="append",                    help="regular expressions of files to not include")
	cmd_parser.add_option("-l", "--list",      dest="list",      action="store_true",                help="display a human readable dependency list (as opposed for a comma separated list suitable to include in your musa ini file)")

	(options, args) = cmd_parser.parse_args()

	try:
		excluders = [ re.compile("(\.svn|\.hg|\.git)") ]
		if options.exclude is not None:
			for exclude in options.exclude:
				excluders.append(re.compile(exclude))
	except re.error:
		cmd_parser.error("regular expression is invalid")


	files = parse_file_args(args, excluders)
	if options.verbose:
		print "the following files will be examined:"
		for file in files:
			print "  - %s" % file

	if len(files) == 0:
		cmd_parser.error("no input files given")

	if options.verbose:
		print ""

	dep_ini_line = "dependencies = "
	for file in files:
		if file.endswith('.tar'):
			try:
				tar = tarfile.open(file, mode='r')
			except TarError:
				print "couldn't open " + file + " as tar file"

			# Get content type
			try:
				type, uniqueid, md5sum = get_tar_info(tar)
			except MusaException, inst:
				print file + ": " + inst.args[0]
				continue

			# If a .tar do not contain information to determine its type,
			# get_tar_info will throw an exception which is handled above.
			# This check is for if get_tar_info returns a content type which
			# is unknown. Eg. if there is an internal error in musa.
			if not type in types:
				raise MusaException('Unknown content type')


			dep = type + ":" + uniqueid + ":" + md5sum
			if not options.list:
				if not dep_ini_line.endswith("= "):
					dep_ini_line += ", "
				dep_ini_line += dep

			# Print dep comment
			if options.verbose:
				print "# " + file
			else:
				print "# " + os.path.basename(file)

			if options.list:
				print dep

	# Print the one-line comma separated list of dependencies
	if not options.list:
		print dep_ini_line


main()
