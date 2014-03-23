# $Id$
#
# This file is part of musa.
# musa is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2.
# musa is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details. You should have received a copy of the GNU General Public License along with musa. If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import with_statement
from exception import MusaException
import re
import os

docs_regexp = re.compile("(readme|changelog)(_[a-z]{2}(_[A-Z]{2})?)?\.txt$")

def check_utf8(text, type):
	try:
		text.decode('utf-8')
	except UnicodeDecodeError:
		raise MusaException("%s is not a valid UTF-8 content" % type)

def package_text(ini_parser, tar, tar_path, package_files):
	if ini_parser.has_option("musa", "description_file"):
		description_file = ini_parser.get("musa", "description_file")
		try:
			with open(description_file, 'r') as content_file:
				description_text = content_file.read()
		except:
			raise MusaException("unknown description file \"%s\"" % description_file)
	elif ini_parser.has_option("musa", "description_text"):
		description_text = ini_parser.get("musa", "description_text")
	else:
		raise MusaException("Neither description_text nor description_file specified in the configuration file")

	if len(description_text) > 512:
		raise MusaException("value for description is too long")

	check_utf8(description_text, "description")

	for fname in list(package_files):
		bname = os.path.basename(fname)
		if docs_regexp.match(bname):
			with open(fname, 'r') as content:
				check_utf8(content.read(), bname)
			tar.add(fname, arcname=os.path.join(tar_path, bname))
			package_files.remove(fname)

	return { 'description': description_text }

def validate_text(metadata, tar, tar_path, suspect_filenames):
	if not 'description' in metadata:
		raise MusaException("description is missing")
	if not isinstance(metadata['description'], str):
		raise MusaException("description is invalid")

	if len(metadata['description']) > 512:
		raise MusaException("value for description is too long")

	check_utf8(metadata['description'], "description")

	if not 'name' in metadata:
		raise MusaException("name is missing")
	if not isinstance(metadata['name'], str):
		raise MusaException("name is invalid")

	if len(metadata['name']) > 32:
		raise MusaException("value for name is too long")

	check_utf8(metadata['name'], "name")

	if tar is not None:
		for member in tar.getnames():
			bname = os.path.basename(member)
			if docs_regexp.match(bname):
				try:
					fd = tar.extractfile(member)
					check_utf8(fd.read(), bname)
					fd.close()
				except:
					fd.close()
					raise

				if os.path.dirname(member) != tar_path:
					raise MuseException("text file %s in wrong folder" % member)

				suspect_filenames.remove(member)
