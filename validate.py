# $Id$
#
# This file is part of musa.
# musa is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2.
# musa is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details. You should have received a copy of the GNU General Public License along with musa. If not, see <http://www.gnu.org/licenses/>.
#

from exception import MusaException
from license import validate_license
from misc import validate_misc
from type import validate_type
from text import validate_text

def validate(metadata, tar, verbose=False):
	if not 'safe_name' in metadata:
		raise MusaException("safe name is missing")
	if not isinstance(metadata['safe_name'], str):
		raise MusaException("safe name is invalid")

	tar_path = metadata['safe_name']
	if tar is not None:
		suspect_filenames = tar.getnames()
		for fn in suspect_filenames:
			if not fn.startswith(tar_path):
				raise MusaException("invalid file in tarball")

			if tar.getmember(fn).isdir():
				suspect_filenames.remove(fn)
	else:
		suspect_filenames = []

	if verbose: print "validating misc data"
	validate_misc(metadata, tar, tar_path, suspect_filenames)

	if verbose: print "validating license..."
	validate_license(metadata, tar, tar_path, suspect_filenames)

	if verbose: print "validating text"
	validate_text(metadata, tar, tar_path, suspect_filenames)

	if verbose: print "validating type..."
	validate_type(metadata, tar, tar_path, suspect_filenames)

	if len(suspect_filenames) != 0:
		if verbose:
			print "the following unknown files are found:"
			for sf in suspect_filenames:
				print " - %s" % sf
		raise MusaException("unknown files in tarball")
