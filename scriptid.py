# $Id$
#
# This file is part of musa.
# musa is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2.
# musa is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details. You should have received a copy of the GNU General Public License along with musa. If not, see <http://www.gnu.org/licenses/>.
#

from exception import MusaException
import re
import os

def get_script_short_name(f):
	scanning = 0
	shortName = ""
	for line in f.readlines():
		if line.find("GetShortName") != -1:
			line = line[line.find("GetShortName"):]
			scanning = 1
		if scanning == 0: continue

		if scanning == 1 and line.find("{") != -1:
			line = line[line.find("{"):]
			scanning = 2
		if scanning == 2 and line.find("return") != -1:
			line = line[line.find("return"):]
			scanning = 3
		if scanning == 3 and line.find('//') != -1 and line.find('//') < line.find('"'): # watch out for // ".."
			continue
		if scanning == 3 and line.find('/*') != -1 and line.find('/*') < line.find('"'): # watch out for /*".."*/
			line = line[line.find('/*') + 1:]
			scanning = 4
		if scanning == 4 and line.find('*/') != -1:
			line = line[line.find('*/') + 1:]
			scanning = 3 # return to looking for "
		if scanning == 3 and line.find('"') != -1:
			line = line[line.find('"') + 1:]
			scanning = 5
		if scanning == 5 and line.find('"') != -1:
			shortName = line[:line.find('"')]
			break

	return shortName

def get_script_type(f):

	for line in f.readlines():

		if re.search("extends\\s+GSInfo", line) != None:
			return 'GS'
		elif re.search("extends\\s+GSLibrary", line) != None:
			return 'GS'
		elif re.search("extends\\s+AIInfo", line) != None:
			return 'AI'
		elif re.search("extends\\s+AILibrary", line) != None:
			return 'AI'

	raise MusaException('Unknown script type');

