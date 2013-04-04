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
		if scanning == 3 and line.find('//') != -1: # watch out for // ".."
			continue
		if scanning == 3 and line.find('/*') != -1: # watch out for /*".."*/
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

