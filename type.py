from ConfigParser import ConfigParser
import hashlib
import os
import re
import array
import StringIO
import tarfile
from grfid import get_grfid
from scriptid import get_script_short_name
from misc import tar_join_path, tar_add_file_from_string
from struct import unpack
from exception import MusaException

obg_ini = {
	'metadata': ['name', 'shortname', 'version', 'description', 'palette',  'blitter' ],
	'files':    ['base', 'logos',     'arctic',  'toyland',     'tropical', 'extra'   ],
	'md5s':     [],
	'origin':   ['default']
}

# @param files  list of files
# @param end    list of accepted file ends
def find_file_in_list(files, end):
	rets = []
	for e in end:
		rets += [ file for file in files if file.endswith(e) ]

	if len(rets) > 1:
		raise MusaException("multiple %s files" % end)
	if len(rets) == 0:
		raise MusaException("no %s file" % end)

	return rets[0]

def find_exact_file_in_list(files, filename):
	rets = [ file for file in files if os.path.basename(file) == filename ]
	if len(rets) > 1:
		raise MusaException("multiple %s files" % filename)
	if len(rets) == 0:
		raise MusaException("no %s file" % filename)

	return rets[0]

def validate_md5(file, md5, size):
	try:
		md5sum = hashlib.md5();

		read_header = file.read(10)
		md5sum.update(read_header)
		read_header = [ ord(i) for i in read_header ]
		size -= 10

		expected_header = list(array.array('B', [0x00, 0x00, ord('G'), ord('R'), ord('F'), 0x82, 0x0D, 0x0A, 0x1A, 0x0A]))
		if read_header == expected_header:
			raw_size = file.read(4)
			size -= 4
			md5sum.update(raw_size)
			size = unpack("<i", raw_size)[0]

		while size > 0:
			data = file.read(min(8192, size))
			if data is None or len(data) == 0:
				break

			md5sum.update(data)
			size -= len(data)

		digest = md5sum.hexdigest()
		if md5 is not None and digest != md5:
			print digest
			print md5
			raise MusaException("MD5 checksums do not match!")

		return int(digest, 16)
	except:
		file.close()
		raise

def validate_ini(file, expected_sections):
	ini_parser = ConfigParser()
	ini_parser.readfp(file)

	for section, keys in obg_ini.items():
		if not ini_parser.has_section(section):
			raise MusaException("section %s is missing" % section)
		for key in keys:
			if not ini_parser.has_option(section, key):
				raise MusaException("option %s:%s is missing" % (section, key))

	shortname = ini_parser.get("metadata", "shortname")
	if len(shortname) != 4:
		raise MusaException("the short name is not 4 long")

	return (ini_parser, shortname)

def validate_packaging_ini(files, expected_sections, extension):
	filename = find_file_in_list(files, [extension])
	try:
		fd = open(filename)
		(ini_parser, shortname) = validate_ini(fd, expected_sections)
		fd.close()

		return (filename, ini_parser, shortname)
	except:
		fd.close()
		raise

def validate_packaged_ini(tar, expected_sections, extension):
	try:
		filename = find_file_in_list(tar.getnames(), [extension])
		fd = tar.extractfile(filename)
		(ini_parser, shortname) = validate_ini(fd, expected_sections)
		fd.close()

		return (filename, ini_parser, shortname)
	except:
		fd.close()
		raise

def validate_tar_file(tar, tar_path, filename, expected_content):
	tar_file = tar_join_path(tar_path, filename)
	f_expected = StringIO.StringIO(expected_content)
	f_expected.seek(0, os.SEEK_END)
	expected_size = f_expected.tell()
	try:
		f = tar.extractfile(tar_file)
	except tarfile.TarError:
		raise MusaException("Tar does not contain expected file " + filename)

	if tar.getmember(tar_file).size != expected_size:
		raise MusaException("File " + filename + " in tar does not has the expected size")

	if f.read(expected_size) != expected_content:
		raise MusaException("File " + filename + " in tar does not contain the expected content")


def get_md5sums(ini_parser, sections, files):
	grfs = []
	for key in sections['files']:
		name = ini_parser.get('files', key)

		if not ini_parser.has_option('md5s', name):
			raise MusaException("no MD5 checksum given for %s" % name)

		md5 = ini_parser.get('md5s', name)
		fname = find_file_in_list(files, [name])
		grfs.append((name, fname, md5))

	return grfs

def get_md5sum(f):
	return int(hashlib.md5(f.read()).hexdigest(), 16)

def get_scen_hm_title(name, version):
	return name + " (" + version + ")"

def package_script(tar, tar_path, files, infofile):
	filename = find_exact_file_in_list(files, infofile)
	short_name = get_script_short_name(open(filename))
	if len(short_name) != 4:
		raise MusaException("Invalid short name")
	uniqueid = (ord(short_name[0]) << 0) + (ord(short_name[1]) << 8) + (ord(short_name[2]) << 16) + (ord(short_name[3]) << 24)

	md5sum = 0
	scriptFiles = list()
	for file in files:
		ext = file.split(".")[-1]
		if ext == "nut":
			md5sum ^= validate_md5(open(file, "rb"), None, os.stat(file).st_size)

		if ext == "nut" or re.search("\/|\\\\lang\/|\\\\.*\.txt$", file) != None:
			scriptFiles.append(file)

	common_path = os.path.commonprefix(scriptFiles)
	for file in scriptFiles:
		content_file_path = file[len(common_path):].replace("\\", "/") # remove common path
		tar.add(file, arcname=os.path.join(tar_path, content_file_path))
		files.remove(file)


	return { 'uniqueid': uniqueid, 'md5sum': "%032x" % md5sum }

# Method for packaging heightmaps and scenarios
def package_hm_scen(tar, tar_path, files, uniqueid, title, extensions):
	filename = find_file_in_list(files, extensions)
	md5sum = validate_md5(open(filename, "rb"), None, os.stat(filename).st_size)

	tar.add(filename, arcname=os.path.join(tar_path, os.path.basename(filename)))
	files.remove(filename)

	tar_add_file_from_string(tar, tar_path, os.path.basename(filename) + '.id', str(uniqueid));
	tar_add_file_from_string(tar, tar_path, os.path.basename(filename) + '.title', title);
	return {  'uniqueid': uniqueid, 'md5sum': "%032x" % md5sum }

def package_ai(tar, tar_path, files):
	return package_script(tar, tar_path, files, "info.nut")

def package_ailib(tar, tar_path, files):
	return package_script(tar, tar_path, files, "library.nut")

def package_bg(tar, tar_path, files):
	(obg, ini_parser, shortname) = validate_packaging_ini(files, obg_ini, ".obg")
	grfs = get_md5sums(ini_parser, obg_ini, files)

	md5sum = 0
	for name, fname, md5 in grfs:
		md5sum ^= validate_md5(open(fname, "rb"), md5, os.stat(fname).st_size)
		tar.add(fname, arcname=os.path.join(tar_path, name))
		files.remove(fname)

	tar.add(obg, arcname=os.path.join(tar_path, os.path.basename(obg)))
	files.remove(obg)
	return { 'uniqueid': (ord(shortname[0]) << 0) + (ord(shortname[1]) << 8) + (ord(shortname[2]) << 16) + (ord(shortname[3]) << 24), 'md5sum': "%032x" % md5sum }

def package_bm(tar, tar_path, files):
	raise MusaException("Base music sets are not supported yet")
	return { 'uniqueid': 0, 'md5sum': 0 }

def package_bs(tar, tar_path, files):
	raise MusaException("Base sound sets are not supported yet")
	return { 'uniqueid': 0, 'md5sum': 0 }

def package_gs(tar, tar_path, files):
	return package_script(tar, tar_path, files, "info.nut")

def package_gslib(tar, tar_path, files):
	return package_script(tar, tar_path, files, "library.nut")

def package_hm(tar, tar_path, files, uniqueid, title):
	return package_hm_scen(tar, tar_path, files, uniqueid, title, [".png", ".bmp"])

def package_newgrf(tar, tar_path, files):
	filename = find_file_in_list(files, [".grf"])
	uniqueid = get_grfid(open(filename, 'rb'))
	if uniqueid >> 24 == 0xFF:
		raise MusaException("Invalid/system GRF")

	md5sum = validate_md5(open(filename, "rb"), None, os.stat(filename).st_size)

	tar.add(filename, arcname=os.path.join(tar_path, os.path.basename(filename)))
	files.remove(filename)
	return { 'uniqueid': uniqueid, 'md5sum': "%032x" % md5sum }

def package_scen(tar, tar_path, files, uniqueid, title):
	return package_hm_scen(tar, tar_path, files, uniqueid, title, [".scn"])

def validate_script(metadata, tar, tar_path, suspect_filenames, infofile):
	if tar is None:
		return

	filename = find_exact_file_in_list(tar.getnames(), infofile)
	short_name = get_script_short_name(tar.extractfile(filename))
	if len(short_name) != 4:
		raise MusaException("Invalid short name")
	uniqueid = (ord(short_name[0]) << 0) + (ord(short_name[1]) << 8) + (ord(short_name[2]) << 16) + (ord(short_name[3]) << 24)
	if metadata['uniqueid'] != uniqueid:
		raise MusaException("Invalid short name")

	md5sum = 0
	for file in tar.getnames():
		ext = file.split(".")[-1]
		if ext == "nut":
			md5sum ^= validate_md5(tar.extractfile(file), None, tar.getmember(file).size)

		if file in suspect_filenames:
			if ext == "nut" or re.search("\/|\\\\lang\/|\\\\.*\.txt$", file.lower()) != None:
				suspect_filenames.remove(file)

	if metadata['md5sum'] != "%032x" % md5sum:
		raise MusaException("md5sum mismatch")

def validate_hm_secn(metadata, tar, tar_path, suspect_filenames, extensions):
	if tar is None:
		return

	filename = find_file_in_list(tar.getnames(), extensions)
	validate_md5(tar.extractfile(filename), metadata['md5sum'], tar.getmember(filename).size)
	suspect_filenames.remove(filename)

	id_file = os.path.basename(filename) + '.id'
	title_file = os.path.basename(filename) + '.title'
	validate_tar_file(tar, tar_path, id_file, str(metadata['uniqueid']));
	validate_tar_file(tar, tar_path, title_file, get_scen_hm_title(metadata["name"], metadata["version"]));
	suspect_filenames.remove(tar_join_path(tar_path, id_file))
	suspect_filenames.remove(tar_join_path(tar_path, title_file))

def validate_ai(metadata, tar, tar_path, suspect_filenames):
	validate_script(metadata, tar, tar_path, suspect_filenames, "info.nut")

def validate_ailib(metadata, tar, tar_path, suspect_filenames):
	validate_script(metadata, tar, tar_path, suspect_filenames, "library.nut")

def validate_bg(metadata, tar, tar_path, suspect_filenames):
	if tar is None:
		return

	(filename, ini_parser, shortname) = validate_packaged_ini(tar, obg_ini, ".obg")
	if os.path.dirname(filename) != tar_path:
		raise MuseException("obg file %s in wrong folder" % fname)

	suspect_filenames.remove(filename)

	if metadata['uniqueid'] != (ord(shortname[0]) << 0) + (ord(shortname[1]) << 8) + (ord(shortname[2]) << 16) + (ord(shortname[3]) << 24):
		raise MusaException("uniqueid mismatch")

	grfs = get_md5sums(ini_parser, obg_ini, tar.getnames())
	md5sum = 0
	for name, fname, md5 in grfs:
		if os.path.dirname(fname) != tar_path:
			raise MuseException("grf file %s in wrong folder" % fname)

		md5sum ^= validate_md5(tar.extractfile(fname), md5, tar.getmember(fname).size)
		suspect_filenames.remove(fname)

	if metadata['md5sum'] != "%032x" % md5sum:
		raise MusaException("md5sum mismatch")

def validate_bm(metadata, tar, tar_path, suspect_filenames):
	raise MusaException("unsupported")
	return

def validate_bs(metadata, tar, tar_path, suspect_filenames):
	raise MusaException("unsupported")
	return

def validate_gs(metadata, tar, tar_path, suspect_filenames):
	validate_script(metadata, tar, tar_path, suspect_filenames, "info.nut")

def validate_gslib(metadata, tar, tar_path, suspect_filenames):
	validate_script(metadata, tar, tar_path, suspect_filenames, "library.nut")

def validate_hm(metadata, tar, tar_path, suspect_filenames):
	validate_hm_secn(metadata, tar, tar_path, suspect_filenames, [".png", ".bmp"])

def validate_newgrf(metadata, tar, tar_path, suspect_filenames):
	if metadata['uniqueid'] >> 24 == 0xFF:
		raise MusaException("Invalid/system GRF")

	if tar is None:
		return

	filename = find_file_in_list(tar.getnames(), [".grf"])
	md5sum = validate_md5(tar.extractfile(filename), metadata['md5sum'], tar.getmember(filename).size)
	if metadata['uniqueid'] != get_grfid(tar.extractfile(filename)):
		raise MusaException("uniqueid mismatch")

	suspect_filenames.remove(filename)

def validate_scen(metadata, tar, tar_path, suspect_filenames):
	validate_hm_secn(metadata, tar, tar_path, suspect_filenames, [".scn"])


types = {
	'AI':           { 'package': package_ai,     'validate': validate_ai     },
	'AI Library':   { 'package': package_ailib,  'validate': validate_ailib  },
	'Base Graphic': { 'package': package_bg,     'validate': validate_bg     },
	'Base Music':   { 'package': package_bm,     'validate': validate_bm     },
	'Base Sound':   { 'package': package_bs,     'validate': validate_bs     },
	'Game Script':  { 'package': package_gs,     'validate': validate_gs     },
	'GS Library':   { 'package': package_gslib,  'validate': validate_gslib  },
	'Heightmap':    { 'package': package_hm,     'validate': validate_hm     },
	'NewGRF':       { 'package': package_newgrf, 'validate': validate_newgrf },
	'Scenario':     { 'package': package_scen,   'validate': validate_scen   },
}


def package_type(ini_parser, tar, tar_path, files):
	if not ini_parser.has_option("musa", "type"):
		raise MusaException("no type specified in the configuration file")

	type_name = ini_parser.get("musa", "type")
	if not type_name in types:
		raise MusaException("unknown type \"%s\"" % type_name)

	metadata = { 'package_type': type_name }

	# uniqueid and content title cannot be obtained from the Scenario (.scn) or Heightmap image file.
	# So for them this need to be obtained from the .ini file instead and passed to their package
	# methods.
	if type_name in ["Scenario", "Heightmap"]:
		uniqueid_str = ini_parser.get("musa", "uniqueid")
		if len(uniqueid_str) == 8:
			uniqueid = int(uniqueid_str, 16)
		elif (len(uniqueid_str) > 0) and uniqueid_str[0] != '0':
			uniqueid = int(uniqueid_str, 10)
		else:
			raise MusaException("Invalid uniqueid syntax in ini file")

		title = get_scen_hm_title(ini_parser.get("musa", "name"), ini_parser.get("musa", "version"))
		metadata.update(types[type_name]['package'](tar, tar_path, files, uniqueid, title))
	else:
		metadata.update(types[type_name]['package'](tar, tar_path, files))

	return metadata

def validate_type(metadata, tar, tar_path, suspect_filenames):
	if not 'package_type' in metadata:
		raise MusaException("package type is missing")
	if not isinstance(metadata['package_type'], str):
		raise MusaException("package_type is invalid")

	package_type = metadata['package_type']
	if not package_type in types:
		raise MusaException("invalid package type")

	if not "uniqueid" in metadata:
		raise MusaException("uniqueid missing")
	if not isinstance(metadata['uniqueid'], int):
		raise MusaException("uniqueid is invalid")

	if not "md5sum" in metadata:
		raise MusaException("md5sum missing")
	if not isinstance(metadata['md5sum'], str):
		raise MusaException("md5sum is invalid")


	types[package_type]['validate'](metadata, tar, tar_path, suspect_filenames)
