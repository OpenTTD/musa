from exception import MusaException
import StringIO
from tarfile import TarInfo
import glob
import os

fields = {
	"name":    32,
	"version": 16,
	"url":     96,
}

def match_excluders(excluders, path):
	for excluder in excluders:
		if excluder.search(path):
			return True
	return False

def parse_file_args(args, options, excluders):
	files = set()
	for arg in args:
		for path in glob.glob(arg):
			if os.path.isfile(path):
				if not match_excluders(excluders, path):
					files.add(path)
			if os.path.isdir(path) and options.recursive:
				for root, dirs, sub_files in os.walk(path):
					for file in sub_files:
						path = os.path.join(root, file)
						if not match_excluders(excluders, path):
							files.add(path)
	return files

def tar_join_path(root, file):
	if len(root) == 0 or root[-1] == '/':
		return root + file
	else:
		return root + '/' + file

def tar_add_file_from_string(tar, tar_path, filename, content):
	file = StringIO.StringIO(content)
	info = TarInfo(tar_join_path(tar_path, filename))
	info.size = len(content)
	tar.addfile(info, file)

def check_utf8(text, type):
	if not isinstance(text, str):
		raise MusaException("%s is not a string" % type)
	try:
		text.decode('utf-8')
	except UnicodeDecodeError:
		raise MusaException("%s is not a valid UTF-8 content" % type)

def checkdependency(dep):
	data = dep.split(":")
	if len(data) != 3:
		raise MusaException("invalid dependency")

	if not data[0] in [ "AI", "AI Library", "Base Graphic", "Base Music", "Base Sound", "Game Script", "GS Library", "Heightmap", "NewGRF", "Scenario" ]:
		raise MusaException("invalid dependency type")

	if len(data[1]) == 4:
		short_name = data[1]
		id = (ord(short_name[0]) << 0) + (ord(short_name[1]) << 8) + (ord(short_name[2]) << 16) + (ord(short_name[3]) << 24)
	elif len(data[1]) == 8:
		try:
			id = int(data[1], 16)
		except:
			raise MusaException("invalid dependency id")
	else:
		raise MusaException("invalid dependency id")

	if len(data[2]) != 32:
		raise MusaException("invalid dependency md5sum")

	try:
		md5 = int(data[2], 16)
	except:
		raise MusaException("invalid dependency id")

	return (data[0], id, md5)

def safe_filename(name, is_version = False):
	new_name = ""

	for i in range(len(name)):
		if name[i] >= 'a' and name[i] <= 'z':
			new_name += name[i]
			continue
		if name[i] >= 'A' and name[i] <= 'Z':
			new_name += name[i]
			continue
		if name[i] >= '0' and name[i] <= '9':
			new_name += name[i]
			continue
		if name[i] == ' ' and not is_version:
			new_name += '_'
			continue
		if name[i] == '.':
			new_name += name[i]
			continue
		pass

	return new_name

def parse_version(ini_parser, name, default):
	if not ini_parser.has_option("musa", name):
		raise MusaException("no %s specified in the configuration file" % name)

	version = ini_parser.get("musa", name)
	if len(version) == 0:
		return default

	version = version.split(" ", 2)
	if len(version) == 1:
		version = version[0].split(".")
		if len(version) != 3:
			raise MusaException("invalid full version")
		iversion = []
		try:
			for v in version:
				iversion.append(int(v))
		except:
			raise MusaException("invalid full version")

		if name == 'openttd_maximum_supported_version':
			stable_comp = 0x0008FFFF
		else:
			stable_comp = 0x00080000
		return iversion[0] * 0x10000000 + iversion[1] * 0x01000000 + iversion[2] * 0x00100000 + stable_comp
	else:
		if not version[1].startswith("r"):
			raise MusaException("invalid revision")
		try:
			revision = int(version[1][1:])
			version = version[0].split(".")
			if len(version) != 2:
				raise MusaException("invalid full version")
			iversion = []
			for v in version:
				iversion.append(int(v))
		except:
			raise MusaException("invalid full version")
		return iversion[0] * 0x10000000 + iversion[1] * 0x01000000 + revision

def parse_list(ini_parser, field):
	if not ini_parser.has_option("musa", field):
		raise MusaException("no %s specified in the configuration file" % field)

	ret = set()
	data = ini_parser.get("musa", field)
	if len(data) != 0:
		for value in data.split(","):
			value = value.strip()
			check_utf8(value, field)
			ret.add(value)

	return list(ret)

def package_misc(ini_parser):
	metadata = {}

	for field in fields.keys():
		if not ini_parser.has_option("musa", field):
			raise MusaException("no %s specified in the configuration file" % field)

		value = ini_parser.get("musa", field)
		if len(value) > fields[field]:
			raise MusaException("value for %s is too long" % field)

		check_utf8(value, field)
		metadata[field] = value

	metadata['min_version'] = parse_version(ini_parser, 'openttd_minimum_supported_version', 0x06000000)
	metadata['max_version'] = parse_version(ini_parser, 'openttd_maximum_supported_version', -1)
	metadata['safe_name'] = safe_filename(metadata["name"]) + "-" + safe_filename(metadata["version"], True)

	metadata['tags'] = parse_list(ini_parser, 'tags')
	for tag in metadata['tags']:
		if len(tag) > 32:
			raise MusaException("invalid tag name")

	metadata['authors'] = parse_list(ini_parser, 'authors')

	raw_deps = parse_list(ini_parser, 'dependencies')
	dep_list = list()
	for dep in raw_deps:
		type, uniqueid, md5sum = checkdependency(dep)
		dep_list.append(type + ":" + "%08X" % uniqueid + ":" + "%032x" % md5sum)
	metadata['dependencies'] = dep_list

	return metadata

def validate_misc(metadata, tar, tar_path, suspect_filenames):
	for field in fields.keys():
		if not field in metadata:
			raise MusaException("%s missing" % field)

		value = metadata[field]
		if len(value) > fields[field]:
			raise MusaException("value for %s is too long" % field)

		check_utf8(value, field)

	if not 'safe_name' in metadata:
		raise MusaException("safe_name missing")
	if not isinstance(metadata['safe_name'], str):
		raise MusaException("safe name is invalid")

	if not 'min_version' in metadata:
		raise MusaException("min_version missing")
	if not isinstance(metadata['min_version'], int):
		raise MusaException("min_version is invalid")

	if not 'max_version' in metadata:
		raise MusaException("min_version missing")
	if not isinstance(metadata['max_version'], int):
		raise MusaException("max_version is invalid")

	min_version = int(metadata['min_version'])
	max_version = int(metadata['max_version'])
	if max_version != -1 and min_version > max_version or min_version < 0 or max_version < -1:
		raise MusaException("invalid version")

	if metadata['safe_name'] != safe_filename(metadata["name"]) + "-" + safe_filename(metadata["version"], True):
		raise MusaException("safe_name inconsistent")

	if not 'tags' in metadata:
		raise MusaException("tags missing")
	if not isinstance(metadata['tags'], list):
		raise MusaException("tags is invalid")

	for tag in metadata['tags']:
		check_utf8(tag, "tags")
		if len(tag) > 32:
			raise MusaException("invalid tag name")

	if not 'authors' in metadata:
		raise MusaException("authors missing")
	if not isinstance(metadata['authors'], list):
		raise MusaException("authors is invalid")

	if len(metadata['authors']) < 1:
		raise MusaException("authors missing")

	for author in metadata['authors']:
		check_utf8(author, "authors")

	if not 'dependencies' in metadata:
		raise MusaException("dependencies missing")
	if not isinstance(metadata['dependencies'], list):
		raise MusaException("dependencies is invalid")

	for dep in metadata['dependencies']:
		check_utf8(dep, "dependencies")
		checkdependency(dep)
