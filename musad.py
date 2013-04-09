#! /usr/bin/env python

import tarfile
import ssl
import asyncore
import socket
import os
import ldap
import _mysql
from literal_eval import literal_eval
from validate import validate
import traceback
import shutil

from exception import MusaException
from struct import pack, unpack
from tempfile import NamedTemporaryFile

from settings import *

db_conn = _mysql.connect(DATABASE_HOST, DATABASE_USER, DATABASE_PASSWORD, DATABASE_NAME)
db_conn.autocommit(False)

def authenticate(username, password):
	username = username.encode('utf-8')
	password = password.encode('utf-8')

	user_dn = "uid=" + username.lower() + ",ou=Users,dc=openttd,dc=org"
	ldap_conn = ldap.initialize(LDAP_HOST)
	try:
		ldap_conn.bind_s(user_dn, password)
	except ldap.INVALID_CREDENTIALS:
		raise MusaException("Invalid username/password")

	r = ldap_conn.search_s('ou=Users,dc=openttd,dc=org', ldap.SCOPE_SUBTREE, "(uid=" + username.lower() + ")", [ "memberOf" ])
	if not 'cn=BaNaNaS-Manager,ou=Manager,ou=Groups,dc=openttd,dc=org' in r[0][1]['memberOf']:
		raise MusaException("You are no bananas manager, you may not upload")

	return True

def check_content(username, metadata):
	db_conn.query("""
		SELECT bananas_file.id, filename, version, uniquemd5, blacklist, published, username
		FROM bananas_file
		JOIN bananas_type ON bananas_file.type_id = bananas_type.id
		JOIN bananas_file_authors ON bananas_file.id = bananas_file_authors.file_id
		JOIN bananas_author ON bananas_author.id = bananas_file_authors.author_id
		JOIN auth_user ON auth_user.id = bananas_author.user_id
		WHERE uniqueid = %d AND bananas_type.name = "%s"
		ORDER BY bananas_file.id
		""" % (metadata['uniqueid'], metadata['package_type']))

	prevId = None
	users = []
	for row in db_conn.store_result().fetch_row(maxrows=0):
		if row[1] == metadata['safe_name']:
			raise MusaException("this content is already uploaded (filename)")
		if row[2] == metadata['version']:
			raise MusaException("this content is already uploaded (version)")
		if row[3] == metadata['md5sum']:
			raise MusaException("this content is already uploaded (md5)")
		if row[4] == "1":
			raise MusaException("this content is blacklisted")
		if row[5] == "1":
			prevId = int(row[0])
			users.append(row[6])

	if len(users) > 0 and username not in users:
		raise MusaException("you are no author for this content; you cannot update it")

	if prevId == None and metadata['type'] in ['Scenario', 'Heightmap']:
		raise MusaException("heightmaps and scenarios must be initially uploaded via bananas web manager to obtain a uniqueid")

	metadata['prevId'] = prevId
	metadata['resolved_dependencies'] = []
	for dep in metadata['dependencies']:
		act_dep = dep.split(":")
		db_conn.query("""
			SELECT bananas_file.id FROM bananas_file
			JOIN bananas_type ON bananas_file.type_id = bananas_type.id
			WHERE uniqueid = %d AND bananas_type.name = "%s" AND uniquemd5 = "%s"
			""" % (int(act_dep[1], 16), act_dep[0], act_dep[2]))
		data = db_conn.store_result().fetch_row(maxrows=0)
		if len(data) == 0:
			raise MusaException("dependency %s not in bananas" % dep)
		if len(data) > 1:
			raise MusaException("duplicate %s dependencies in bananas" % dep)
		metadata['resolved_dependencies'].append(int(data[0][0]))

	metadata['resolved_authors'] = []
	for author in metadata['authors']:
		db_conn.query("""
			SELECT bananas_author.id
			FROM bananas_author
			JOIN auth_user ON auth_user.id = bananas_author.user_id
			WHERE username = '%s'
			""" % (_mysql.escape_string(author)))
		data = db_conn.store_result().fetch_row(maxrows=0)
		if len(data) == 0:
			raise MusaException("author %s not in bananas; this author must first accept bananas' terms" % author)
		if len(data) > 1:
			raise MusaException("duplicate %s authors in bananas" % author)
		metadata['resolved_authors'].append(int(data[0][0]))

def add_content(username, metadata, filename):
	db_conn.rollback()
	try:
		db_conn.query("""
			INSERT INTO bananas_file
			(name, filename, type_id, version, description, url, license_id, minimalVersion, maximalVersion,
					published, date, downloads, active, filesize, isMirrored, uniqueid, uniquemd5, blacklist)
			SELECT "%s", "%s", bananas_type.id, "%s", "%s", "%s", bananas_license.id, %d, %d,
					1, NOW(), 0, 1, %d, 0, %d, "%s", 0
			FROM bananas_type, bananas_license
			WHERE bananas_type.name = "%s" AND bananas_license.name = "%s"
		""" % (_mysql.escape_string(metadata['name']), _mysql.escape_string(metadata['safe_name']),
				_mysql.escape_string(metadata['version']), _mysql.escape_string(metadata['description']),
				_mysql.escape_string(metadata['url']), metadata['min_version'], metadata['max_version'],
				os.stat(filename).st_size, metadata['uniqueid'], _mysql.escape_string(metadata['md5sum']),
				_mysql.escape_string(metadata['package_type']), _mysql.escape_string(metadata['license_type'])))
		file_id = db_conn.insert_id()

		for author_id in metadata['resolved_authors']:
			db_conn.query("INSERT INTO bananas_file_authors (author_id, file_id) VALUES (%d, %d)" % (author_id, file_id))

		for dep_id in metadata['resolved_dependencies']:
			db_conn.query("INSERT INTO bananas_file_deps (from_file_id, to_file_id) VALUES (%d, %d)" % (file_id, dep_id))

		for tag in metadata['tags']:
			db_conn.query("SELECT id FROM bananas_tag WHERE name = '%s'" % (_mysql.escape_string(tag)))
			data = db_conn.store_result().fetch_row(maxrows=0)
			if len(data) > 1:
				raise MusaException("duplicate %s tags in bananas" % author)
			if len(data) == 0:
				db_conn.query("INSERT INTO bananas_tag (name) VALUES ('%s')" % (_mysql.escape_string(tag)))
				tag_id = db_conn.insert_id()
			else:
				tag_id = int(data[0][0])

			db_conn.query("INSERT INTO bananas_file_tags (tag_id, file_id) VALUES (%d, %d)" % (tag_id, file_id))

		if metadata['prevId'] is not None:
			db_conn.query("UPDATE bananas_file SET published=0, invalidatedBy_id=%d WHERE id=%d" % (file_id, metadata['prevId']))

		directory = os.path.join(DATA_PATH, "%d" % (file_id / 100))
		if not os.path.exists(directory):
			os.makedirs(directory)
		dest = os.path.join(directory, "%d.tar.gz" % file_id)
		shutil.copyfile(filename, dest)

		db_conn.commit()

		if ONADD_SHELL != None: os.system(ONADD_SHELL)
	except Exception, inst:
		try:
			# for some reason a rollback makes them linger somehow?!?
			db_conn.query("DELETE FROM bananas_file WHERE id = %d" % file_id)
		except:
			pass

		db_conn.rollback()
		raise inst

class MusaHandler(asyncore.dispatcher_with_send):
	def __init__(self, sock):
		asyncore.dispatcher_with_send.__init__(self, sock)
		self.state = self.handle_version
		self.data = ""
		self.size = -1
		self.file = None
		self.binary = False
		self.user = None

	def handle_version(self, version):
		if not isinstance(version, str):
			raise MusaException("invalid type for version")

		if version != "0.0.0":
			raise MusaException("please update your client to version %s" % version)

		self.state = self.handle_authorization

	def handle_authorization(self, info):
		if not isinstance(info, dict):
			raise MusaException("invalid type for info")

		if not "username" in info or not isinstance(info["username"], str): raise MusaException("invalid type for info")
		if not "password" in info or not isinstance(info["password"], str): raise MusaException("invalid type for info")
		if not "check"    in info or not isinstance(info["check"],    str): raise MusaException("invalid type for info")

		if info["check"] != "yes I am":
			raise MusaException("you are not the author of this content. You may not upload it")

		if not authenticate(info["username"], info["password"]):
			raise MusaException("could not authenticate")

		self.user = info["username"]
		self.state = self.handle_metadata

	def handle_metadata(self, metadata):
		if not isinstance(metadata, dict):
			raise MusaException("invalid type for metadata")

		self.metadata = metadata
		validate(self.metadata, None)

		if not self.user in self.metadata['authors']:
			raise MusaException("you are not listed as author for this content")

		check_content(self.user, self.metadata)
		self.send("metadata validated at server side")

		self.binary = True
		self.state = self.handle_upload

	def handle_close(self):
		if self.file is not None:
			self.file.close()
			self.file = None

	def handle_error(self):
		self.handle_close()

	def handle_upload(self, blob):
		if self.file is None:
			if len(blob) == 0:
				# No file is uploaded
				self.close()
				return

			self.file = NamedTemporaryFile(mode="wb", dir=TEMP_PATH)

		if len(blob) != 0:
			self.file.write(blob)
			return

		self.file.flush()

		try:
			tar = tarfile.open(self.file.name, mode='r:gz')
			validate(self.metadata, tar)
			tar.close()
		except:
			tar.close()
			raise

		# And push it into the database and such
		add_content(self.user, self.metadata, self.file.name)

		# Only close the file afterwards as this close removes the file
		self.file.close()
		self.file = None

		self.send("all okay, content uploaded into bananas")
		self.close()

	def read_data(self, amount):
			if amount == 0:
				return True

			self.data += self.recv(amount - len(self.data))
			return len(self.data) == amount

	def handle_read(self):
		try:
			if self.size < 0:
				if not self.read_data(2):
					return

				self.size = unpack('!H', self.data)[0]
				self.data = ""

			if not self.read_data(self.size):
				return

			self.state(self.data if self.binary else literal_eval(self.data))
			self.data = ""
			self.size = -1
		except ssl.SSLError:
			# Not enough bytes to read actual data from the stream
			pass
		except MusaException, inst:
			try:
				self.send("error: %s" % str(inst))
			except:
				pass

			print "Exception %s" % str(inst)
			self.close()
		except:
			print traceback.format_exc(10)
			self.close()
			raise

class MusaServer(asyncore.dispatcher):
	def __init__(self, host, port):
		asyncore.dispatcher.__init__(self)
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.set_reuse_addr()
		self.bind((host, port))
		self.listen(5)

	def handle_accept(self):
		pair = self.accept()
		if pair is None:
			pass
		else:
			sock, addr = pair
			print "Connection from %s" % repr(addr)
			try:
				sock = ssl.wrap_socket(sock, certfile="musa.pem", keyfile="musa.pem", server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)
				handler = MusaHandler(sock)
			except ssl.SSLError:
				print "No SSL validation for %s" % repr(addr)

server = MusaServer('0.0.0.0', 3980)
asyncore.loop()
