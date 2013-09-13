# $Id$
#
# This file is part of musa.
# musa is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2.
# musa is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details. You should have received a copy of the GNU General Public License along with musa. If not, see <http://www.gnu.org/licenses/>.
#

from exception import MusaException
import array
import os

grfv2header = list(array.array('B', [0x00, 0x00, ord('G'), ord('R'), ord('F'), 0x82, 0x0D, 0x0A, 0x1A, 0x0A]))

class GRFIDReader():
	def __init__(self, file):
		self.file = file
		self.fill_buffer()

	def fill_buffer(self):
		self.buffer = [ ord(i) for i in self.file.read(8192) ]
		if len(self.buffer) == 0:
			raise MusaException("Invalid GRF")

	def skip_bytes(self, count):
		for i in range(0, count):
			self.read_byte()

	def read_byte(self):
		if len(self.buffer) == 0:
			self.fill_buffer()
		return int(self.buffer.pop(0))

	def read_word(self):
		ret = self.read_byte()
		return ret | self.read_byte() << 8

	def read_dword(self):
		ret = self.read_word()
		return ret | self.read_word() << 16

	def skip_sprite_data(self, type, num):
		if type & 2:
			self.skip_bytes(num)
		else:
			while num > 0:
				i = self.read_byte();
				if i >= 0x80: i -= 0x100
				if i >= 0:
					size = 0x80 if i == 0 else i;
					num -= size;
					self.skip_bytes(size)
				else:
					i = -(i >> 3);
					num -= i;
					self.read_byte();

	def swap(self, x):
		return ((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | ((x << 24) & 0xFF000000);

	def read_size(self, grfcontversion):
		ret = self.read_dword() if grfcontversion == 2 else self.read_word();
		return ret

def get_grfid(f):
	try:
		reader = GRFIDReader(f)
		grfcontversion = 1;

		# Check version
		if reader.buffer[0:len(grfv2header)] == grfv2header:
			grfcontversion = 2
			reader.skip_bytes(len(grfv2header) + 4 + 1)

		if reader.read_size(grfcontversion) != 0x04 or reader.read_byte() != 0xFF:
			raise MusaException("No magic header")

		reader.read_dword()

		while True:
			num = reader.read_size(grfcontversion)
			if num == 0:
				# End of file, but no GRFID
				raise MusaException("No GRFID")

			type = reader.read_byte()
			if type == 0xFF:
				action = reader.read_byte()
				if action == 0x08:
					# Ignored version
					reader.read_byte()
					# Finally... the GRFID
					return reader.swap(reader.read_dword())
				else:
					# Skip pseudo sprites
					reader.skip_bytes(num - 1)
			else:
				# Skip real sprites
				reader.skip_bytes(7)
				reader.skip_sprite_data(type, num - 8)
	except Exception, inst:
		f.close()
		raise inst
