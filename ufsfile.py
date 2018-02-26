#!/usr/bin/env python
"""
SAGE UFS file tool
Version: 1.0

Copyright (c) 2018 JrMasterModelBuilder
Licensed under the Mozilla Public License, v. 2.0

RNC ProPack unpacker code based on a class in ScummVM
"""

import os
import sys
import struct
import json
import argparse

unpacked_suffix = '.DIR'

def class_str(instance):
	return class_repr(instance)

def class_repr(instance):
	return '<%s: %s>' % (instance.__class__, instance.__dict__)




class RNCUnpackerError(Exception):
	pass

class RNCUnpackerMagicError(Exception):
	pass

class RNCUnpackerVersionError(Exception):
	pass

class RNCUnpackerCRCError(Exception):
	pass

class RNCUnpackerCRCPackedError(Exception):
	pass

class RNCUnpackerCRCUnpackedError(Exception):
	pass

class RNCUnpacker():
	MIN_LENGTH = 2

	MAGIC = b'RNC'

	VERSION_1 = 1

	struct_head = struct.Struct(''.join([
		'<',
		'3s', # magic
		'B', # version
		'I', # size_unpacked
		'I', # size_packed
		'H', # crc_unpacked
		'H', # crc_packed
		'x', # unused
		'B', # blocks
	]))

	def __str__(self):
		return class_str(self)

	def __repr__(self):
		return class_repr(self)

	def __init__(self):
		self.crc16_init()
		self.reset()

	def reset(self):
		self._src = None
		self._srcPtr = None
		self._bitBuffl = None
		self._bitBuffh = None
		self._bitCount = None
		self._rawTable = None
		self._posTable = None
		self._lenTable = None

	def crc16_init(self):
		table = [0] * 0x100
		for i in range(0x100):
			tmp = i
			for _ in range(8):
				if tmp % 2:
					tmp >>= 1
					tmp ^= 0xA001
				else:
					tmp >>= 1
			table[i] = tmp & 0xFFFF
		self.src16_table = table

	def crc16(self, data, seed=0, table=None):
		if table is None:
			table = self.src16_table
		crc = seed
		for i, _ in enumerate(data):
			tmp = ord(data[i:i+1])
			crc ^= tmp
			tmp = (crc >> 8) & 0x00FF
			crc &= 0x00FF
			crc = table[crc]
			crc ^= tmp
		return crc

	def read_le_uint16(self, offset):
		# Since if could be used out of range, pad extra null bytes if needed.
		d = self._src[offset:offset+2]
		while len(d) < 2:
			d += b'\x00'
		[r] = struct.unpack('<H', d)
		return r

	def inputBits(self, amount):
		if self._bitBuffl is None:
			self._bitBuffl = self.read_le_uint16(self._srcPtr)
			self._bitBuffh = 0
			self._bitCount = 0

		newBitBuffh = self._bitBuffh
		newBitBuffl = self._bitBuffl
		newBitCount = self._bitCount

		returnVal = ((1 << amount) - 1) & newBitBuffl
		newBitCount -= amount

		if newBitCount < 0:
			newBitCount += amount
			remBits = (newBitBuffh << (16 - newBitCount))
			newBitBuffh >>= newBitCount
			newBitBuffl >>= newBitCount
			newBitBuffl |= remBits
			self._srcPtr += 2
			newBitBuffh = self.read_le_uint16(self._srcPtr)
			amount -= newBitCount
			newBitCount = 16 - amount

		remBits = (newBitBuffh << (16 - amount)) & 0xFFFF
		self._bitBuffh = newBitBuffh >> amount
		self._bitBuffl = (newBitBuffl >> amount) | remBits
		self._bitCount = newBitCount

		return returnVal

	def makeHufftable(self):
		table = [0] * 64
		table_i = 0

		numCodes = self.inputBits(5)
		if numCodes == 0:
			return table

		huffLength = [0] * 16
		for i in range(numCodes):
			v = self.inputBits(4)
			huffLength[i] = v & 0x00FF

		huffCode = 0
		for bitLength in range(1, 17):
			for i in range(numCodes):
				if (huffLength[i] == bitLength):
					table[table_i] = ((1 << bitLength) - 1) & 0xFFFF
					table_i += 1

					b = huffCode >> (16 - bitLength)
					a = 0

					for j in range(bitLength):
						a |= ((b >> j) & 1) << (bitLength - j - 1)
					table[table_i] = a & 0xFFFF
					table_i += 1

					table[table_i + 0x1E] = ((huffLength[i] << 8) | (i & 0x00FF)) & 0xFFFF
					huffCode += (1 << (16 - bitLength)) & 0xFFFF
					huffCode &= 0xFFFF

		return table

	def inputValue(self, table):
		value = self._bitBuffl
		table_i = 0
		while True:
			valTwo = table[table_i] & value
			table_i += 1
			valOne = table[table_i]
			table_i += 1
			if valOne == valTwo:
				break

		value = table[table_i + 0x1E]
		self.inputBits((value>>8) & 0x00FF)
		value &= 0x00FF

		if value >= 2:
			value -= 1
			valOne = self.inputBits(value & 0x00FF)
			valOne |= (1 << value)
			value = valOne

		return value

	def unpack_v1(self, data):
		self.reset()

		[
			magic,
			version,
			size_unpacked,
			size_packed,
			crc_unpacked,
			crc_packed,
			blocks
		] = self.struct_head.unpack_from(data)

		if magic != self.MAGIC:
			hex_str = '%0X %0X %0X' % (
				ord(magic[0:1]),
				ord(magic[1:2]),
				ord(magic[2:3])
			)
			raise RNCUnpackerMagicError('Invalid magic "%s"' % (hex_str))

		if version != self.VERSION_1:
			raise RNCUnpackerVersionError('Invalid version: %i' % (version))

		body = data[self.struct_head.size:]

		body_crc = self.crc16(body)
		if body_crc != crc_packed:
			raise RNCUnpackerCRCPackedError('Invalid CRC: packed: 0x%X != 0x%X' % (
				body_crc,
				crc_packed
			))

		output = bytearray(size_unpacked)

		self._src = body
		self._srcPtr = 0
		self._dstPtr = 0

		self.inputBits(2)

		for _ in range(blocks):
			self._rawTable = self.makeHufftable()
			self._posTable = self.makeHufftable()
			self._lenTable = self.makeHufftable()

			counts = self.inputBits(16)
			while True:
				inputLength = self.inputValue(self._rawTable)

				if inputLength:
					output[
						self._dstPtr : self._dstPtr+inputLength
					] = self._src[
						self._srcPtr : self._srcPtr+inputLength
					]
					self._dstPtr += inputLength
					self._srcPtr += inputLength

					a = self.read_le_uint16(self._srcPtr)
					b = self.read_le_uint16(self._srcPtr + 2)

					self._bitBuffl &= ((1 << self._bitCount) - 1)
					self._bitBuffl |= (a << self._bitCount)
					self._bitBuffh = (a >> (16 - self._bitCount)) | (b << self._bitCount)

				if counts > 1:
					inputOffset = self.inputValue(self._posTable) + 1
					inputLength = self.inputValue(self._lenTable) + self.MIN_LENGTH

					# print(-inputOffset, inputLength)
					tmpPtr = self._dstPtr - inputOffset
					for _ in range(inputLength):
						output[self._dstPtr:self._dstPtr+1] = output[tmpPtr:tmpPtr+1]
						self._dstPtr += 1
						tmpPtr += 1

				counts -= 1
				if counts < 1:
					break

		self.reset()

		output = bytes(output)

		output_crc = self.crc16(output)
		if output_crc != crc_unpacked:
			raise RNCUnpackerCRCUnpackedError('Invalid CRC: unpacked: 0x%X != 0x%X' % (
				output_crc,
				crc_unpacked
			))

		return output




class UFSFileBase():
	def __str__(self):
		return class_str(self)

	def __repr__(self):
		return class_repr(self)

class UFSFileError(Exception):
	pass

class UFSFileTypeError(UFSFileError):
	pass

class UFSFileReadError(UFSFileError):
	pass

class UFSFileReadEntryError(UFSFileError):
	pass

class UFSFileReadEntry(UFSFileBase):
	struct_entry = struct.Struct(''.join([
		'<',
		'I', # kind
		'32s', # name
		'I', # offset
		'I', # size_compressed
		'I' # size_uncompressed
	]))

	def __init__(
		self,
		kind = 0,
		name = b'\xCD' * 32,
		offset = 0,
		size_compressed = 0,
		size_uncompressed = 0
	):
		self.kind = kind
		self.name = name
		self.offset = offset
		self.size_compressed = size_compressed
		self.size_uncompressed = size_uncompressed
		self.rnc_unpacker = None

	def from_read(self, read):
		[
			kind,
			name,
			offset,
			size_compressed,
			size_uncompressed
		] = read.read_struct(self.struct_entry)
		self.kind = kind
		self.name = name
		self.offset = offset
		self.size_compressed = size_compressed
		self.size_uncompressed = size_uncompressed

	def get_rnc_unpacker(self):
		if not self.rnc_unpacker:
			self.rnc_unpacker = RNCUnpacker()
		return self.rnc_unpacker

	def get_name(self):
		return self.name.split(b'\x00')[0]

	def get_is_valid(self):
		return self.kind != 0

	def get_is_compressed(self):
		return self.kind == 0x41

	def read_from(self, read):
		compressed = self.get_is_compressed()
		if not compressed and self.size_compressed != self.size_uncompressed:
			raise UFSFileTypeError(
				'Unexpected %s and %s mismatch (compression?): %s != %s' % (
					'size_compressed',
					'size_uncompressed',
					self.size_compressed,
					self.size_uncompressed
				)
			)
		read.seek(self.offset)
		data = read.read(self.size_compressed)
		if compressed:
			data = self.get_rnc_unpacker().unpack_v1(data)
		return data

class UFSFileRead(UFSFileBase):
	MAGIC = 3

	struct_header = struct.Struct(''.join([
		'<',
		'I', # magic
		'I', # count
		'I', # valid
		'I', # size
		'20s' # padding
	]))

	entries_offset = struct_header.size

	def __init__(self, fio, offset=None, size_max=None):
		# If offset set, use the current input offset.
		if offset is None:
			offset = fio.tell()

		# If maximum set, determine how much input available.
		if size_max is None:
			# Find how much data remains after input offset.
			before = fio.tell()
			fio.seek(0, os.SEEK_END)
			size_max = fio.tell() - offset
			fio.seek(before, os.SEEK_SET)

		# Set needed properties to use the reading methods.
		self.fio = fio
		self.__pos = 0
		self.offset = 0

		# Temporarily set the size to the input limit.
		# Actual size set below after reading the header, and may be smaller.
		self.size = size_max

		# Check that files is large enough to read header.
		if size_max < self.struct_header.size:
			raise UFSFileReadError('Input size too small: %s' % (size_max))

		[
			magic,
			count,
			valid,
			size,
			padding
		] = self.read_struct(self.struct_header)

		# Check the header magic.
		if magic != self.MAGIC:
			raise UFSFileReadError('Invalid input header magic: %s' % (magic))
		self.magic = magic

		# Check the header magic.
		if valid != 1 and valid != 0:
			raise UFSFileReadError('Invalid header valid flag: %s' % (valid))
		self.valid = valid

		# Check size within input limit, before limiting to header size.
		if size_max < size:
			raise UFSFileReadError(
				'Header size (%s) smaller than input size: %s' %
				(size, size_max)
			)
		self.size = size

		# Set properties.
		self.count = count
		self.padding = padding

		# Move the file IO to the file end.
		fio.seek(size, os.SEEK_CUR)

	def read(self, size):
		pos = self.__pos
		fio = self.fio
		before = fio.tell()
		seekto = self.offset + pos

		if seekto + size > self.size:
			raise UFSFileReadError('Cannot read past end of file')

		fio.seek(seekto, os.SEEK_SET)
		ret = fio.read(size)
		fio.seek(before, os.SEEK_SET)
		read_size = len(ret)

		if read_size != size:
			raise UFSFileReadError('Read an unexpected sizeL %s' % (read_size))

		self.__pos = pos + read_size
		return ret

	def tell(self):
		return self.__pos

	def seek(self, offset, from_what=os.SEEK_SET):
		pos = None
		if from_what == os.SEEK_CUR:
			pos = self.__pos + offset
		elif from_what == os.SEEK_END:
			pos = self.__pos - offset
		elif from_what == os.SEEK_SET:
			pos = offset
		else:
			raise UFSFileTypeError('Invalid seek from type: %s' % (from_what))

		if pos < 0 or pos > self.size:
			raise UFSFileReadError('Cannot seek to: %s' % (pos))

		self.__pos = pos

	def can_read(self, size):
		return self.__pos + size < self.size

	def read_struct(self, structure):
		return structure.unpack_from(self.read(structure.size))

	def entries(self):
		entries_offset = self.entries_offset

		# Seek to entries offset.
		self.seek(entries_offset, os.SEEK_SET)

		# Loop over the entries.
		for i in range(self.count):
			# Read entry.
			entry = UFSFileReadEntry()
			entry.from_read(self)

			# Remember current file position, yield, then reset position.
			before = self.tell()
			yield entry
			self.seek(before, os.SEEK_SET)

	def entry_read(self, entry):
		return entry.read_from(self)

def process_file(options, path):
	print('File: %s' % (path))

	outdir = '%s%s' % (path, unpacked_suffix)

	# Open the file for binary reading.
	with open(path, 'rb') as fi:
		# Use the reader class.
		ufs = UFSFileRead(fi)

		# File properties.
		print('  count: %i' % (ufs.count))
		print('  valid: %i' % (ufs.valid))
		print('  size: 0x%08X' % (ufs.size))

		# Create output directory unless just listing.
		if not options.list:
			if os.path.exists(outdir):
				raise UFSFileError(
					'Output directory already exists: %s' % (
						outdir
					)
				)
			os.mkdir(outdir)

		# Loop over the entries.
		print('  entries:')
		for entry_i, entry in enumerate(ufs.entries()):
			name = entry.get_name().decode('ascii')

			# print information on entry.
			print('    [%%%ii]: %s' % (
				len(str(ufs.count)),
				(', '.join([
					'kind: 0x%08X',
					'offset: 0x%08X',
					'size_compressed: 0x%08X',
					'size_uncompressed: 0x%08X',
					'name: %s'
				]))
			) % (
				entry_i,
				entry.kind,
				entry.offset,
				entry.size_compressed,
				entry.size_uncompressed,
				json.dumps(name)
			))

			# If just listing skip extracting file.
			if options.list:
				continue

			# Skip the invalid entries.
			if not entry.get_is_valid():
				continue

			# If name is empty, cannot extract.
			if not len(name):
				raise UFSFileError('Unexpected empty name on valid entry, cannot extract')

			# Write the file to output directory.
			outfile = os.path.join(outdir, name)
			with open(outfile, 'wb') as fo:
				fo.write(ufs.entry_read(entry))
				fo.close()

		fi.close()

def process(options):
	for path in options.paths:
		if os.path.isdir(path):
			raise UFSFileError('Creating archives is unsupported: %s' % (path))
		elif os.path.isfile(path):
			process_file(options, path)
		else:
			raise UFSFileError('Path is not valid: %s' % (path))
	return 0

def main():
	parser = argparse.ArgumentParser(
		description=os.linesep.join([
			'SAGE UFS file tool',
			'Version: 1.0'
		]),
		epilog=os.linesep.join([
			'Copyright (c) 2018 JrMasterModelBuilder',
			'Licensed under the Mozilla Public License, v. 2.0',
			'',
			'RNC ProPack unpacker code based on a class in ScummVM'
		]),
		formatter_class=argparse.RawTextHelpFormatter
	)
	parser.add_argument(
		'-l',
		'--list',
		action='store_true',
		help='Just list the files'
	)
	parser.add_argument(
		'paths',
		nargs='+',
		help='Paths to run on'
	)
	return process(parser.parse_args())

if __name__ == '__main__':
	sys.exit(main())
