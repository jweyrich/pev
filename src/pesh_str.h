/*
	pev - the PE file analyzer toolkit

	pesh_str.h - ...

	Copyright (C) 2014 pev authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <string.h>

//
// Description:
//   Fills a 256-byte bytemask with input.
//
void str_fill_charmask(unsigned char *mask, const unsigned char *input, size_t length) {
	memset(mask, 0, 256);
	for (size_t i=0; i < length; ++i) {
		unsigned char c = input[i];
		mask[c] = 1;
	}
}

typedef enum {
	STR_TRIM_LEFT			= 1,
	STR_TRIM_RIGHT			= 2,
	STR_TRIM_LEFT_AND_RIGHT	= STR_TRIM_LEFT | STR_TRIM_RIGHT,
} str_trim_mode_e;

//
// Description:
//   Strips whitespace from the beginning and end of `str`.
// Return value:
//   A newly allocated string.
//   The user is responsible for its deallocation.
// Arguments:
//   str - String to be trimmed.
//   input_mask - which characters should be trimmed from `str`.
//   input_mask_size - how many characters does `input_mask` contain.
//   mode - what kind of trimming should be done (left, right, or both).
//
char *str_trim_ex(
	const char *str,
	size_t length,
	const char *input_mask,
	size_t input_mask_size,
	str_trim_mode_e mode)
{
	unsigned char charmask[256];
	str_fill_charmask(charmask, (unsigned char *)input_mask, input_mask_size);

	unsigned char *str_ptr = (unsigned char *)str;
	int trimmed = 0;

	if (mode & STR_TRIM_LEFT) {
		for (size_t i = 0; i < length; ++i) {
			if (charmask[str_ptr[i]]) {
				trimmed++;
			} else {
				break;
			}
		}
		length -= trimmed;
		str_ptr += trimmed;
	}

	if (mode & STR_TRIM_RIGHT) {
		for (int i = length - 1; i >= 0; --i) {
			if (charmask[str_ptr[i]]) {
				length--;
			} else {
				break;
			}
		}
	}

	// strndup conforms to POSIX.1-2008. Not available on Windows.
	char *result = strndup((char *)str_ptr, length);
	return result;
}

char *str_trim(const char *str, size_t length, str_trim_mode_e mode) {
	static const char whitespaces[] = {
		' ',	// whitespace
		'\t',	// horizontal tab (HT)
		'\r',	// carriage return (CR)
		'\n',	// line feed (LF)
		'\0',	// null character (NUL)
		'\v'	// vertical tab (VT)
	};
	// TODO(jweyrich): USE LIBPE_SIZEOF_ARRAY?
	static const size_t whitespaces_size = sizeof(whitespaces) / sizeof(whitespaces[0]);
	return str_trim_ex(str, length, whitespaces, whitespaces_size, mode);
}
