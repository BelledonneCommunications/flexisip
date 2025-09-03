/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/


#pragma once

#include <cstdint>
#include <filesystem>

#include "utils/tmp-dir.hh"

namespace flexisip::tester {

struct WaveHeader {
	struct {
		char riff[4]; /* "RIFF" (ASCII characters) */
		std::uint32_t len; /* Length of package (binary, little endian) */
		char wave[4]; /* "WAVE" (ASCII characters) */
	} riff_chunk;
	struct {
		char fmt[4];         /* "fmt_" (ASCII characters) */
		std::uint32_t len;        /* length of FORMAT chunk (always 0x10) */
		std::uint16_t type;       /* codec type*/
		std::uint16_t channels;   /* number of channels (0x01 = mono, 0x02 = stereo) */
		std::uint32_t rate;       /* Sample rate (binary, in Hz) */
		std::uint32_t bps;        /* Average Bytes Per Second */
		std::uint16_t blockalign; /* bytes per sample */
		std::uint16_t bitpspl;    /* bits per sample */
	} format_chunk;
	struct {
		char data[4]; /* "data" (ASCII characters) */
		std::uint32_t len; /* length of data */
	} data_chunk;
};

/**
 * Create a short version of sounds/hello8000.wav
 *
 * @param tmpDir temporary directory to store the generated audio file
 * @return Path to the new audio file
 */
std::filesystem::path createShortAudioFile(const TmpDir& tmpDir);
}