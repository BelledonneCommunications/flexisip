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

#include "wave.hh"

#include "tester.hh"
#include "utils/test-patterns/test.hh"

#include <fstream>

using namespace std;

namespace flexisip::tester {

filesystem::path createShortAudioFile(const TmpDir& tmpDir) {
	constexpr auto patternStartMs = 670;
	constexpr auto patternDurationMs = 1700; // 2360 - patternStartMs ("Hello this is Simon speaking")
	const auto& audioFilePath = tmpDir.path() / "hello-short.wav";
	const auto& helloPath = bcTesterRes("sounds/hello8000.wav");

	auto inputStream = std::ifstream(helloPath, std::ios::binary);
	using byte_type = decltype(inputStream)::char_type;
	WaveHeader header{};
	inputStream.read(reinterpret_cast<byte_type*>(&header), sizeof(header));

	// Endianness sanity check
	BC_ASSERT_CPP_EQUAL(header.format_chunk.len, 0x10);
	const auto bytesPerSample = header.format_chunk.blockalign * header.format_chunk.channels;
	BC_ASSERT_CPP_EQUAL(header.format_chunk.bitpspl, bytesPerSample * 8);
	const auto bytesPerSecond = header.format_chunk.rate * bytesPerSample;
	const auto bytesPerMs = bytesPerSecond / 1000;
	const auto patternSize = patternDurationMs * bytesPerMs;
	header.data_chunk.len = patternSize + 1; // +1 for EOF
	header.riff_chunk.len = header.data_chunk.len + header.format_chunk.len;

	// Write header
	auto clippedAudioStream = std::ofstream(audioFilePath, std::fstream::trunc | std::ios::binary);
	clippedAudioStream.write(reinterpret_cast<byte_type*>(&header), sizeof(header));

	// Copy data from input to output
	inputStream.seekg(patternStartMs * bytesPerMs, std::ios::cur);
	auto buffer = std::vector<byte_type>(patternSize, '\0');
	inputStream.read(buffer.data(), buffer.size());
	clippedAudioStream.write(buffer.data(), buffer.size());

	return audioFilePath;
}}