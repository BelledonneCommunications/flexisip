/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <string>

namespace flexisip {
namespace tester {

/**
 * Create a file in a temporary location on construction, delete it on destruction.
 */
class TempFile {
public:
	TempFile() {
		char name[] = "/tmp/flexitest_XXXXXX"; // last 6 X characters are mandatory
		auto fd = mkstemp(name);
		if (fd == -1) throw std::runtime_error("A temporary file cannot be created.");
		if (close(fd) != 0) throw std::runtime_error("Error while creating a temporary file.");
		filename = name;
	}

	template <class Streamable>
	TempFile(Streamable content) : TempFile() {
		writeStream() << content;
	}

	~TempFile() {
		std::remove(filename.c_str());
	}

	/** Overwrite the contents of the file */
	std::ofstream writeStream() const {
		std::ofstream wStream(filename);
		return wStream;
	}

	const std::string& getFilename() const {
		return filename;
	}

private:
	std::string filename;
};

} // namespace tester
} // namespace flexisip
