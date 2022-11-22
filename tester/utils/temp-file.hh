/** Copyright (C) 2010-2022 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstdio>
#include <fstream>

namespace flexisip {
namespace tester {

/**
 * Create a file in a temporary location on construction, delete it on destruction.
 */
struct TempFile {
	const char* const name;

	TempFile() : name(std::tmpnam(nullptr)) {
	}

	template <class Streamable>
	TempFile(Streamable content) : TempFile() {
		writeStream() << content;
	}

	~TempFile() {
		std::remove(name);
	}

	/** Overwrite the contents of the file */
	std::ofstream writeStream() const {
		std::ofstream wStream(name);
		return wStream;
	}
};

} // namespace tester
} // namespace flexisip
