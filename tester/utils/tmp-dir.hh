/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <string>

#include "compat/filesystem.hh"

namespace flexisip {
namespace tester {

/**
 * Creates a directory with the given suffix in the writable directory of flexisip_tester then deletes it and all its
 * contents on destruction.
 * The directory name will start with a random prefix.
 */
class TmpDir {
	friend std::string operator+(const std::string&, const TmpDir&);

public:
	TmpDir(const char*);
	~TmpDir();

private:
	std::filesystem::path mPath;
};

/**
 * Convenience concat operator to build strings from a TmpDir path
 */
std::string operator+(const std::string&, const TmpDir&);

} // namespace tester
} // namespace flexisip
