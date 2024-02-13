/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <filesystem>
#include <string>

namespace flexisip {
namespace tester {

/**
 * Creates a directory with the given suffix in the writable directory of flexisip_tester then deletes it and all its
 * contents on destruction.
 * The directory name will start with a random prefix.
 */
class TmpDir {
public:
	TmpDir(const char*);
	~TmpDir();

	const auto& path() const {
		return mPath;
	}

private:
	std::filesystem::path mPath;
};

} // namespace tester
} // namespace flexisip
