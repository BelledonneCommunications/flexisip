/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <filesystem>
#include <string>

namespace flexisip::tester {

/**
 * Creates a directory with the given prefix in the writable directory of flexisip_tester then deletes it and all its
 * contents on destruction.
 * The directory name will start with a random suffix.
 */
class TmpDir {
public:
	explicit TmpDir(const char*);
	~TmpDir();

	TmpDir(const TmpDir&) = delete;
	TmpDir(TmpDir&&) noexcept = default;

	const auto& path() const {
		return mPath;
	}

private:
	std::filesystem::path mPath;
};

} // namespace flexisip::tester
