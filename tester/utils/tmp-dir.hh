/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
	explicit TmpDir(const std::string&);
	~TmpDir();

	TmpDir(const TmpDir&) noexcept = delete;
	TmpDir& operator=(const TmpDir&) noexcept = delete;
	TmpDir(TmpDir&&) noexcept;
	TmpDir& operator=(TmpDir&&) noexcept;

	const auto& path() const {
		return mPath;
	}

private:
	std::filesystem::path mPath;
};

} // namespace flexisip::tester