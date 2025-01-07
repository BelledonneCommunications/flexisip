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

#include "tester.hh"
#include "utils/rand.hh"

#include "tmp-dir.hh"

using namespace std;

namespace flexisip::tester {

TmpDir::TmpDir(const std::string& suffix)
    : mPath(bcTesterWriteDir() / (Rand::generate(10, string{"0123456789abcdefghijklmnopqrstuvwxyz"}) + suffix)) {
	filesystem::create_directory(mPath);
}

TmpDir::TmpDir(TmpDir&& other) noexcept : mPath() {
	*this = std::move(other);
}

TmpDir& TmpDir::operator=(TmpDir&& other) noexcept {
	// The moved-from TmpDir must have an empty path so it does not clean up files when destructed.
	// The C++ standard only guarantees that moved-from objects remain valid, not that they should represent an empty
	// state. If it is cheaper to copy the state from a path without emptying it on move, then an implementation is
	// allowed to do that, so it is our job to clear the moved-from path.
	mPath.swap(other.mPath);
	return *this;
}

TmpDir::~TmpDir() {
	filesystem::remove_all(mPath);
}

} // namespace flexisip::tester