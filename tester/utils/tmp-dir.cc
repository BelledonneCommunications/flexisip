/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "tester.hh"
#include "utils/rand.hh"

#include "tmp-dir.hh"

using namespace std;

namespace flexisip {
namespace tester {

TmpDir::TmpDir(const char* suffix)
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

} // namespace tester
} // namespace flexisip
