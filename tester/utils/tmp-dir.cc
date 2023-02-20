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
TmpDir::~TmpDir() {
	filesystem::remove_all(mPath);
}

string operator+(const string& str, const TmpDir& tmpDir) {
	return str + tmpDir.mPath.string();
}

} // namespace tester
} // namespace flexisip
