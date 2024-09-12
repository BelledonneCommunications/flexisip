/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "tester.hh"

#include "tmp-dir.hh"

using namespace std;

namespace flexisip::tester {

TmpDir::TmpDir(const char* prefix) : mPath(bcTesterWriteDir() / (prefix + randomString(10))) {
	filesystem::create_directory(mPath);
}

TmpDir::~TmpDir() {
	filesystem::remove_all(mPath);
}

} // namespace flexisip::tester
