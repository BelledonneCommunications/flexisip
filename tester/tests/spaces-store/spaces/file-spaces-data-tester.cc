/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "spaces-store/spaces/file-spaces-data.hh"

#include <filesystem>
#include <fstream>
#include <vector>

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "shared-tests.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester {
namespace {

namespace legacy {

/*
 * Test legacy domains loading at initialization.
 */
void spacesLoading() {
	vector<flexiapi::Space> actualSpaces{};
	const auto onSpacesChanged = [&actualSpaces](const std::vector<flexiapi::Space>& spaces) { actualSpaces = spaces; };

	const auto store = make_shared<FileSpacesData>(list<string>{kTestDomains[0], kTestDomains[1]}, onSpacesChanged);

	flexisip::tester::hasSpaces(actualSpaces, kTestSpaces);
}

} // namespace legacy

/*
 * Test spaces loading from a JSON data file.
 */
void spacesLoading() {
	vector<flexiapi::Space> actualSpaces{};
	const auto notifySpacesChangedCb = [&](const vector<flexiapi::Space>& spaces) { actualSpaces = spaces; };
	const auto filePath = filesystem::temp_directory_path() / "flexisip-file-spaces-data-tester.json";

	{
		ofstream file{filePath};
		file << kTestSpacesJson;
	}

	const auto store = make_shared<FileSpacesData>(filePath.string(), notifySpacesChangedCb);

	flexisip::tester::hasSpaces(actualSpaces, kTestSpaces);
	filesystem::remove(filePath);
}

const TestSuite kSuite{
    "FileSpacesData",
    {
        CLASSY_TEST(legacy::spacesLoading),
        CLASSY_TEST(spacesLoading),
    },
};

} // namespace
} // namespace flexisip::tester