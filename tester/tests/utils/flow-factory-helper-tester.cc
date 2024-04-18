/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include "utils/flow.hh"

#include <filesystem>
#include <fstream>

#include <flexisip/logmanager.hh>

#include "flexisip-config.h"
#include "tester.hh"
#include "utils/flow-test-helper.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
namespace fs = filesystem;

namespace flexisip::tester {

using Helper = FlowTestHelper;

namespace {

void makeFlowFactoryHelper() {
	const auto filePath = bcTesterWriteDir().append("flow-token-hash-key-test");
	filesystem::remove(filePath);

	BC_HARD_ASSERT(filesystem::exists(filePath) == false);

	const auto flowFactoryHelper = FlowFactory::Helper(filePath);

	BC_HARD_ASSERT(filesystem::exists(filePath) == true);

	const auto hashKeySize = filesystem::file_size(filePath);
	BC_HARD_ASSERT(hashKeySize == flowFactoryHelper.getHashKey().size());

	fstream file;
	file.open(filePath.c_str(), ios_base::in);
	char buffer[hashKeySize];
	file.read(buffer, hashKeySize);
	file.close();

	const auto hashKey = flowFactoryHelper.getHashKey();
	BC_ASSERT_CPP_EQUAL(string(buffer, buffer + hashKeySize), string(hashKey.data(), hashKey.data() + hashKeySize));
}

void makeFlowFactoryHelperFromExistingHashKeyFile() {
	const auto flowFactoryHelper = FlowFactory::Helper(kHashKeyFilePath);
	const auto& hashKey = flowFactoryHelper.getHashKey();
	const auto hashKeySize = hashKey.size();

	fstream file;
	file.open(kHashKeyFilePath, ios_base::in);
	char buffer[hashKeySize];
	file.read(buffer, hashKeySize);
	file.close();

	BC_ASSERT_CPP_EQUAL(string(buffer, buffer + hashKeySize), string(hashKey.data(), hashKey.data() + hashKeySize));
}

void makeFlowFactoryHelperPermissionDeniedToCreateFolder() {
	const auto filePath = filesystem::path("/folder") / "file";

	BC_ASSERT_THROWN(FlowFactory::Helper{filePath}, runtime_error);
}

void makeFlowFactoryHelperFailToReadHashKeyFile() {
	const auto filePath = filesystem::path(kHashKeyFilePath).parent_path() / "flow-token-hash-key-corrupted";

	BC_ASSERT_THROWN(FlowFactory::Helper{filePath}, runtime_error);
}

void encodeFlowTokenIPV4() {
	const Helper helper{};
	const auto expected = Helper::getSampleFlowToken(AF_INET);

	const auto flowToken = helper.mFactoryHelper.encode(helper.getSampleFlowData(AF_INET).raw());

	BC_ASSERT_CPP_EQUAL(flowToken, expected);
}

void encodeFlowTokenIPV6() {
	const Helper helper{};
	const auto expected = Helper::getSampleFlowToken(AF_INET6);

	const auto flowToken = helper.mFactoryHelper.encode(helper.getSampleFlowData(AF_INET6).raw());

	BC_ASSERT_CPP_EQUAL(flowToken, expected);
}

void decodeFlowTokenIPV4() {
	const auto [data, hmac] = FlowFactory::Helper::decode(Helper::getSampleFlowToken(AF_INET));

	BC_ASSERT_CPP_EQUAL(hmac, Helper::getSampleFlowHash(AF_INET));
	BC_ASSERT_CPP_EQUAL(data.getLocalAddress()->str(), "1.2.3.4:5678");
	BC_ASSERT_CPP_EQUAL(data.getRemoteAddress()->str(), "1.2.3.4:5678");
	BC_ASSERT(data.getTransportProtocol() == FlowData::Transport::Protocol::tcp);
}

void decodeFlowTokenIPV6() {
	const auto [data, hmac] = FlowFactory::Helper::decode(Helper::getSampleFlowToken(AF_INET6));

	BC_ASSERT_CPP_EQUAL(hmac, Helper::getSampleFlowHash(AF_INET6));
	BC_ASSERT_CPP_EQUAL(data.getLocalAddress()->str(), "[102:304:506:708:90a:b0c:d0e:f10]:5678");
	BC_ASSERT_CPP_EQUAL(data.getRemoteAddress()->str(), "[102:304:506:708:90a:b0c:d0e:f10]:5678");
	BC_ASSERT(data.getTransportProtocol() == FlowData::Transport::Protocol::tcp);
}

void decodeTokenWrongInput() {
	BC_ASSERT_THROWN(FlowFactory::Helper::decode("_"), runtime_error);
}

void hashFlowRawDataIPV4() {
	const Helper helper{};
	const auto expected = Helper::getSampleFlowHash(AF_INET);

	const auto hash = helper.mFactoryHelper.hash(helper.getSampleFlowData(AF_INET).raw());

	BC_ASSERT_CPP_EQUAL(hash, expected);
}

void hashFlowRawDataIPV6() {
	const Helper helper{};
	const auto expected = Helper::getSampleFlowHash(AF_INET6);

	const auto hash = helper.mFactoryHelper.hash(helper.getSampleFlowData(AF_INET6).raw());

	BC_ASSERT_CPP_EQUAL(hash, expected);
}

void readSocketAddressFromRawTokenIPV4() {
	const auto rawToken = Helper::getSampleRawToken(AF_INET);

	const auto local = FlowFactory::Helper::readSocketAddressFromRawToken(rawToken, FlowData::Address::local);
	BC_ASSERT_CPP_EQUAL(local->str(), "1.2.3.4:5678");
	BC_ASSERT_CPP_EQUAL(local->getAddressFamily(), AF_INET);

	const auto remote = FlowFactory::Helper::readSocketAddressFromRawToken(rawToken, FlowData::Address::remote);
	BC_ASSERT_CPP_EQUAL(remote->str(), "1.2.3.4:5678");
	BC_ASSERT_CPP_EQUAL(remote->getAddressFamily(), AF_INET);
}

void readSocketAddressFromRawTokenIPV6() {
	const auto rawToken = Helper::getSampleRawToken(AF_INET6);

	const auto local = FlowFactory::Helper::readSocketAddressFromRawToken(rawToken, FlowData::Address::local);
	BC_ASSERT_CPP_EQUAL(local->str(), "[102:304:506:708:90a:b0c:d0e:f10]:5678");
	BC_ASSERT_CPP_EQUAL(local->getAddressFamily(), AF_INET6);

	const auto remote = FlowFactory::Helper::readSocketAddressFromRawToken(rawToken, FlowData::Address::remote);
	BC_ASSERT_CPP_EQUAL(remote->str(), "[102:304:506:708:90a:b0c:d0e:f10]:5678");
	BC_ASSERT_CPP_EQUAL(remote->getAddressFamily(), AF_INET6);
}

void readSocketAddressFromRawTokenWithWrongSize() {
	BC_ASSERT_THROWN(FlowFactory::Helper::readSocketAddressFromRawToken({}, FlowData::Address::local), runtime_error);
}

TestSuite _("FlowFactory::Helper",
            {
                TEST_NO_TAG_AUTO_NAMED(makeFlowFactoryHelper),
                TEST_NO_TAG_AUTO_NAMED(makeFlowFactoryHelperFromExistingHashKeyFile),
                TEST_NO_TAG_AUTO_NAMED(makeFlowFactoryHelperPermissionDeniedToCreateFolder),
                TEST_NO_TAG_AUTO_NAMED(makeFlowFactoryHelperFailToReadHashKeyFile),
                TEST_NO_TAG_AUTO_NAMED(encodeFlowTokenIPV4),
                TEST_NO_TAG_AUTO_NAMED(encodeFlowTokenIPV6),
                TEST_NO_TAG_AUTO_NAMED(decodeFlowTokenIPV4),
                TEST_NO_TAG_AUTO_NAMED(decodeFlowTokenIPV6),
                TEST_NO_TAG_AUTO_NAMED(decodeTokenWrongInput),
                TEST_NO_TAG_AUTO_NAMED(hashFlowRawDataIPV4),
                TEST_NO_TAG_AUTO_NAMED(hashFlowRawDataIPV6),
                TEST_NO_TAG_AUTO_NAMED(readSocketAddressFromRawTokenIPV4),
                TEST_NO_TAG_AUTO_NAMED(readSocketAddressFromRawTokenIPV6),
                TEST_NO_TAG_AUTO_NAMED(readSocketAddressFromRawTokenWithWrongSize),
            });
} // namespace

} // namespace flexisip::tester
