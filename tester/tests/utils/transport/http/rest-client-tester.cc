/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "lib/nlohmann-json-3-11-2/json.hpp"
#include "utils/asserts.hh"
#include "utils/http-mock/http-mock.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/transport/http/rest-client.hh"

using namespace std;
using namespace std::chrono;
using namespace nlohmann;

namespace flexisip {
namespace tester {

// ####################################################################################################################
// ################################################### ABSTRACT TEST CLASS ############################################
// ####################################################################################################################

class RestTest : public Test {
public:
	void operator()() override {
		HttpMock httpMock{"/api/test"};
		int port = httpMock.serveAsync();
		BC_HARD_ASSERT_TRUE(port > -1);

		HttpHeaders httpHeaders{};
		httpHeaders.add(":authority", "localhost");
		httpHeaders.add("custom_header", "custom_header_value");
		httpHeaders.add("custom_header2", "custom_header_value2");
		RestClient restClient{Http2Client::make(mRoot, "localhost", to_string(port)), httpHeaders};

		sendRequest(restClient);

		BcAssert asserter{[this] { mRoot.step(1ms); }};
		BC_HARD_ASSERT_TRUE(asserter.iterateUpTo(10, [this] { return mRequestReceived; }));

		httpMock.forceCloseServer();
		mRoot.step(10ms); // needed to acknowledge mock server closing

		const auto actualRequest = httpMock.popRequestReceived();
		BC_HARD_ASSERT(actualRequest != nullptr);

		customAssert(actualRequest);
		BC_ASSERT_CPP_EQUAL(actualRequest->headers.size(), 3);
		BC_HARD_ASSERT_CPP_EQUAL(actualRequest->headers.count("custom_header"), 1);
		BC_HARD_ASSERT_CPP_EQUAL(actualRequest->headers.find("custom_header")->second.value, "custom_header_value");
		BC_HARD_ASSERT_CPP_EQUAL(actualRequest->headers.count("custom_header2"), 1);
		BC_HARD_ASSERT_CPP_EQUAL(actualRequest->headers.find("custom_header2")->second.value, "custom_header_value2");
	}

protected:
	virtual void sendRequest(RestClient& restClient) = 0;
	virtual void customAssert(const shared_ptr<Request>& actualRequest) = 0;

	bool mRequestReceived;
	sofiasip::SuRoot mRoot{};
};

// ####################################################################################################################
// ################################################### ACTUAL TESTS ###################################################
// ####################################################################################################################

class PostRestTest : public RestTest {
protected:
	void sendRequest(RestClient& restClient) override {
		json json = {{"la_creme", "épaisse"}};
		restClient.post(
		    "/api/test", json, [this](const auto&, const auto&) { mRequestReceived = true; },
		    [](const auto&) { BC_HARD_FAIL("Request must succeed"); });
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
		BC_ASSERT_CPP_EQUAL(actualRequest->body, "{\"la_creme\":\"épaisse\"}");
	}
};

class PutRestTest : public RestTest {
protected:
	void sendRequest(RestClient& restClient) override {
		json json = {{"la_creme", "entière"}};
		restClient.put(
		    "/api/test", json, [this](const auto&, const auto&) { mRequestReceived = true; },
		    [](const auto&) { BC_HARD_FAIL("Request must succeed"); });
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "PUT");
		BC_ASSERT_CPP_EQUAL(actualRequest->body, "{\"la_creme\":\"entière\"}");
	}
};

class PatchRestTest : public RestTest {
protected:
	class JsonObject {
	public:
		JsonObject(const string& string, int integer) : aString(string), integer(integer) {
		}

	private:
		string aString;
		int integer;
		NLOHMANN_DEFINE_TYPE_INTRUSIVE(JsonObject, aString, integer)
	};
	void sendRequest(RestClient& restClient) override {
		JsonObject jsonObject{"42", 42};
		restClient.patch(
		    "/api/test", jsonObject, [this](const auto&, const auto&) { mRequestReceived = true; },
		    [](const auto&) { BC_HARD_FAIL("Request must succeed"); });
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
		BC_ASSERT_CPP_EQUAL(actualRequest->body, "{\"aString\":\"42\",\"integer\":42}");
	}
};

class GetRestTest : public RestTest {
protected:
	void sendRequest(RestClient& restClient) override {
		restClient.get(
		    "/api/test", [this](const auto&, const auto&) { mRequestReceived = true; },
		    [](const auto&) { BC_HARD_FAIL("Request must succeed"); });
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "GET");
		BC_ASSERT_CPP_EQUAL(actualRequest->body, "");
	}
};

namespace {
TestSuite _("Rest client unit tests",
            {
                CLASSY_TEST(PostRestTest),
                CLASSY_TEST(PutRestTest),
                CLASSY_TEST(PatchRestTest),
                CLASSY_TEST(GetRestTest),
            });

} // namespace

} // namespace tester
} // namespace flexisip
