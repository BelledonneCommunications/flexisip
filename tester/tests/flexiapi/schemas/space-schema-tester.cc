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

#include "flexiapi/schemas/space/realm-json.hh"
#include "flexiapi/schemas/space/space-json.hh"

#include <filesystem>
#include <fstream>
#include <functional>

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "flexiapi/schemas/space/realm.hh"
#include "flexiapi/schemas/space/space.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace flexisip::flexiapi;
using namespace flexisip::tester;

namespace {

const auto kValidBearer = nlohmann::json{
    {"authz_server", "https://issuer.example/"},
    {"audience", "audience"},
    {"sip_id_claim", "sip-id"},
    {"public_key_type", "file"},
    {"public_key_location", "/tmp/key"},
};

const auto kValidRealm = nlohmann::json{
    {"realm", "realm"},
    {"bearer", kValidBearer},
};

const auto kValidSpaces = nlohmann::json::array({
    {
        {"name", "space-one"},
        {"domain", "example.com"},
    },
    {
        {"name", "space-two"},
        {"domain", "example.org"},
        {"accounts", "accounts.json"},
        {"realm", kValidRealm},
    },
});

void assertNoException(const function<void()>& test) {
	try {
		test();
	} catch (const exception&) {
		BC_FAIL("Unexpected exception");
	}
}

namespace space {

void validSchema() {
	assertNoException([] { verifySpacesSchemaIntegrity(kValidSpaces); });
}

void parsing() {
	{
		const auto space = kValidSpaces[0].get<Space>();

		BC_ASSERT_CPP_EQUAL(space.name, "space-one");
		BC_ASSERT_CPP_EQUAL(space.domain, "example.com");
	}

	{
		const auto space = kValidSpaces[1].get<Space>();

		BC_ASSERT_CPP_EQUAL(space.name, "space-two");
		BC_ASSERT_CPP_EQUAL(space.domain, "example.org");
		BC_ASSERT_CPP_EQUAL(space.accounts.value(), filesystem::path{"accounts.json"});
		BC_ASSERT_TRUE(space.realm.has_value());
		BC_ASSERT_CPP_EQUAL(space.realm->realm, "realm");
		BC_ASSERT_TRUE(space.realm->bearer.has_value());
		BC_ASSERT_CPP_EQUAL(space.realm->bearer->authz_server.str(), "https://issuer.example/");
		BC_ASSERT_CPP_EQUAL(space.realm->bearer->audience, "audience");
		BC_ASSERT_CPP_EQUAL(space.realm->bearer->sip_id_claim, "sip-id");
		BC_ASSERT_CPP_EQUAL(space.realm->bearer->public_key_type.value(), flexisip::Bearer::PubKeyType::file);
		BC_ASSERT_CPP_EQUAL(space.realm->bearer->public_key_location.value(), filesystem::path{"/tmp/key"});
	}
}

void invalidRootType() {
	BC_ASSERT_THROWN(verifySpacesSchemaIntegrity(nlohmann::json::object()), nlohmann::json::type_error);
}

void invalidElementType() {
	BC_ASSERT_THROWN(verifySpacesSchemaIntegrity(nlohmann::json::array({"invalid"})), nlohmann::json::type_error);
}

void missingOrWrongTypeName() {
	BC_ASSERT_THROWN(verifySpacesSchemaIntegrity(nlohmann::json::array({{{"domain", "example.com"}}})),
	                 nlohmann::json::out_of_range);
	BC_ASSERT_THROWN(verifySpacesSchemaIntegrity(nlohmann::json::array({{{"name", 42}, {"domain", "example.com"}}})),
	                 nlohmann::json::type_error);
}

void missingOrWrongTypeDomain() {
	BC_ASSERT_THROWN(verifySpacesSchemaIntegrity(nlohmann::json::array({{{"name", "space"}}})),
	                 nlohmann::json::out_of_range);
	BC_ASSERT_THROWN(verifySpacesSchemaIntegrity(nlohmann::json::array({{{"name", "space"}, {"domain", 42}}})),
	                 nlohmann::json::type_error);
}

void duplicateDomain() {
	const auto config = nlohmann::json::array({
	    {{"name", "space-one"}, {"domain", "example.com"}},
	    {{"name", "space-two"}, {"domain", "example.com"}},
	});
	BC_ASSERT_THROWN(verifySpacesSchemaIntegrity(config), nlohmann::json::other_error);
}

void wrongTypeAccounts() {
	const auto config = nlohmann::json::array({{{"name", "space"}, {"domain", "example.com"}, {"accounts", 42}}});
	BC_ASSERT_THROWN(verifySpacesSchemaIntegrity(config), nlohmann::json::type_error);
}

void invalidNested() {
	const auto config = nlohmann::json::array({
	    {{"name", "space"}, {"domain", "example.com"}, {"realm", nlohmann::json::object()}},
	});
	BC_ASSERT_THROWN(verifySpacesSchemaIntegrity(config), nlohmann::json::type_error);
}

} // namespace space

namespace realm {

void validSchema() {
	assertNoException([] { verifyRealmSchemaIntegrity(kValidRealm); });
}

void parsing() {
	const auto realm = nlohmann::json{{"realm", "realm"}, {"bearer", kValidBearer}}.get<Realm>();

	BC_ASSERT_CPP_EQUAL(realm.realm, "realm");
	BC_ASSERT_TRUE(realm.bearer.has_value());
	BC_ASSERT_CPP_EQUAL(realm.bearer->authz_server.str(), "https://issuer.example/");
	BC_ASSERT_CPP_EQUAL(realm.bearer->audience, "audience");
	BC_ASSERT_CPP_EQUAL(realm.bearer->sip_id_claim, "sip-id");
}

void parsingFromFile() {
	const TmpDir directory{__func__};
	const auto path = directory.path() / "realm.json";
	{
		ofstream file{path};
		file << kValidRealm;
	}

	const auto realm = nlohmann::json(path.string()).get<Realm>();

	BC_ASSERT_CPP_EQUAL(realm.realm, "realm");
	BC_ASSERT_TRUE(realm.bearer.has_value());
	BC_ASSERT_CPP_EQUAL(realm.bearer->authz_server.str(), "https://issuer.example/");
	BC_ASSERT_CPP_EQUAL(realm.bearer->audience, "audience");
	BC_ASSERT_CPP_EQUAL(realm.bearer->sip_id_claim, "sip-id");
}

void invalidRootType() {
	BC_ASSERT_THROWN(verifyRealmSchemaIntegrity(42), nlohmann::json::type_error);
}

void missingOrWrongTypeName() {
	BC_ASSERT_THROWN(verifyRealmSchemaIntegrity(nlohmann::json::object()), nlohmann::json::type_error);
	BC_ASSERT_THROWN(verifyRealmSchemaIntegrity(nlohmann::json{{"realm", 42}}), nlohmann::json::type_error);
}

void wrongTypeNested() {
	BC_ASSERT_THROWN(verifyRealmSchemaIntegrity(nlohmann::json{{"realm", "realm"}, {"bearer", "invalid"}}),
	                 nlohmann::json::type_error);
}

} // namespace realm

namespace bearer {

void validSchema() {
	assertNoException([] { verifyBearerSchemaIntegrity(kValidBearer); });
}

void parsing() {
	const auto bearer = kValidBearer.get<Bearer>();

	BC_ASSERT_CPP_EQUAL(bearer.authz_server.str(), "https://issuer.example/");
	BC_ASSERT_CPP_EQUAL(bearer.audience, "audience");
	BC_ASSERT_CPP_EQUAL(bearer.sip_id_claim, "sip-id");
	BC_ASSERT_CPP_EQUAL(bearer.public_key_type.value(), flexisip::Bearer::PubKeyType::file);
	BC_ASSERT_CPP_EQUAL(bearer.public_key_location.value(), filesystem::path{"/tmp/key"});

	auto wellKnownBearerJson = kValidBearer;
	wellKnownBearerJson["public_key_type"] = "well-known";
	wellKnownBearerJson["public_key_location"] = "";
	const auto wellKnownBearer = wellKnownBearerJson.get<Bearer>();

	BC_ASSERT_CPP_EQUAL(wellKnownBearer.authz_server.str(), "https://issuer.example/");
	BC_ASSERT_CPP_EQUAL(wellKnownBearer.audience, "audience");
	BC_ASSERT_CPP_EQUAL(wellKnownBearer.sip_id_claim, "sip-id");
	BC_ASSERT_CPP_EQUAL(wellKnownBearer.public_key_type.value(), flexisip::Bearer::PubKeyType::wellKnown);
	BC_ASSERT_CPP_EQUAL(wellKnownBearer.public_key_location.value(), filesystem::path{""});
}

void invalidRootType() {
	BC_ASSERT_THROWN(verifyBearerSchemaIntegrity(nlohmann::json::array()), nlohmann::json::type_error);
}

void missingOrWrongTypeRequiredFields() {
	for (const auto& field : {"authz_server", "audience", "sip_id_claim"}) {
		auto missing = kValidBearer;
		missing.erase(field);
		BC_ASSERT_THROWN(verifyBearerSchemaIntegrity(missing), nlohmann::json::type_error);

		auto wrongType = kValidBearer;
		wrongType[field] = 42;
		BC_ASSERT_THROWN(verifyBearerSchemaIntegrity(wrongType), nlohmann::json::type_error);
	}
}

void wrongTypeOptionalFields() {
	for (const auto& field : {"public_key_type", "public_key_location"}) {
		auto config = kValidBearer;
		config[field] = 42;
		BC_ASSERT_THROWN(verifyBearerSchemaIntegrity(config), nlohmann::json::type_error);
	}
}

} // namespace bearer

const TestSuite kSuite = {
    "FlexiapiSpaceSchema",
    {
        CLASSY_TEST(space::validSchema),
        CLASSY_TEST(space::parsing),
        CLASSY_TEST(space::invalidRootType),
        CLASSY_TEST(space::invalidElementType),
        CLASSY_TEST(space::missingOrWrongTypeName),
        CLASSY_TEST(space::missingOrWrongTypeDomain),
        CLASSY_TEST(space::duplicateDomain),
        CLASSY_TEST(space::wrongTypeAccounts),
        CLASSY_TEST(space::invalidNested),
        CLASSY_TEST(realm::validSchema),
        CLASSY_TEST(realm::parsing),
        CLASSY_TEST(realm::parsingFromFile),
        CLASSY_TEST(realm::invalidRootType),
        CLASSY_TEST(realm::missingOrWrongTypeName),
        CLASSY_TEST(realm::wrongTypeNested),
        CLASSY_TEST(bearer::validSchema),
        CLASSY_TEST(bearer::parsing),
        CLASSY_TEST(bearer::invalidRootType),
        CLASSY_TEST(bearer::missingOrWrongTypeRequiredFields),
        CLASSY_TEST(bearer::wrongTypeOptionalFields),
    },
};

} // namespace
