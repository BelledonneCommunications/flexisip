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

#include <jwt/jwt.hpp>

#include "auth/bearer-auth.hh"
#include "rsa-keys.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace flexisip;
using namespace flexisip::tester;
using namespace std::chrono_literals;

namespace {
const tester::TempFile kFile(kRsaPubKey);
const Bearer::BearerParams kParams{.issuer = "example.org",
                                   .realm = "totoRealm",
                                   .idClaimer = "sip-id",
                                   .keyType = Bearer::PubKeyType::file,
                                   .keyPath = kFile.getFilename()};

jwt::jwt_object generateValidJwtObject() {
	jwt::jwt_object obj{jwt::params::algorithm("RS256"), jwt::params::secret(kRsaPrivKey)};
	obj.add_claim("iss", kParams.issuer);
	obj.add_claim(kParams.idClaimer, "sip:toto@example.org");
	obj.add_claim("exp", std::chrono::system_clock::now() + 60s);
	return obj;
}

auto check(const msg_param_t data) {
	msg_param_t msgData[] = {data, nullptr};
	msg_auth_t msg{};
	msg.au_scheme = "Bearer";
	msg.au_params = msgData;
	Bearer bearerScheme(kParams);
	return bearerScheme.check(&msg);
}

auto generateAndCheckToken(const jwt::jwt_object& jwtObj) {
	const auto token = jwtObj.signature();
	std::string data{"token=\"" + token + "\""};
	return check(data.c_str());
}

// check that malformed messages do not cause crashes
void invalidMsgFormat() {
	BC_ASSERT_FALSE(check(nullptr).has_value());
	BC_ASSERT_FALSE(check("invalid message data").has_value());
	BC_ASSERT_FALSE(check("token=\"notAtoken").has_value());
}

// check that a "valid" result is generated on a valid token
void validToken() {
	auto obj = generateValidJwtObject();
	auto result = generateAndCheckToken(obj);
	BC_HARD_ASSERT(result.has_value());
	BC_ASSERT(result->getType() == RequestSipEvent::AuthResult::Type::Bearer);
	BC_ASSERT(result->getResult() == RequestSipEvent::AuthResult::Result::Valid);
	BC_ASSERT(isValidSipUri(result->getIdentity().get()));
}

// check that no challenge result is generated if the issuer is not the one expected
void validTokenOfAnotherIssuer() {
	// generate a valid authorization for another issuer
	auto obj = generateValidJwtObject();
	obj.payload().add_claim("iss", "notOurIssuer.example.org", true);
	auto result = generateAndCheckToken(obj);
	BC_ASSERT_FALSE(result.has_value());
}

// generate a valid token but with another algorithm (symmetrical signing)
// expect an invalid result
void badAlgo() {
	auto obj = generateValidJwtObject();
	obj.header().algo("HS256");
	obj.secret(kRsaPubKey);
	auto result = generateAndCheckToken(obj);
	BC_HARD_ASSERT(result.has_value());
	BC_ASSERT(result->getType() == RequestSipEvent::AuthResult::Type::Bearer);
	BC_ASSERT(result->getResult() == RequestSipEvent::AuthResult::Result::Invalid);
}

// check that identity is verified
void invalidIdentity() {
	// generate a token without a sip-id claimer
	auto obj = generateValidJwtObject();
	obj.remove_claim(kParams.idClaimer);
	{
		auto result = generateAndCheckToken(obj);
		BC_HARD_ASSERT(result.has_value());
		BC_ASSERT(result->getType() == RequestSipEvent::AuthResult::Type::Bearer);
		BC_ASSERT(result->getResult() == RequestSipEvent::AuthResult::Result::Invalid);
	}
	// generate a token with an invalid SIP URI
	obj.payload().add_claim(kParams.idClaimer, "notASipUri@example.org", true);
	{
		auto result = generateAndCheckToken(obj);
		BC_HARD_ASSERT(result.has_value());
		BC_ASSERT(result->getType() == RequestSipEvent::AuthResult::Type::Bearer);
		BC_ASSERT(result->getResult() == RequestSipEvent::AuthResult::Result::Invalid);
	}
}

// check token expiration is taken into account
void tokenExpiration() {
	auto obj = generateValidJwtObject();
	// generate a token without an expiration time
	obj.remove_claim("exp");
	{
		auto result = generateAndCheckToken(obj);
		BC_HARD_ASSERT(result.has_value());
		BC_ASSERT(result->getType() == RequestSipEvent::AuthResult::Type::Bearer);
		BC_ASSERT(result->getResult() == RequestSipEvent::AuthResult::Result::Invalid);
	}
	// generate an expired token
	// expiration is checked to the nearest second
	obj.payload().add_claim("exp", std::chrono::system_clock::now() - 1s, true);
	{
		auto result = generateAndCheckToken(obj);
		BC_HARD_ASSERT(result.has_value());
		BC_ASSERT(result->getType() == RequestSipEvent::AuthResult::Type::Bearer);
		BC_ASSERT(result->getResult() == RequestSipEvent::AuthResult::Result::Invalid);
		BC_ASSERT(isValidSipUri(result->getIdentity().get()));
	}
}

// generate a token with an invalid signature
void verifySignature() {
	auto obj = generateValidJwtObject();
	obj.secret(kInvalidRsaPrivKey);
	auto result = generateAndCheckToken(obj);
	BC_ASSERT(result->getType() == RequestSipEvent::AuthResult::Type::Bearer);
	BC_ASSERT(result->getResult() == RequestSipEvent::AuthResult::Result::Invalid);
	BC_ASSERT(isValidSipUri(result->getIdentity().get()));
}

TestSuite _("AuthBearerScheme",
            {
                CLASSY_TEST(invalidMsgFormat),
                CLASSY_TEST(validToken),
                CLASSY_TEST(validTokenOfAnotherIssuer),
                CLASSY_TEST(badAlgo),
                CLASSY_TEST(invalidIdentity),
                CLASSY_TEST(tokenExpiration),
                CLASSY_TEST(verifySignature),
            });
} // namespace