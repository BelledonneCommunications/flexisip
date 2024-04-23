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
#include <memory>

#include <jwt/jwt.hpp>

#include "auth/bearer-auth.hh"
#include "rsa-keys.hh"
#include "utils/core-assert.hh"
#include "utils/http-mock/http1-mock.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace flexisip;
using namespace flexisip::tester;
using namespace std::string_literals;
using namespace std::string_view_literals;
using namespace std::chrono_literals;

namespace {
const tester::TempFile kFile(kRsaPubKey);
const Bearer::BearerParams kParams{
    .issuer = sofiasip::Url("https://example.org/realms/EXAMPLE"),
    .realm = "totoRealm",
    .audience = "testAuthz",
    .idClaimer = "sip-id",
};
const Bearer::KeyStoreParams kKeyStoreParams{
    .keyType = Bearer::PubKeyType::file,
    .keyPath = kFile.getFilename(),
};

jwt::jwt_object generateValidJwtObject() {
	jwt::jwt_object obj{jwt::params::algorithm("RS256"), jwt::params::secret(kRsaPrivKey)};
	obj.header().add_header("kid", "default");
	obj.add_claim("iss", kParams.issuer.str());
	obj.add_claim("sub", "25863444a27");
	obj.add_claim("aud", std::vector{"notThisOne", kParams.audience.c_str()});
	obj.add_claim(kParams.idClaimer, "sip:toto@example.org");
	obj.add_claim("iat", std::chrono::system_clock::now());
	obj.add_claim("exp", std::chrono::system_clock::now() + 60s);
	return obj;
}

auto check(const msg_param_t data, std::function<void(RequestSipEvent::AuthResult::ChallengeResult&&)>&& onResult) {
	msg_param_t msgData[] = {data, nullptr};
	msg_auth_t msg{};
	msg.au_scheme = "Bearer";
	msg.au_params = msgData;
	Bearer bearerScheme(std::make_shared<sofiasip::SuRoot>(), kParams, kKeyStoreParams);
	return bearerScheme.check(&msg, std::move(onResult));
}

auto generateAndCheckToken(const jwt::jwt_object& jwtObj,
                           std::function<void(RequestSipEvent::AuthResult::ChallengeResult&&)>&& onResult) {
	const auto token = jwtObj.signature();
	return check(token.c_str(), std::move(onResult));
}

// check that malformed messages do not cause crashes
void invalidMsgFormat() {
	auto onResult = [](RequestSipEvent::AuthResult::ChallengeResult&&) {};
	{
		msg_auth_t msg{};
		msg.au_scheme = "Bearer";
		msg.au_params = nullptr;
		Bearer bearerScheme(std::make_shared<sofiasip::SuRoot>(), kParams, kKeyStoreParams);
		BC_ASSERT(bearerScheme.check(&msg, onResult) == AuthScheme::State::Inapplicable);
	}
	return;
	BC_ASSERT(check("", onResult) == AuthScheme::State::Inapplicable);
	BC_ASSERT(check("notAtoken", onResult) == AuthScheme::State::Inapplicable);
}

// check that a "valid" result is generated on a valid token
void validToken() {
	auto obj = generateValidJwtObject();
	auto onResult = [](RequestSipEvent::AuthResult::ChallengeResult&& challResult) {
		BC_ASSERT(challResult.getType() == RequestSipEvent::AuthResult::Type::Bearer);
		BC_ASSERT(challResult.getResult() == RequestSipEvent::AuthResult::Result::Valid);
		BC_ASSERT(isValidSipUri(challResult.getIdentity().get()));
	};
	auto result = generateAndCheckToken(obj, onResult);
	BC_ASSERT(result == AuthScheme::State::Done);
}

// check that no challenge result is generated if the issuer is not the one expected
void validTokenOfAnotherIssuer() {
	// generate a valid authorization for an unexpected issuer
	// issuer comparison must be case-sensitive
	auto obj = generateValidJwtObject();
	obj.payload().add_claim("iss", "https://example.org/realms/ExAMPLE", true);
	auto onResult = [](RequestSipEvent::AuthResult::ChallengeResult&&) {};
	auto result = generateAndCheckToken(obj, onResult);
	BC_ASSERT(result == AuthScheme::State::Inapplicable);
}

// generate a valid token but with another algorithm (symmetrical signing)
// expect an invalid result
void badAlgo() {
	auto obj = generateValidJwtObject();
	obj.header().algo("HS256");
	obj.secret(kRsaPubKey);
	auto onResult = [](RequestSipEvent::AuthResult::ChallengeResult&& challResult) {
		BC_ASSERT(challResult.getType() == RequestSipEvent::AuthResult::Type::Bearer);
		BC_ASSERT(challResult.getResult() == RequestSipEvent::AuthResult::Result::Invalid);
	};
	auto result = generateAndCheckToken(obj, onResult);
	BC_ASSERT(result == AuthScheme::State::Done);
}

// check that a token is not valid when the subject claim is not present or too large
void tokenSubject() {
	auto obj = generateValidJwtObject();
	// generate a token with no subject
	obj.remove_claim("sub");
	{
		auto onResult = [](RequestSipEvent::AuthResult::ChallengeResult&& challResult) {
			BC_ASSERT(challResult.getType() == RequestSipEvent::AuthResult::Type::Bearer);
			BC_ASSERT(challResult.getResult() == RequestSipEvent::AuthResult::Result::Invalid);
		};
		auto result = generateAndCheckToken(obj, onResult);
		BC_ASSERT(result == AuthScheme::State::Done);
	}
	// generate a token with a subject exceeding max length
	const std::string largeSubject(256, 't');
	obj.add_claim("sub", largeSubject);
	{
		auto onResult = [](RequestSipEvent::AuthResult::ChallengeResult&& challResult) {
			BC_ASSERT(challResult.getType() == RequestSipEvent::AuthResult::Type::Bearer);
			BC_ASSERT(challResult.getResult() == RequestSipEvent::AuthResult::Result::Invalid);
		};
		auto result = generateAndCheckToken(obj, onResult);
		BC_ASSERT(result == AuthScheme::State::Done);
	}
}

// check that a token is not valid when the audience claim is not present
void tokenMissingAudience() {
	auto obj = generateValidJwtObject();
	// generate a token with no audience
	obj.remove_claim("aud");
	{
		auto onResult = [](RequestSipEvent::AuthResult::ChallengeResult&& challResult) {
			BC_ASSERT(challResult.getType() == RequestSipEvent::AuthResult::Type::Bearer);
			BC_ASSERT(challResult.getResult() == RequestSipEvent::AuthResult::Result::Invalid);
		};
		auto result = generateAndCheckToken(obj, onResult);
		BC_ASSERT(result == AuthScheme::State::Done);
	}
	// generate a token with an audience but without the expected one
	obj.add_claim("aud", "invalid");
	{
		auto onResult = [](RequestSipEvent::AuthResult::ChallengeResult&& challResult) {
			BC_ASSERT(challResult.getType() == RequestSipEvent::AuthResult::Type::Bearer);
			BC_ASSERT(challResult.getResult() == RequestSipEvent::AuthResult::Result::Invalid);
		};
		auto result = generateAndCheckToken(obj, onResult);
		BC_ASSERT(result == AuthScheme::State::Done);
	}
}

// check that a token is not valid when the iat claim is not present
void tokenMissingIssuedTime() {
	auto obj = generateValidJwtObject();
	// generate a token without an issued time
	obj.remove_claim("iat");
	{
		auto onResult = [](RequestSipEvent::AuthResult::ChallengeResult&& challResult) {
			BC_ASSERT(challResult.getType() == RequestSipEvent::AuthResult::Type::Bearer);
			BC_ASSERT(challResult.getResult() == RequestSipEvent::AuthResult::Result::Invalid);
		};
		auto result = generateAndCheckToken(obj, onResult);
		BC_ASSERT(result == AuthScheme::State::Done);
	}
}

// check that identity is verified
void invalidIdentity() {
	// generate a token without a sip-id claimer
	auto obj = generateValidJwtObject();
	obj.remove_claim(kParams.idClaimer);
	{
		auto onResult = [](RequestSipEvent::AuthResult::ChallengeResult&& challResult) {
			BC_ASSERT(challResult.getType() == RequestSipEvent::AuthResult::Type::Bearer);
			BC_ASSERT(challResult.getResult() == RequestSipEvent::AuthResult::Result::Invalid);
		};
		auto result = generateAndCheckToken(obj, onResult);
		BC_ASSERT(result == AuthScheme::State::Done);
	}
	// generate a token with an invalid SIP URI
	obj.payload().add_claim(kParams.idClaimer, "notASipUri@example.org", true);
	{
		auto onResult = [](RequestSipEvent::AuthResult::ChallengeResult&& challResult) {
			BC_ASSERT(challResult.getType() == RequestSipEvent::AuthResult::Type::Bearer);
			BC_ASSERT(challResult.getResult() == RequestSipEvent::AuthResult::Result::Invalid);
		};
		auto result = generateAndCheckToken(obj, onResult);
		BC_ASSERT(result == AuthScheme::State::Done);
	}
}

// check token expiration is taken into account
void tokenExpiration() {
	auto obj = generateValidJwtObject();
	// generate a token without an expiration time
	obj.remove_claim("exp");
	{
		auto onResult = [](RequestSipEvent::AuthResult::ChallengeResult&& challResult) {
			BC_ASSERT(challResult.getType() == RequestSipEvent::AuthResult::Type::Bearer);
			BC_ASSERT(challResult.getResult() == RequestSipEvent::AuthResult::Result::Invalid);
		};
		auto result = generateAndCheckToken(obj, onResult);
		BC_ASSERT(result == AuthScheme::State::Done);
	}
	// generate an expired token
	// expiration is checked to the nearest second
	obj.payload().add_claim("exp", std::chrono::system_clock::now() - 1s, true);
	{
		auto onResult = [](RequestSipEvent::AuthResult::ChallengeResult&& challResult) {
			BC_ASSERT(challResult.getType() == RequestSipEvent::AuthResult::Type::Bearer);
			BC_ASSERT(challResult.getResult() == RequestSipEvent::AuthResult::Result::Invalid);
			BC_ASSERT(isValidSipUri(challResult.getIdentity().get()));
		};
		auto result = generateAndCheckToken(obj, onResult);
		BC_ASSERT(result == AuthScheme::State::Done);
	}
}

// generate a token with an invalid signature
void verifySignature() {
	auto obj = generateValidJwtObject();
	obj.secret(kInvalidRsaPrivKey);
	auto onResult = [](RequestSipEvent::AuthResult::ChallengeResult&& challResult) {
		BC_ASSERT(challResult.getType() == RequestSipEvent::AuthResult::Type::Bearer);
		BC_ASSERT(challResult.getResult() == RequestSipEvent::AuthResult::Result::Invalid);
		BC_ASSERT(isValidSipUri(challResult.getIdentity().get()));
	};
	auto result = generateAndCheckToken(obj, onResult);
	BC_ASSERT(result == AuthScheme::State::Done);
}

auto removePemMarker(std::string_view data) {
	constexpr auto header = "-----BEGIN CERTIFICATE-----\n"sv.size();
	constexpr auto footer = "\n-----END CERTIFICATE-----"sv.size();
	return data.substr(header, data.size() - header - footer);
}

// create a mock authorization server
// check that the tokens will be verified after filling the key store
void bearerAuthWithWellknown() {
	auto root = std::make_shared<sofiasip::SuRoot>();

	// mock an authorization server
	http_mock::Http1Srv httpSvr(root);
	const auto realm = "testRealm";
	const auto issuer = std::string("http://127.0.0.1:") + httpSvr.getFirstPort() + "/TEST";

	auto rsaCert = removePemMarker(kRsaCert);
	nlohmann::json jwksBody = {{"keys",
	                            {{
	                                 {"kid", "notForUs"},
	                                 {"alg", "RS256"},
	                                 {"use", "enc"},
	                                 {"x5c", {rsaCert}},
	                             },
	                             {
	                                 {"kid", "testCert"},
	                                 {"alg", "RS256"},
	                                 {"use", "sig"},
	                                 {"x5c", {rsaCert}},
	                             }}}};
	nlohmann::json wellknownBody = {{"issuer", issuer}, {"jwks_uri", issuer + "/jwks"}};
	httpSvr.addPage("/TEST/jwks", jwksBody.dump());
	httpSvr.addPage("/TEST/.well-known/openid-configuration", wellknownBody.dump());

	// create BearerScheme with default well-known behavior
	const Bearer::BearerParams params{
	    .issuer = sofiasip::Url(issuer),
	    .realm = realm,
	    .idClaimer = "sip-identity",
	};
	const Bearer::KeyStoreParams keyStoreParams{
	    .keyType = Bearer::PubKeyType::wellKnown,
	    .keyPath = "",
	    .wellKnownRefreshDelay = 2s,
	    .jwksRefreshDelay = 1s,
	};

	Bearer bearerScheme(root, params, keyStoreParams);

	// generate a valid and an invalid token
	// expect state to be pending, while key store is still empty
	auto generateAndCheckMsg =
	    [&params, &bearerScheme](std::string_view kid,
	                             std::function<void(RequestSipEvent::AuthResult::ChallengeResult&&)> callback) {
		    jwt::jwt_object obj{jwt::params::algorithm("RS256"), jwt::params::secret(kRsaPrivKey)};
		    obj.header().add_header("kid", kid);
		    obj.add_claim("iss", params.issuer.str());
		    obj.add_claim("sub", "25863444a27");
		    obj.add_claim("aud", params.audience);
		    obj.add_claim(params.idClaimer, "sip:toto@example.org");
		    obj.add_claim("iat", std::chrono::system_clock::now());
		    obj.add_claim("exp", std::chrono::system_clock::now() + 60s);
		    const auto token = obj.signature();
		    msg_param_t msgData[] = {token.data(), nullptr};
		    msg_auth_t msg{};
		    msg.au_scheme = "Bearer";
		    msg.au_params = msgData;
		    return bearerScheme.check(&msg, std::move(callback));
	    };

	bool receivedValidResult{}, receivedInvalidResult{};
	auto onValidResult = [&receivedValidResult](RequestSipEvent::AuthResult::ChallengeResult&& challResult) {
		BC_ASSERT(challResult.getType() == RequestSipEvent::AuthResult::Type::Bearer);
		BC_ASSERT(challResult.getResult() == RequestSipEvent::AuthResult::Result::Valid);
		BC_ASSERT(isValidSipUri(challResult.getIdentity().get()));
		receivedValidResult = true;
	};
	auto onInvalidResult = [&receivedInvalidResult](RequestSipEvent::AuthResult::ChallengeResult&& challResult) {
		BC_ASSERT(challResult.getType() == RequestSipEvent::AuthResult::Type::Bearer);
		BC_ASSERT(challResult.getResult() == RequestSipEvent::AuthResult::Result::Invalid);
		BC_ASSERT(isValidSipUri(challResult.getIdentity().get()));
		receivedInvalidResult = true;
	};
	BC_ASSERT(generateAndCheckMsg("testCert", onValidResult) == AuthScheme::State::Pending);
	BC_ASSERT(generateAndCheckMsg("notForUs", onInvalidResult) == AuthScheme::State::Pending);

	// iterate to get the well-known response, then the jwks response and processing of pending tokens
	CoreAssert asserter(*root);
	asserter
	    .iterateUpTo(
	        16,
	        [&receivedValidResult, &receivedInvalidResult] {
		        FAIL_IF(!receivedValidResult);
		        FAIL_IF(!receivedInvalidResult);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();
}

TestSuite _("AuthBearerScheme",
            {
                CLASSY_TEST(invalidMsgFormat),
                CLASSY_TEST(validToken),
                CLASSY_TEST(validTokenOfAnotherIssuer),
                CLASSY_TEST(badAlgo),
                CLASSY_TEST(tokenSubject),
                CLASSY_TEST(tokenMissingAudience),
                CLASSY_TEST(tokenMissingIssuedTime),
                CLASSY_TEST(invalidIdentity),
                CLASSY_TEST(tokenExpiration),
                CLASSY_TEST(verifySignature),
                CLASSY_TEST(bearerAuthWithWellknown),
            });
} // namespace