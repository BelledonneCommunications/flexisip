/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "bearer-auth.hh"

#include <jwt/jwt.hpp>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "flexisip/logmanager.hh"
#include "utils/load-file.hh"

using namespace flexisip;
using namespace std;
using namespace std::string_literals;

namespace {

constexpr auto kSchemeType = "Bearer";

string pemKey(const string& pub_key) {
	return "-----BEGIN PUBLIC KEY-----\n"s + pub_key + "\n-----END PUBLIC KEY-----\n";
}

[[maybe_unused]] string extractKey(const string& certificate) {
	jwt::BIO_uptr certbio{BIO_new_mem_buf(certificate.data(), certificate.size()), jwt::bio_deletor};

	std::unique_ptr<X509, decltype(&X509_free)> x509Cert{PEM_read_bio_X509(certbio.get(), NULL, 0, NULL), X509_free};
	if (!x509Cert) {
		LOGE("Error loading cert into memory");
		return {};
	}

	auto* pkey = X509_get0_pubkey(x509Cert.get()); // get pointer, no allocation
	if (!pkey) {
		LOGE("Error getting public key from certificate");
		return {};
	}

	jwt::BIO_uptr outbio{BIO_new(BIO_s_mem()), jwt::bio_deletor};
	if (!PEM_write_bio_PUBKEY(outbio.get(), pkey)) {
		LOGE("Error writing public key data in PEM format");
	}

	char* buf{};
	long size = BIO_get_mem_data(outbio.get(), &buf);
	return string(buf, size);
}

string readToken(const msg_param_t* param) {
	stringstream ss;
	ss << msg_params_find(param, "token=");
	string token;
	ss >> std::quoted(token);
	return token;
}

string readKeyId(jwt::jwt_header& hdr) {
	const auto keyId = "kid"s;
	if (!hdr.has_header(keyId)) return {};

	const auto& hdrData = hdr.create_json_obj();
	return hdrData[keyId];
}

constexpr auto defaultKid = "default";

} // namespace

Bearer::Bearer(const BearerParams& params) : mParams(params) {
	if (params.keyType == Bearer::PubKeyType::file) {
		mPubKeys[defaultKid] = loadFromFile(params.keyPath);
	}

	// hack for well-known or url keyType not yet implemented
	const std::string pub_key =
	    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoFGTEOL9avZwQM8gszLfCcYnJ8uEdbNNP4mRPlQwydNDqFQ"
	    "tFCzn0Ncee99KsJAyAa2Ieowy5DXq2etKdO6J8rA74z4NrWEo//"
	    "trfKCcEcS2f6jExYxw6RfJ67M+0AvqSZo6aGLaNHeFCHiue9695j7zLaj6BOHUGkB/N3h/PQkFxGUHQj0/"
	    "aiXTTdscNfhADtreXEOubNrnjPy5HJu87BaBpXgRByqInsjDQMdq7UUnznAZ1EN8j1y456qiLtJac9VaftUivkJg0eM"
	    "E93Ob12pkJbAU/qtswWoapRp232tk25QRbNf9aJCUdq8rp/dusX0DBAvtCnUuslzjRehJxwIDAQAB";
	mPubKeys["PMEcV2m3B0EM5FJq9GD6FZuMEx9FVDkd0oSf80gKOMI"] = pemKey(pub_key);
}

string Bearer::schemeType() const {
	return kSchemeType;
}

void Bearer::challenge(AuthStatus& as, const auth_challenger_t* ach) {
	as.status(ach->ach_status);
	as.phrase(ach->ach_phrase);
	auto* s_as = as.getPtr();

	// select one according to request?
	string scope{};
	if (!mParams.scope.empty()) {
		scope = ", scope=\"" + *mParams.scope.cbegin();
		for (auto it = (++mParams.scope.cbegin()); it != mParams.scope.cend(); ++it) {
			scope += " "s + *it;
		}
		scope += "\"";
	}
	auto* response_msg = msg_header_format(s_as->as_home, ach->ach_header,
	                                       "%s"
	                                       " authz-server=\"%s\","
	                                       " realm=\"%s\"%s",
	                                       kSchemeType, mParams.issuer.c_str(), mParams.realm.c_str(), scope.c_str());
	as.response(response_msg);
}

optional<RequestSipEvent::AuthResult::ChallengeResult> Bearer::check(const msg_auth_t* credentials) {
	const auto* authParam = credentials->au_params;
	if (authParam == nullptr) return nullopt;

	auto token = readToken(authParam);
	std::optional<RequestSipEvent::AuthResult::ChallengeResult> challengeResult{};
	try {
		const auto algo = jwt::params::algorithms({"RS256"});

		// decode a first time to read parameters
		auto dec = jwt::decode(token, algo, jwt::params::verify(false));
		if (!dec.payload().has_claim_with_value("iss", mParams.issuer)) {
			LOGD("Bearer authentication stops: unknown issuer");
			return nullopt;
		}

		// issuer is the one expected, the authorization message is for us
		// a challenge result is generated
		challengeResult = RequestSipEvent::AuthResult::ChallengeResult{RequestSipEvent::AuthResult::Type::Bearer};

		if (!dec.payload().has_claim("exp")) throw runtime_error("expiration time is missing");

		if (!dec.payload().has_claim(mParams.idClaimer)) throw runtime_error(mParams.idClaimer + " is missing");
		string identity = dec.payload().create_json_obj()[mParams.idClaimer];
		challengeResult->setIdentity(SipUri(identity));

		if (dec.payload().has_claim("scope")) {
			// todo: check scope value
		}

		auto kid = mParams.keyType == Bearer::PubKeyType::file ? defaultKid : readKeyId(dec.header());
		if (kid.empty()) throw runtime_error("kid is missing");

		if (mPubKeys.find(kid) == mPubKeys.end()) {
			// get new key or error
			throw runtime_error("unknown kid");
		}

		// check validity (key expiration, signature)
		std::ignore = jwt::decode(token, algo, jwt::params::verify(true), jwt::params::secret(mPubKeys[kid]));

		// result is valid if decoding hasn't throw
		challengeResult->accept();
	} catch (const std::exception& e) {
		LOGW("Bearer authentication error: %s", e.what());
	}
	return challengeResult;
}