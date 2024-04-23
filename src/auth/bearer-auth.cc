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

#include <algorithm>
#include <cstdio>

#include <jwt/jwt.hpp>
#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <sofia-sip/hostdomain.h>

#include "flexisip/logmanager.hh"

using namespace std;
using namespace std::string_literals;
using namespace std::string_view_literals;

namespace flexisip {

namespace {

constexpr auto kOpenIDConnect = "OpenID Connect";
constexpr auto kSchemeType = "Bearer";

namespace claim {
constexpr auto kIssuer = "iss"sv;
constexpr auto kSubject = "sub"sv;
constexpr auto kAudience = "aud"sv;
constexpr auto kExpirationTime = "exp"sv;
constexpr auto kScope = "scope"sv;
} // namespace claim

// nlohmann lib only supports 'std::string's as keys in version before 3.11.0
// this wrapper forces the use of a string as a key id
class JsonWrapper {
public:
	explicit JsonWrapper(const nlohmann::json& jsonData) : mJsonData(jsonData) {
	}
	auto has(const string& keyId) const {
		return mJsonData.contains(keyId);
	}
	auto hasString(const string& keyId) const {
		return has(keyId) && mJsonData[keyId].is_string();
	};
	auto hasString(string_view keyId) const {
		return hasString(string(keyId));
	};
	auto hasArray(const string& keyId) const {
		return has(keyId) && mJsonData[keyId].is_array();
	};
	auto hasArray(string_view keyId) const {
		return hasArray(string(keyId));
	};

	// the following functions may throw
	auto getArray(const string& keyId) const {
		vector<JsonWrapper> jsonVector;
		for (const auto& value : mJsonData[keyId])
			jsonVector.emplace_back(value);
		return jsonVector;
	}
	auto getArray(string_view keyId) const {
		return getArray(string(keyId));
	}

	auto operator[](const string& keyId) const {
		return mJsonData[keyId];
	};
	auto operator[](string_view keyId) const {
		return mJsonData[string(keyId)];
	};

private:
	nlohmann::json mJsonData;
};

string readToken(const msg_param_t* param) {
	if (param == nullptr) return string{};
	// token is the 1st param (RFC 6750-2.1)
	return string{*param};
}

string readKeyId(jwt::jwt_header& header) {
	constexpr auto keyId = "kid"sv;
	if (!header.has_header(keyId)) return {};

	const auto headerData = JsonWrapper(header.create_json_obj());
	return headerData[keyId];
}

bool acceptIssuer(const sofiasip::Url& issuer, const sofiasip::Url& authzServer) {
	if (issuer.getType() != authzServer.getType()) return false;

	// fragments are fobidden
	if (!issuer.getFragment().empty()) return false;

	// case-sensitive url comparison
	const auto* authz = authzServer.get();
	const auto* iss = issuer.get();
	constexpr auto equal = [](const char* a, const char* b) {
		if (a && (!b || string_view(a) != b)) return false;
		if (!a && b) return false;
		return true;
	};
	if (!equal(iss->url_host, authz->url_host)) return false;
	if (!equal(iss->url_port, authz->url_port)) return false;
	if (!equal(iss->url_path, authz->url_path)) return false;
	return true;
}

bool acceptSubjet(string_view subject) {
	constexpr size_t maxSubjectSize = 255;
	if (subject.size() > maxSubjectSize) return false;
	return true;
}

bool acceptAudience(const vector<nlohmann::json>& audience, string_view expected) {
	return std::any_of(audience.cbegin(), audience.cend(), [&expected](const nlohmann::json& aud) {
		return aud.is_string() && aud.get<string>() == expected;
	});
}

void verifySignature(string_view token,
                     const Bearer::KeyInfo& pubKey,
                     RequestSipEvent::AuthResult::ChallengeResult& result) {
	// check validity (token expiration, signature)
	// validate_iat verifies the presence of claim, not its value
	try {
		std::ignore = jwt::decode(token, jwt::params::algorithms({pubKey.algo}), jwt::params::verify(true),
		                          jwt::params::secret(pubKey.key), jwt::params::validate_iat(true));

		// result is valid if decoding did not throw
		result.accept();
	} catch (const std::exception& e) {
		LOGW("Bearer authentication is rejected: %s.", e.what());
	}
}

// KeyStore
constexpr auto kDefaultKid = "default";
constexpr auto kRS256 = "RS256";
struct bio_deleter {
	void operator()(BIO* b) {
		BIO_free(b);
	}
};
using uniqueBioPtr = unique_ptr<BIO, bio_deleter>;

string loadPemKey(string_view pubKeyFile) {
	struct file_deleter {
		void operator()(FILE* f) {
			fclose(f);
		}
	};
	unique_ptr<FILE, file_deleter> fp{fopen(pubKeyFile.data(), "r")};
	if (!fp) {
		LOGF("%s: failed to open file: %s.", kOpenIDConnect, pubKeyFile.data());
	}

	unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pubKey{PEM_read_PUBKEY(fp.get(), nullptr, nullptr, nullptr),
	                                                      EVP_PKEY_free};
	uniqueBioPtr outbio{BIO_new(BIO_s_mem())};

	if (!PEM_write_bio_PUBKEY(outbio.get(), pubKey.get())) {
		LOGF("%s: error loading public key in PEM format.", kOpenIDConnect);
	}

	char* buf{};
	const auto size = BIO_get_mem_data(outbio.get(), &buf);
	return {buf, static_cast<size_t>(size)};
}

std::pair<string, ASN1_TIME> extractKey(string_view certificate) {
	uniqueBioPtr certbio{BIO_new_mem_buf(certificate.data(), static_cast<int>(certificate.size()))};

	std::unique_ptr<X509, decltype(&X509_free)> x509Cert{PEM_read_bio_X509(certbio.get(), nullptr, nullptr, nullptr),
	                                                     X509_free};
	if (!x509Cert) {
		LOGW("%s: error loading cert into memory.", kOpenIDConnect);
		return {};
	}

	const auto* notAfter = X509_get0_notAfter(x509Cert.get());
	if (!notAfter) {
		LOGW("%s: no certificate validity found,", kOpenIDConnect);
		return {};
	}
	auto* pkey = X509_get0_pubkey(x509Cert.get()); // get pointer, no allocation
	if (!pkey) {
		LOGW("%s: failed to get public key from certificate.", kOpenIDConnect);
		return {};
	}

	uniqueBioPtr outbio{BIO_new(BIO_s_mem())};
	if (!PEM_write_bio_PUBKEY(outbio.get(), pkey)) {
		LOGE("%s: error writing public key data in PEM format.", kOpenIDConnect);
	}

	char* buf{};
	const auto size = BIO_get_mem_data(outbio.get(), &buf);
	return {{buf, static_cast<size_t>(size)}, *notAfter};
}

bool isKeyValid(const ASN1_TIME& notAfter) {
	return X509_cmp_current_time(&notAfter) <= 0;
}

unordered_map<string, Bearer::KeyInfo> parseJWKSResponse(string_view response) {
	// RFC 7517
	const auto payload = JsonWrapper(nlohmann::json::parse(response));
	constexpr auto keys = "keys"sv;
	if (!payload.hasArray(keys)) {
		LOGW("%s: failed to parse the JWKS authority server response.", kOpenIDConnect);
		return {};
	}

	LOGD("%s: a JWKS response has been received from the authority server.", kOpenIDConnect);

	unordered_map<string, Bearer::KeyInfo> pubKeys{};

	constexpr auto use = "use"sv;
	constexpr auto alg = "alg"sv;
	constexpr auto kid = "kid"sv;
	constexpr auto x5c = "x5c"sv;

	for (const auto& k : payload.getArray(keys)) {
		if (k.hasString(use) && (k[use] == "sig") && k.hasString(alg) && k.hasString(kid)) {
			string keyId = k[kid];
			string cert = k.hasArray(x5c) ? k[x5c][0] : "";
			const auto pemCert = "-----BEGIN CERTIFICATE-----\n"s + cert + "\n-----END CERTIFICATE-----";
			auto [publicKey, notAfter] = extractKey(pemCert);
			if (publicKey.empty()) LOGW("%s: rejected certificate, kid \"%s\".", kOpenIDConnect, keyId.c_str());
			else if (!isKeyValid(notAfter)) LOGD("%s: expired certificate, kid \"%s\".", kOpenIDConnect, keyId.c_str());
			else {
				pubKeys[keyId] = {.key = publicKey, .algo = k[alg], .notAfter = notAfter};
				LOGD("%s: valid certificate, kid \"%s\".", kOpenIDConnect, keyId.c_str());
			}
		}
	}
	return pubKeys;
}

} // namespace

Bearer::Bearer(const shared_ptr<sofiasip::SuRoot>& root,
               const BearerParams& params,
               const KeyStoreParams& keyStoreParams)
    : mParams(params), mKeyStore(root, params.issuer, keyStoreParams, [this] { processPendingTokens(); }) {
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
	auto* response_msg =
	    msg_header_format(s_as->as_home, ach->ach_header,
	                      "%s"
	                      " authz_server=\"%s\","
	                      " realm=\"%s\"%s",
	                      kSchemeType, mParams.issuer.str().c_str(), mParams.realm.c_str(), scope.c_str());
	as.response(response_msg);
}

AuthScheme::State Bearer::check(const msg_auth_t* credentials, std::function<void(ChallengeResult&&)>&& onResult) {
	const auto* authParam = credentials->au_params;
	auto resState = State::Inapplicable;
	const auto token = readToken(authParam);

	ChallengeResult result{RequestSipEvent::AuthResult::Type::Bearer};
	try {
		// decode a first time to read parameters
		auto dec = jwt::decode(token, jwt::params::algorithms({""}), jwt::params::verify(false));
		const auto& payload = dec.payload();
		const auto payloadValues = JsonWrapper(payload.create_json_obj());

		auto checkMandatoryClaim = [&payload, &payloadValues](string_view claim) {
			if (!payload.has_claim(claim)) throw runtime_error(string(claim) + " claim is missing");
			return payloadValues[claim];
		};

		const auto issuer = sofiasip::Url(checkMandatoryClaim(claim::kIssuer).get<string>());
		if (!acceptIssuer(issuer, mParams.issuer)) {
			LOGD("Bearer authentication stops: unknown issuer: %s.", issuer.str().c_str());
			return resState;
		}
		// issuer is the one expected, the authorization message is for us
		resState = AuthScheme::State::Done;

		const auto subject = checkMandatoryClaim(claim::kSubject).get<string>();
		if (!acceptSubjet(subject)) throw runtime_error("invalid subject");

		auto audience = checkMandatoryClaim(claim::kAudience);
		if (!acceptAudience(audience.is_array() ? audience.get<vector<nlohmann::json>>()
		                                        : vector<nlohmann::json>{audience},
		                    mParams.audience))
			throw runtime_error("invalid audience");

		checkMandatoryClaim(claim::kExpirationTime); // ensure claim is present, value is checked later

		const auto identity = checkMandatoryClaim(mParams.idClaimer).get<string>();
		result.setIdentity(SipUri(identity));

		if (payload.has_claim(claim::kScope)) {
			// todo: check scope value
		}

		auto kid = readKeyId(dec.header());
		if (kid.empty()) throw runtime_error("kid is missing");

		const auto PubKey = mKeyStore.getPubKey(kid);
		if (PubKey.key.empty()) {
			mPendingTokens.push_back({.token = token,
			                          .kid = kid,
			                          .retry = mKeyStore.keyCachePending(),
			                          .result = result,
			                          .callback = std::move(onResult)});
			mKeyStore.askForJWKS();
			return AuthScheme::State::Pending;
		}
		verifySignature(token, PubKey, result);
		onResult(std::move(result));

	} catch (const std::exception& e) {
		LOGW("Bearer authentication is rejected: %s.", e.what());
	}
	return resState;
}

void Bearer::processPendingTokens() {
	for (auto pendingToken = mPendingTokens.begin(); pendingToken != mPendingTokens.end();) {
		const auto pubKey = mKeyStore.getPubKey(pendingToken->kid);
		if (pubKey.key.empty()) {
			if (pendingToken->retry) {
				pendingToken->retry = false;
				++pendingToken;
				continue;
			}
			LOGW("Bearer authentication is rejected: unknown kid.");
		} else {
			verifySignature(pendingToken->token, pubKey, pendingToken->result);
		}
		pendingToken->callback(std::move(pendingToken->result));
		pendingToken = mPendingTokens.erase(pendingToken);
	}
	if (!mPendingTokens.empty()) mKeyStore.askForJWKS();
}

// KeyStore
Bearer::KeyStore::KeyStore(const shared_ptr<sofiasip::SuRoot>& root,
                           const sofiasip::Url& issuer,
                           const KeyStoreParams& params,
                           function<void()>&& refreshCallback)
    : mKeyType{params.keyType}, mIssuer{issuer}, mHttpClient{root}, mWellKnownTimer{root, params.wellKnownRefreshDelay},
      mJWKSTimer{root, params.jwksRefreshDelay}, mOnPubKeyRefresh{std::move(refreshCallback)} {
	switch (mKeyType) {
		case Bearer::PubKeyType::file: {
			updateKeys({{kDefaultKid, {.key = loadPemKey(params.keyPath), .algo = kRS256}}});
			break;
		}
		case Bearer::PubKeyType::wellKnown: {
			constexpr auto wellKnownPath = ".well-known/openid-configuration";
			auto issPath = mIssuer.str();
			if (issPath.back() != '/') issPath += "/";
			mWellKnownUrl = issPath + wellKnownPath;
			askForWellKnown();
			break;
		}
	}
}

void Bearer::KeyStore::askForWellKnown() {
	mHttpClient.requestGET(mWellKnownUrl, [this](string_view response) { onWellKnownResponse(response); });
}

void Bearer::KeyStore::onWellKnownResponse(string_view response) {
	if (response.empty()) {
		LOGW("%s: failed to get the .well-known content from the authority server. Retry in 5 minutes.",
		     kOpenIDConnect);
		const auto timeout = 5min;
		mWellKnownTimer.set([this] { askForWellKnown(); }, timeout);
		return;
	}

	LOGD("%s: a .well-known response has been received from the authority server.", kOpenIDConnect);
	mWellKnownTimer.set([this] { askForWellKnown(); });
	auto payload = JsonWrapper(nlohmann::json::parse(response));

	constexpr auto issuer = "issuer"sv;
	if (!payload.hasString(issuer)) {
		LOGW("%s: failed to find %s in .well-known server response.", kOpenIDConnect, issuer.data());
	} else {
		try {
			auto iss = payload[issuer].get<string>();
			auto issUrl = sofiasip::Url(iss);
			if (!acceptIssuer(issUrl, mIssuer))
				LOGW("%s: a different issuer has been received from .well-known: %s while expecting %s.",
				     kOpenIDConnect, issUrl.str().c_str(), mIssuer.str().c_str());
		} catch (const exception& e) {
			LOGW("%s: an invalid issuer has been received from .well-known: %s.", kOpenIDConnect, e.what());
		}
	}

	constexpr auto jwksUri = "jwks_uri"sv;
	if (!payload.hasString(jwksUri)) {
		LOGW("%s: failed to find %s in .well-known server response.", kOpenIDConnect, jwksUri.data());
	}
	mKeyPath = payload[jwksUri].get<string>();
	askForJWKS();
}

void Bearer::KeyStore::askForJWKS() {
	// wait next response
	if (mKeyCacheUpdate == KeyCache::Pending) return;

	mHttpClient.requestGET(mKeyPath, [this](string_view response) { onJWKSResponse(response); });
	mKeyCacheUpdate = KeyCache::Pending;
}

void Bearer::KeyStore::onJWKSResponse(string_view response) {
	mJWKSTimer.set([this] { askForJWKS(); });

	if (response.empty()) {
		LOGW("%s: failed to get the JWKS from the authority server.", kOpenIDConnect);
		checkKeysValidity();
		// check if url has changed
		askForWellKnown();
		mKeyCacheUpdate = KeyCache::Required;
		return;
	}

	auto keys = parseJWKSResponse(response);
	updateKeys(keys);
}

void Bearer::KeyStore::updateKeys(const unordered_map<std::string, KeyInfo>& pubKeys) {
	mPubKeys = pubKeys;
	mKeyCacheUpdate = KeyCache::Done;
	mOnPubKeyRefresh();
}

void Bearer::KeyStore::checkKeysValidity() {
	for (auto pubKey = mPubKeys.begin(); pubKey != mPubKeys.end();) {
		if (isKeyValid(pubKey->second.notAfter)) {
			++pubKey;
			continue;
		}
		LOGI("%s: remove expired key with kid \"%s\".", kOpenIDConnect, pubKey->first.c_str());
		pubKey = mPubKeys.erase(pubKey);
	}
}

Bearer::KeyInfo Bearer::KeyStore::getPubKey(const string& kid) const {
	const auto& keyId = mKeyType == PubKeyType::file ? kDefaultKid : kid;
	auto pubKey = mPubKeys.find(keyId);
	if (pubKey == mPubKeys.end()) return {};
	return pubKey->second;
}

} // namespace flexisip
