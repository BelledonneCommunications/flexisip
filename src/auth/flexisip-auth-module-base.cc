/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2018  Belledonne Communications SARL, All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <algorithm>
#include <iomanip>

#include <sofia-sip/auth_plugin.h>
#include <sofia-sip/base64.h>
#include <sofia-sip/msg_header.h>

#include "flexisip/logmanager.hh"
#include "flexisip/module.hh"

#include "utils/digest.hh"

#include "flexisip/auth/flexisip-auth-module-base.hh"

using namespace std;
using namespace flexisip;

// ====================================================================================================================
//  FlexisipAuthModuleBase class
// ====================================================================================================================

#define setattr(dst, src, attr_name) dst.attr_name = src->attr_name ? src->attr_name : ""

void FlexisipAuthModuleBase::AuthResponse::parse(char const * const params[]) {
	sofiasip::Home h{};
	const string badAuthMsg{"Bad authorization"};
	string missingMsg{"Authorization missing "};

	if (params == nullptr) throw runtime_error{badAuthMsg};

	auth_response_t ar[1] = {{0}};
	auto n = auth_get_params(h.home(), params, "username=", &ar->ar_username, "realm=", &ar->ar_realm, "nonce=", &ar->ar_nonce,
						"uri=", &ar->ar_uri, "response=", &ar->ar_response, "algorithm=", &ar->ar_algorithm,
						"opaque=", &ar->ar_opaque, "cnonce=", &ar->ar_cnonce, "qop=", &ar->ar_qop, "nc=", &ar->ar_nc, nullptr);

	if (n < 0) throw runtime_error{badAuthMsg};

	AuthResponse ar2{};
	setattr(ar2, ar, ar_username);
	setattr(ar2, ar, ar_realm);
	setattr(ar2, ar, ar_nonce);
	setattr(ar2, ar, ar_uri);
	setattr(ar2, ar, ar_response);

	ar2.ar_algorithm = ar->ar_algorithm ? ar->ar_algorithm : "MD5";
	for (auto &c : ar2.ar_algorithm) {c = toupper(c);}

	setattr(ar2, ar, ar_opaque);
	setattr(ar2, ar, ar_cnonce);
	setattr(ar2, ar, ar_qop);

	try {
		if (ar->ar_nc) {
			auto nc = stoul(ar->ar_nc, nullptr, 16);
			if (nc == 0) throw invalid_argument{""};
			if (nc > numeric_limits<decltype(nc)>::max()) throw out_of_range{""};
			ar2.ar_nc = nc;
		}
	} catch (const invalid_argument &) {
		throw runtime_error{"Invalid nonce counter"};
	} catch (const out_of_range &) {
		throw runtime_error{"Too big nonce counter"};
	}

	ar2.ar_md5 = (ar2.ar_algorithm == "MD5");
	ar2.ar_md5sess = (ar2.ar_algorithm == "MD5-SESS");
	ar2.ar_sha1 = (ar2.ar_algorithm == "SHA1");
	ar2.ar_auth = (ar2.ar_qop == "auth");
	ar2.ar_auth_int = (ar2.ar_qop == "auth-int");

	if (ar2.ar_username.empty()) throw runtime_error{move(missingMsg) + "username"};
	if (ar2.ar_nonce.empty()) throw runtime_error{move(missingMsg) + "nonce"};
	if (ar2.ar_uri.empty()) throw runtime_error{move(missingMsg) + "uri"};
	if (ar2.ar_response.empty()) throw runtime_error{move(missingMsg) + "response"};

	if (!ar2.ar_qop.empty() && (
		(ar2.ar_auth && strcasecmp(ar2.ar_qop.c_str(), "auth") !=0 && strcasecmp(ar2.ar_qop.c_str(), "\"auth\"") != 0) ||
		(ar2.ar_auth_int && strcasecmp(ar2.ar_qop.c_str(), "auth-int") !=0 && strcasecmp(ar2.ar_qop.c_str(), "\"auth-int\"") != 0))
	) throw runtime_error{"Invalid qop parameter"};

	if (ar2.ar_auth && ar2.ar_nc == 0) throw runtime_error{move(missingMsg) + "nonce count"};

	*this = move(ar2);
}

template <>
std::uint32_t FlexisipAuthModuleBase::AuthResponse::getNc() const noexcept {
	return ar_nc;
}

template <>
std::string FlexisipAuthModuleBase::AuthResponse::getNc() const noexcept {
	ostringstream os{};
	os << hex << setw(8) << setfill('0') << ar_nc;
	return os.str();
}

// ====================================================================================================================


// ====================================================================================================================
//  FlexisipAuthModuleBase class
// ====================================================================================================================

FlexisipAuthModuleBase::FlexisipAuthModuleBase(su_root_t *root, unsigned nonceExpire, bool qopAuth):
	am_qop{qopAuth ? "auth" : ""}, am_expires{nonceExpire}, mRoot{root}, mQOPAuth{qopAuth} {

	mNonceStore.setNonceExpires(nonceExpire);
}

void FlexisipAuthModuleBase::verify(const std::shared_ptr<FlexisipAuthStatus> &as, msg_auth_t &_credentials, const auth_challenger_t &ach) {
	auto credentials = &_credentials;
	if (!as->as_realm.empty()) {
		/* Workaround for old linphone client that don't check whether algorithm is MD5 or SHA256.
		 * They then answer for both, but the first one for SHA256 is of course wrong.
		 * We workaround by selecting the second digest response.
		 */
		if (credentials->au_next) {
			auth_response_t r = {0};
			r.ar_size = sizeof(r);
			auth_digest_response_get(as->mHome.home(), &r, credentials->au_next->au_params);

			if (r.ar_algorithm == NULL || !strcasecmp(r.ar_algorithm, "MD5")) {
				credentials = credentials->au_next;
			}
		}
		/* After auth_digest_credentials, there is no more au->au_next. */
		credentials = auth_digest_credentials(credentials, as->as_realm.c_str(), am_opaque.c_str());
	} else
		credentials = nullptr;

	if (credentials) {
		LOGD("AuthStatus[%p]: searching for auth digest response for this proxy", &as);
		msg_auth_t *matched_au = ModuleToolbox::findAuthorizationForRealm(as->mHome.home(), credentials, as->as_realm.c_str());
		if (matched_au)
			credentials = matched_au;
		as->as_match = reinterpret_cast<msg_header_t *>(credentials);
		checkAuthHeader(as, *credentials, ach);
	} else {
		/* There was no realm or credentials, send challenge */
		LOGD("AuthStatus[%p]: no credential found for realm '%s'", &as, as->as_realm.c_str());
		challenge(as, ach);
		notify(as);
		return;
	}
}

void FlexisipAuthModuleBase::challenge(const std::shared_ptr<FlexisipAuthStatus> &as, const auth_challenger_t &ach) {
	as->as_response = nullptr;

	auto nonce = generateDigestNonce(false, msg_now());

	const auto &u = as->as_uri;
	const auto &d = as->as_pdomain;

	for (auto algo = as->mUsedAlgo.crbegin(); algo != as->mUsedAlgo.crend(); ++algo) {
		ostringstream resp{};
		resp << "Digest realm=\"" << as->as_realm << "\",";
		if (!u.empty()) resp << " uri=\"" << u << "\",";
		if (!d.empty()) resp << " domain=\"" << d << "\",";
		resp << " nonce=\"" << nonce << "\",";
		if (!am_opaque.empty()) resp << " opaque=\"" << am_opaque << "\",";
		if (as->as_stale) resp << " stale=true,";
		resp << " algorithm=" << *algo;
		if (!am_qop.empty()) resp << ", qop=\"" << am_qop << "\"";

		auto challenge = msg_header_make(as->mHome.home(), ach.ach_header, resp.str().c_str());
		if (as->as_response) {
			challenge->sh_auth->au_next = as->as_response->sh_auth;
		}
		as->as_response = challenge;
	}

	if (as->as_response == nullptr) {
		SLOGE << "AuthStatus[" << &as << "]: no available algorithm while challenge making";
		as->as_status = 500;
		as->as_phrase = auth_internal_server_error;
	} else {
		as->as_status = ach.ach_status;
		as->as_phrase = ach.ach_phrase;
		mNonceStore.insert(as->as_response->sh_auth);
	}
}

void FlexisipAuthModuleBase::notify(const std::shared_ptr<FlexisipAuthStatus> &as) {
	if (as->as_callback) as->as_callback(as);
}

void FlexisipAuthModuleBase::onError(FlexisipAuthStatus &as) {
	if (as.as_status != 0) {
		as.as_status = 500;
		as.as_phrase = "Internal error";
		as.as_response = nullptr;
	}
}

std::string FlexisipAuthModuleBase::generateDigestNonce(bool nextnonce, msg_time_t now) {
	am_count += 3730029547U; /* 3730029547 is a prime */

	Nonce _nonce = {0};
	_nonce.issued = now;
	_nonce.count = am_count;
	_nonce.nextnonce = uint16_t(nextnonce);

	/* Calculate HMAC of nonce data */
	auto len = reinterpret_cast<char *>(&_nonce.digest) - reinterpret_cast<char *>(&_nonce);
	Md5 md5{};
	auto digest = md5.compute<vector<uint8_t>>(&_nonce, len);
	memcpy(_nonce.digest, digest.data(), min(sizeof(_nonce.digest), digest.size()));

	string res(sizeof(_nonce)*4+1, '\0');
	auto size = base64_e(&res[0], res.size(), &_nonce, sizeof(_nonce));
	res.resize(size-1);
	return res;
}

// ====================================================================================================================
