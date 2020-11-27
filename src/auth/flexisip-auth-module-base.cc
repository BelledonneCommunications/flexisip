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

FlexisipAuthModuleBase::FlexisipAuthModuleBase(su_root_t *root, const std::string &domain, unsigned nonceExpire, bool qopAuth):
	am_realm{domain}, am_qop{qopAuth ? "auth" : ""}, am_expires{nonceExpire}, mRoot{root}, mQOPAuth{qopAuth} {

	mNonceStore.setNonceExpires(nonceExpire);
}

void FlexisipAuthModuleBase::verify(FlexisipAuthStatus &as, msg_auth_t &_credentials, const auth_challenger_t &ach) {
	auto wildcardPos = find(am_realm.cbegin(), am_realm.cend(), '*');
	const auto &host = as.as_domain;

	/* Initialize per-request realm */
	if (!as.as_realm.empty())
		;
	else if (wildcardPos == am_realm.cend()) {
		as.as_realm = am_realm;
	} else if (host.empty()) {
		return; /* Internal error */
	} else if (am_realm == "*") {
		as.as_realm = host;
	} else {
		/* Replace * with hostpart */
		as.as_realm = string{am_realm.cbegin(), wildcardPos} + host + string{wildcardPos+1, am_realm.cend()};
	}

	as.as_allow = as.as_allow || allowCheck(as);

	auto credentials = &_credentials;
	if (!as.as_realm.empty()) {
		/* Workaround for old linphone client that don't check whether algorithm is MD5 or SHA256.
		 * They then answer for both, but the first one for SHA256 is of course wrong.
		 * We workaround by selecting the second digest response.
		 */
		if (credentials->au_next) {
			auth_response_t r = {0};
			r.ar_size = sizeof(r);
			auth_digest_response_get(as.mHome.home(), &r, credentials->au_next->au_params);

			if (r.ar_algorithm == NULL || !strcasecmp(r.ar_algorithm, "MD5")) {
				credentials = credentials->au_next;
			}
		}
		/* After auth_digest_credentials, there is no more au->au_next. */
		credentials = auth_digest_credentials(credentials, as.as_realm.c_str(), am_opaque.c_str());
	} else
		credentials = nullptr;

	if (as.as_allow) {
		LOGD("AuthStatus[%p]: allow unauthenticated %s", &as, as.as_method.c_str());
		as.as_status = 0, as.as_phrase = "";
		as.as_match = reinterpret_cast<msg_header_t *>(credentials);
		return;
	}

	if (credentials) {
		LOGD("AuthStatus[%p]: searching for auth digest response for this proxy", &as);
		msg_auth_t *matched_au = ModuleToolbox::findAuthorizationForRealm(as.mHome.home(), credentials, as.as_realm.c_str());
		if (matched_au)
			credentials = matched_au;
		as.as_match = reinterpret_cast<msg_header_t *>(credentials);
		checkAuthHeader(as, *credentials, ach);
	} else {
		/* There was no realm or credentials, send challenge */
		LOGD("AuthStatus[%p]: no credential found for realm '%s'", &as, as.as_realm.c_str());
		challenge(as, ach);
		notify(as);
		return;
	}
}

void FlexisipAuthModuleBase::challenge(FlexisipAuthStatus &as, const auth_challenger_t &ach) {
	as.as_response = nullptr;

	auto nonce = generateDigestNonce(false, msg_now());

	const auto &u = as.as_uri;
	const auto &d = as.as_pdomain;

	for (auto algo = as.mUsedAlgo.crbegin(); algo != as.mUsedAlgo.crend(); ++algo) {
		ostringstream resp{};
		resp << "Digest realm=\"" << as.as_realm << "\",";
		if (!u.empty()) resp << " uri=\"" << u << "\",";
		if (!d.empty()) resp << " domain=\"" << d << "\",";
		resp << " nonce=\"" << nonce << "\",";
		if (!am_opaque.empty()) resp << " opaque=\"" << am_opaque << "\",";
		if (as.as_stale) resp << " stale=true,";
		resp << " algorithm=" << *algo;
		if (!am_qop.empty()) resp << ", qop=\"" << am_qop << "\"";

		auto challenge = msg_header_make(as.mHome.home(), ach.ach_header, resp.str().c_str());
		if (as.as_response) {
			challenge->sh_auth->au_next = as.as_response->sh_auth;
		}
		as.as_response = challenge;
	}

	if (as.as_response == nullptr) {
		SLOGE << "AuthStatus[" << &as << "]: no available algorithm while challenge making";
		as.as_status = 500;
		as.as_phrase = auth_internal_server_error;
	} else {
		as.as_status = ach.ach_status;
		as.as_phrase = ach.ach_phrase;
		mNonceStore.insert(as.as_response->sh_auth);
	}
}

void FlexisipAuthModuleBase::notify(FlexisipAuthStatus &as) {
	as.as_callback(as);
}

void FlexisipAuthModuleBase::onError(FlexisipAuthStatus &as) {
	if (as.as_status != 0) {
		as.as_status = 500;
		as.as_phrase = "Internal error";
		as.as_response = nullptr;
	}
}

bool FlexisipAuthModuleBase::allowCheck(FlexisipAuthStatus &as) {
	const auto &method = as.as_method;

	if (method == "ACK") { /* Hack */
		as.as_status = 0;
		return true;
	}

	if (method.empty() || am_allow.empty())
		return false;

	if (am_allow[0] == "*") {
		as.as_status = 0;
		return true;
	}

	if (find(am_allow.cbegin(), am_allow.cend(), method) != am_allow.cend()) {
		as.as_status = 0;
		return true;
	}

	return false;
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

	string res(256, '\0');
	auto size = base64_e(&res[0], res.size(), &_nonce, sizeof(_nonce));
	res.resize(size-1);
	return res;
}

// ====================================================================================================================
