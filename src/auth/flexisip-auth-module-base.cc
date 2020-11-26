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

// FlexisipAuthModuleBase::FlexisipAuthModuleBase(su_root_t *root, const std::string &domain, int nonceExpire, bool qopAuth):
// AuthModule(root,
// 		   AUTHTAG_REALM(domain.c_str()),
// 		   AUTHTAG_OPAQUE("+GNywA=="),
// 		   AUTHTAG_FORBIDDEN(1),
// 		   AUTHTAG_ALLOW("ACK CANCEL BYE"),
// 		   AUTHTAG_EXPIRES(nonceExpire),
// 		   AUTHTAG_NEXT_EXPIRES(nonceExpire),
// 		   AUTHTAG_QOP(qopAuth ? "auth" : nullptr),
// 		   TAG_END()
// ),
// 	mQOPAuth(qopAuth) {
// 	mNonceStore.setNonceExpires(nonceExpire);
// }

FlexisipAuthModuleBase::FlexisipAuthModuleBase(su_root_t *root, const std::string &domain, unsigned nonceExpire, bool qopAuth):
	am_realm{domain}, am_qop{qopAuth ? "auth" : ""}, am_expires{nonceExpire}, am_next_exp{nonceExpire}, mRoot{root}, mQOPAuth{qopAuth} {

	mNonceStore.setNonceExpires(nonceExpire);
}

void FlexisipAuthModuleBase::verify(AuthStatus &as, msg_auth_t *credentials, auth_challenger_t const *ach) {
	if (!ach) return;

	auto wildcardPos = find(am_realm.cbegin(), am_realm.cend(), '*');
	auto host = as.domain();

	/* Initialize per-request realm */
	if (as.domain())
		;
	else if (wildcardPos == am_realm.cend()) {
		as.realm(am_realm.c_str());
	} else if (!host) {
		return; /* Internal error */
	} else if (am_realm == "*") {
		as.realm(host);
	} else {
		/* Replace * with hostpart */
		as.realm( string{am_realm.cbegin(), wildcardPos} + host + string{wildcardPos+1, am_realm.cend()} );
	}

	onCheck(as, credentials, ach);
}

void FlexisipAuthModuleBase::onCheck(AuthStatus &as, msg_auth_t *au, auth_challenger_t const *ach) {
	auto &authStatus = dynamic_cast<FlexisipAuthStatus &>(as);

	as.allow(as.allow() || allowCheck(as));

	if (as.realm()) {
		/* Workaround for old linphone client that don't check whether algorithm is MD5 or SHA256.
		 * They then answer for both, but the first one for SHA256 is of course wrong.
		 * We workaround by selecting the second digest response.
		 */
		if (au && au->au_next) {
			auth_response_t r = {0};
			r.ar_size = sizeof(r);
			auth_digest_response_get(as.home(), &r, au->au_next->au_params);

			if (r.ar_algorithm == NULL || !strcasecmp(r.ar_algorithm, "MD5")) {
				au = au->au_next;
			}
		}
		/* After auth_digest_credentials, there is no more au->au_next. */
		au = auth_digest_credentials(au, as.realm(), am_opaque.c_str());
	} else
		au = NULL;

	if (as.allow()) {
		LOGD("AuthStatus[%p]: allow unauthenticated %s", &as, as.method());
		as.status(0), as.phrase(nullptr);
		as.match(reinterpret_cast<msg_header_t *>(au));
		return;
	}

	if (au) {
		LOGD("AuthStatus[%p]: searching for auth digest response for this proxy", &as);
		msg_auth_t *matched_au = ModuleToolbox::findAuthorizationForRealm(as.home(), au, as.realm());
		if (matched_au)
			au = matched_au;
		as.match(reinterpret_cast<msg_header_t *>(au));
		checkAuthHeader(authStatus, au, ach);
	} else {
		/* There was no realm or credentials, send challenge */
		LOGD("AuthStatus[%p]: no credential found for realm '%s'", &as, as.realm());
		challenge(as, ach);
		notify(authStatus);
		return;
	}
}

void FlexisipAuthModuleBase::onChallenge(AuthStatus &as, auth_challenger_t const *ach) {
	auto &flexisipAs = dynamic_cast<FlexisipAuthStatus &>(as);

	challengeDigest(as, ach);

	msg_header_t *response = as.response();
	as.response(nullptr);

	msg_header_t *lastChallenge = nullptr;
	for (const std::string &algo : flexisipAs.usedAlgo()) {
		msg_header_t *challenge;
		LOGD("AuthStatus[%p]: making challenge header for '%s' algorithm", &as, algo.c_str());
		const char *algoValue = msg_header_find_param(response->sh_common, "algorithm");
		if (algo == &algoValue[1]) {
			challenge = response;
		} else {
			const char *param = su_sprintf(as.home(), "algorithm=%s", algo.c_str());
			challenge = msg_header_copy(as.home(), response);
			msg_header_replace_param(as.home(), challenge->sh_common, param);
		}

		if (lastChallenge == nullptr) {
			as.response(challenge);
		} else {
			lastChallenge->sh_auth->au_next = challenge->sh_auth;
		}
		lastChallenge = challenge;
	}
	if (as.response() == nullptr) {
		SLOGE << "AuthStatus[" << &as << "]: no available algorithm while challenge making";
		as.status(500);
		as.phrase("Internal error");
	} else {
		mNonceStore.insert(as.response()->sh_auth);
	}
}

void FlexisipAuthModuleBase::notify(FlexisipAuthStatus &as) {
	as.getPtr()->as_callback(as.magic(), as.getPtr());
}

void FlexisipAuthModuleBase::onError(FlexisipAuthStatus &as) {
	if (as.status() != 0) {
		as.status(500);
		as.phrase("Internal error");
		as.response(nullptr);
	}
}

bool FlexisipAuthModuleBase::allowCheck(AuthStatus &as) {
	auto method = as.method();

	if (method && strcmp(method, "ACK") == 0) { /* Hack */
		as.status(0);
		return true;
	}

	if (!method || am_allow.empty())
		return false;

	if (am_allow[0] == "*") {
		as.status(0);
		return true;
	}

	if (find(am_allow.cbegin(), am_allow.cend(), method) != am_allow.cend()) {
		as.status(0);
		return true;
	}

	return false;
}

void FlexisipAuthModuleBase::challengeDigest(AuthStatus &as, auth_challenger_t const *ach) {
	auto nonce = generateDigestNonce(false, msg_now());

	const auto &u = as.getPtr()->as_uri;
	const auto &d = as.getPtr()->as_pdomain;

	ostringstream resp{};
	resp << "Digest realm=\"" << as.realm() << "\",";
	if (u) resp << " uri=\"" << u << "\",";
	if (d) resp << " domain=\"" << d << "\",";
	resp << " nonce=\"" << nonce << "\",";
	if (!am_opaque.empty()) resp << " opaque=\"" << am_opaque << "\",";
	if (as.stale()) resp << " stale=true,";
	resp << " algorithm=" << am_algorithm;
	if (!am_qop.empty()) resp << ", qop=\"" << am_qop << "\"";

	as.response(msg_header_make(as.home(), ach->ach_header, resp.str().c_str()));
	if (as.response() == nullptr) {
		as.status(500);
		as.phrase(auth_internal_server_error);
	} else {
		as.status(ach->ach_status);
		as.phrase(ach->ach_phrase);
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

	string res(256, '\0');
	auto size = base64_e(&res[0], res.size(), &_nonce, sizeof(_nonce));
	res.resize(size-1);
	return res;
}

// ====================================================================================================================
