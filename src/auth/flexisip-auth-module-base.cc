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

#include <sofia-sip/auth_plugin.h>
#include <sofia-sip/msg_header.h>

#include "log/logmanager.hh"
#include "module.hh"

#include "flexisip-auth-module-base.hh"

using namespace std;


// ====================================================================================================================
//  FlexisipAuthModuleBase class
// ====================================================================================================================

FlexisipAuthModuleBase::FlexisipAuthModuleBase(su_root_t *root, const std::string &domain, const std::string &algo):
AuthModule(root,
		   AUTHTAG_REALM(domain.c_str()),
		   AUTHTAG_OPAQUE("+GNywA=="),
		   AUTHTAG_FORBIDDEN(1),
		   AUTHTAG_ALLOW("ACK CANCEL BYE"),
		   AUTHTAG_ALGORITHM(algo.c_str()),
		   TAG_END()
),
mDisableQOPAuth(true) {
}

FlexisipAuthModuleBase::FlexisipAuthModuleBase(su_root_t *root, const std::string &domain, const std::string &algo, int nonceExpire):
AuthModule(root,
		   AUTHTAG_REALM(domain.c_str()),
		   AUTHTAG_OPAQUE("+GNywA=="),
		   AUTHTAG_QOP("auth"),
		   AUTHTAG_FORBIDDEN(1),
		   AUTHTAG_ALLOW("ACK CANCEL BYE"),
		   AUTHTAG_ALGORITHM(algo.c_str()),
		   AUTHTAG_EXPIRES(nonceExpire),
		   AUTHTAG_NEXT_EXPIRES(nonceExpire),
		   TAG_END()
) {
	mNonceStore.setNonceExpires(nonceExpire);
}

void FlexisipAuthModuleBase::onCheck(AuthStatus &as, msg_auth_t *au, auth_challenger_t const *ach) {
	auto &authStatus = dynamic_cast<FlexisipAuthStatus &>(as);

	as.allow(as.allow() || auth_allow_check(mAm, as.getPtr()) == 0);

	if (as.realm()) {
		/* Workaround for old linphone client that don't check whether algorithm is MD5 or SHA256.
		 * They then answer for both, but the first one for SHA256 is of course wrong.
		 * We workaround by selecting the second digest response.
		 */
		if (au && au->au_next) {
			auth_response_t r;
			memset(&r, 0, sizeof(r));
			r.ar_size = sizeof(r);
			auth_digest_response_get(as.home(), &r, au->au_next->au_params);

			if (r.ar_algorithm == NULL || !strcasecmp(r.ar_algorithm, "MD5")) {
				au = au->au_next;
			}
		}
		/* After auth_digest_credentials, there is no more au->au_next. */
		au = auth_digest_credentials(au, as.realm(), mAm->am_opaque);
	} else
		au = NULL;

	if (as.allow()) {
		LOGD("%s: allow unauthenticated %s", __func__, as.method());
		as.status(0), as.phrase(nullptr);
		as.match(reinterpret_cast<msg_header_t *>(au));
		return;
	}

	if (au) {
		SLOGD << "Searching for auth digest response for this proxy";
		msg_auth_t *matched_au = ModuleToolbox::findAuthorizationForRealm(as.home(), au, as.realm());
		if (matched_au)
			au = matched_au;
		as.match(reinterpret_cast<msg_header_t *>(au));
		checkAuthHeader(authStatus, au, ach);
	} else {
		/* There was no realm or credentials, send challenge */
		SLOGD << __func__ << ": no credentials matched realm or no realm";
		auth_challenge_digest(mAm, as.getPtr(), ach);
		mNonceStore.insert(as.response());

		// Retrieve the password in the hope it will be in cache when the remote UAC
		// sends back its request; this time with the expected authentication credentials.
		if (mImmediateRetrievePass) {
			loadPassword(authStatus);
		}
		finish(authStatus);
		return;
	}
}

void FlexisipAuthModuleBase::onChallenge(AuthStatus &as, auth_challenger_t const *ach) {
	auth_challenge_digest(mAm, as.getPtr(), ach);
}

void FlexisipAuthModuleBase::onCancel(AuthStatus &as) {
	auth_cancel_default(mAm, as.getPtr());
}

/**
 * return true if the event is terminated
 */
void FlexisipAuthModuleBase::finish(FlexisipAuthStatus &as) {
	if ((as.usedAlgo().size() > 1) && (as.status() == 401)) {
		auto *response = reinterpret_cast<msg_auth_t *>(msg_header_copy(as.home(), as.response()));
		msg_header_remove_param(reinterpret_cast<msg_common_t *>(as.response()), "algorithm=MD5");
		msg_header_replace_item(as.home(), reinterpret_cast<msg_common_t *>(as.response()), "algorithm=SHA-256");
		reinterpret_cast<msg_auth_t *>(as.response())->au_next = response;
	}
	as.getPtr()->as_callback(as.magic(), as.getPtr());
}

void FlexisipAuthModuleBase::onError(FlexisipAuthStatus &as) {
	if (as.status() != 0) {
		as.status(500);
		as.phrase("Internal error");
		as.response(nullptr);
	}
	finish(as);
}

// ====================================================================================================================
