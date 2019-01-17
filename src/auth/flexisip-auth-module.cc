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

#include <bctoolbox/crypto.h>

#include <flexisip/module.hh>

#include "flexisip-auth-module.hh"

using namespace std;
using namespace flexisip;

// ====================================================================================================================
//  FlexisipAuthModule::AuthenticationListener class
// ====================================================================================================================

void FlexisipAuthModule::AuthenticationListener::main_thread_async_response_cb(su_root_magic_t *rm, su_msg_r msg, void *u) {
	AuthenticationListener *listener = *reinterpret_cast<AuthenticationListener **>(su_msg_data(msg));
	listener->mAm.processResponse(*listener);
	delete listener;
}

void FlexisipAuthModule::AuthenticationListener::onResult(AuthDbResult result, const vector<passwd_algo_t> &passwd) {
	// invoke callback on main thread (sofia-sip)
	su_msg_r mamc = SU_MSG_R_INIT;
	if (-1 == su_msg_create(mamc, su_root_task(mAm.getRoot()), su_root_task(mAm.getRoot()), main_thread_async_response_cb,
		sizeof(AuthenticationListener *))) {
		LOGF("Couldn't create auth async message");
		}

		string algo = "";
	AuthenticationListener **listenerStorage = (AuthenticationListener **)su_msg_data(mamc);
	*listenerStorage = this;

	switch (result) {
		case PASSWORD_FOUND:
			mResult = AuthDbResult::PASSWORD_FOUND;

			if (mAr.ar_algorithm == NULL || !strcmp(mAr.ar_algorithm, "MD5")) {
				algo = "MD5";
			} else if (!strcmp(mAr.ar_algorithm, "SHA-256")) {
				algo = "SHA-256";
			} else {
				mResult = AuthDbResult::AUTH_ERROR;
				break;
			}

			for (const auto &password : passwd) {
				if (password.algo == algo) mPassword = password.pass;
			}

			if (mPassword.empty()) {
				mResult = AuthDbResult::PASSWORD_NOT_FOUND;
			}

			break;
		case PASSWORD_NOT_FOUND:
			mResult = AuthDbResult::PASSWORD_NOT_FOUND;
			mPassword = "";
			break;
		case AUTH_ERROR:
			/*in that case we can fallback to the cached password previously set*/
			break;
		case PENDING:
			LOGF("unhandled case PENDING");
			break;
	}
	if (-1 == su_msg_send(mamc)) {
		LOGF("Couldn't send auth async message to main thread.");
	}
}

void FlexisipAuthModule::AuthenticationListener::onResult(AuthDbResult result, const string &passwd) {
	// invoke callback on main thread (sofia-sip)
	su_msg_r mamc = SU_MSG_R_INIT;
	if (-1 == su_msg_create(mamc, su_root_task(mAm.getRoot()), su_root_task(mAm.getRoot()), main_thread_async_response_cb,
		sizeof(AuthenticationListener *))) {
		LOGF("Couldn't create auth async message");
		}

		AuthenticationListener **listenerStorage = (AuthenticationListener **)su_msg_data(mamc);
	*listenerStorage = this;

	switch (result) {
		case PASSWORD_FOUND:
			mResult = AuthDbResult::PASSWORD_FOUND;
			mPassword = passwd;
			break;
		case PASSWORD_NOT_FOUND:
			mResult = AuthDbResult::PASSWORD_NOT_FOUND;
			mPassword = "";
			break;
		case AUTH_ERROR:
			/*in that case we can fallback to the cached password previously set*/
			break;
		case PENDING:
			LOGF("unhandled case PENDING");
			break;
	}
	if (-1 == su_msg_send(mamc)) {
		LOGF("Couldn't send auth async message to main thread.");
	}
}

void FlexisipAuthModule::AuthenticationListener::finishVerifyAlgos(const vector<passwd_algo_t> &pass) {
	mAs.usedAlgo().remove_if([&pass](string algo) {
		bool found = false;

		for (const auto &password : pass) {
			if (password.algo == algo) {
				found = true;
				break;
			}
		}

		return !found;
	});

	mAm.finish(mAs);
}

// ====================================================================================================================

// ====================================================================================================================
//  FlexisipAuthModule class
// ====================================================================================================================


#define PA "Authorization missing "

/** Verify digest authentication */
void FlexisipAuthModule::checkAuthHeader(FlexisipAuthStatus &as, msg_auth_t *au, auth_challenger_t const *ach) {
	auth_response_t ar = {0};
	ar.ar_size = sizeof(ar);

	auth_digest_response_get(as.home(), &ar, au->au_params);
	SLOGD << "Using auth digest response for realm " << ar.ar_realm;

	char const *phrase = "Bad authorization ";
	if ((!ar.ar_username && (phrase = PA "username")) || (!ar.ar_nonce && (phrase = PA "nonce")) ||
		(!mDisableQOPAuth && !ar.ar_nc && (phrase = PA "nonce count")) ||
		(!ar.ar_uri && (phrase = PA "URI")) || (!ar.ar_response && (phrase = PA "response")) ||
		/* (!ar.ar_opaque && (phrase = PA "opaque")) || */
		/* Check for qop */
		(ar.ar_qop &&
		((ar.ar_auth && !strcasecmp(ar.ar_qop, "auth") && !strcasecmp(ar.ar_qop, "\"auth\"")) ||
		(ar.ar_auth_int && !strcasecmp(ar.ar_qop, "auth-int") && !strcasecmp(ar.ar_qop, "\"auth-int\""))) &&
		(phrase = PA "has invalid qop"))) {

		// assert(phrase);
		LOGD("auth_method_digest: 400 %s", phrase);
		as.status(400);
		as.phrase(phrase);
		as.response(nullptr);
		finish(as);
		return;
		}

		if (!ar.ar_username || !as.userUri()->url_user || !ar.ar_realm || !as.userUri()->url_host) {
			as.status(403);
			as.phrase("Authentication info missing");
			SLOGUE << "Registration failure, authentication info are missing: usernames " <<
			ar.ar_username << "/" << as.userUri()->url_user << ", hosts " << ar.ar_realm << "/" << as.userUri()->url_host;
			LOGD("from and authentication usernames [%s/%s] or from and authentication hosts [%s/%s] empty",
				 ar.ar_username, as.userUri()->url_user, ar.ar_realm, as.userUri()->url_host);
			as.response(nullptr);
			finish(as);
			return;
		}

		msg_time_t now = msg_now();
		if (as.nonceIssued() == 0 /* Already validated nonce */ && auth_validate_digest_nonce(mAm, as.getPtr(), &ar, now) < 0) {
			as.blacklist(mAm->am_blacklist);
			auth_challenge_digest(mAm, as.getPtr(), ach);
			mNonceStore.insert(as.response());
			finish(as);
			return;
		}

		if (as.stale()) {
			auth_challenge_digest(mAm, as.getPtr(), ach);
			mNonceStore.insert(as.response());
			finish(as);
			return;
		}

		if (!mDisableQOPAuth) {
			int pnc = mNonceStore.getNc(ar.ar_nonce);
			int nnc = (int)strtoul(ar.ar_nc, NULL, 16);
			if (pnc == -1 || pnc >= nnc) {
				LOGE("Bad nonce count %d -> %d for %s", pnc, nnc, ar.ar_nonce);
				as.blacklist(mAm->am_blacklist);
				auth_challenge_digest(mAm, as.getPtr(), ach);
				mNonceStore.insert(as.response());
				finish(as);
				return;
			} else {
				mNonceStore.updateNc(ar.ar_nonce, nnc);
			}
		}

		AuthenticationListener *listener = new AuthenticationListener(*this, as, *ach, ar);
		AuthDbBackend::get().getPassword(as.userUri()->url_user, as.userUri()->url_host, ar.ar_username, listener);
		as.status(100);
}

void FlexisipAuthModule::loadPassword(const FlexisipAuthStatus &as) {
	SLOGD << "Searching for " << as.userUri()->url_user << " password to have it when the authenticated request comes";
	AuthDbBackend::get().getPassword(as.userUri()->url_user, as.userUri()->url_host, as.userUri()->url_user, nullptr);
}

void FlexisipAuthModule::processResponse(AuthenticationListener &l) {
	switch (l.result()) {
		case PASSWORD_FOUND:
		case PASSWORD_NOT_FOUND:
			l.authStatus().passwordFound(l.result() == PASSWORD_FOUND);
			checkPassword(l.authStatus(), l.challenger(), *l.response(), l.password().c_str());
			finish(l.authStatus());
			break;
		case AUTH_ERROR:
			onError(l.authStatus());
			break;
		default:
			LOGE("Unhandled asynchronous response %u", l.result());
			onError(l.authStatus());
	}
}

/**
 * NULL if passwd not found.
 */
void FlexisipAuthModule::checkPassword(FlexisipAuthStatus &as, const auth_challenger_t &ach, auth_response_t &ar, const char *password) {
	if (checkPasswordForAlgorithm(as, ar, password)) {
		if (getPtr()->am_forbidden && !as.no403()) {
			as.status(403);
			as.phrase("Forbidden");
			as.response(nullptr);
			as.blacklist(getPtr()->am_blacklist);
		} else {
			auth_challenge_digest(getPtr(), as.getPtr(), &ach);
			nonceStore().insert(as.response());
			as.blacklist(getPtr()->am_blacklist);
		}
		if (password) {
			SLOGUE << "Registration failure, password did not match";
			LOGD("auth_method_digest: password '%s' did not match", password);
		} else {
			SLOGUE << "Registration failure, no password";
			LOGD("auth_method_digest: no password");
		}

		return;
	}

	// assert(apw);
	as.user(ar.ar_username);
	as.anonymous(false);

	if (getPtr()->am_nextnonce || getPtr()->am_mutual)
		auth_info_digest(getPtr(), as.getPtr(), &ach);

	if (getPtr()->am_challenge)
		auth_challenge_digest(getPtr(), as.getPtr(), &ach);

	LOGD("auth_method_digest: successful authentication");

	as.status(0); /* Successful authentication! */
	as.phrase("");
}

int FlexisipAuthModule::checkPasswordForAlgorithm(FlexisipAuthStatus &as, auth_response_t &ar, const char *passwd) {
	if ((ar.ar_algorithm == NULL) || (!strcmp(ar.ar_algorithm, "MD5"))) {
		return checkPasswordMd5(as, ar, passwd);
	} else if (!strcmp(ar.ar_algorithm, "SHA-256")) {
		if (passwd && passwd[0] == '\0')
			passwd = NULL;

		string a1;
		if (passwd) {
			// 			++*getModule()->mCountPassFound;
			a1 = passwd;
		} else {
			// 			++*getModule()->mCountPassNotFound;
			a1 = auth_digest_a1_for_algorithm(&ar, "xyzzy");
		}

		if (ar.ar_md5sess)
			a1 = auth_digest_a1sess_for_algorithm(&ar, a1);

		string response = auth_digest_response_for_algorithm(&ar, as.method(), as.body(), as.bodyLen(), a1);
		return (passwd && response == ar.ar_response ? 0 : -1);
	}
	return -1;
}

int FlexisipAuthModule::checkPasswordMd5(FlexisipAuthStatus &as, auth_response_t &ar, const char *passwd){
	char const *a1;
	auth_hexmd5_t a1buf, response;

	if (passwd && passwd[0] == '\0')
		passwd = NULL;

	if (passwd) {
		// 		++*getModule()->mCountPassFound;
		strncpy(a1buf, passwd, sizeof(a1buf)-1); // remove trailing NULL character
		a1buf[sizeof(a1buf)-1] = '\0';
		a1 = a1buf;
	} else {
		// 		++*getModule()->mCountPassNotFound;
		auth_digest_a1(&ar, a1buf, "xyzzy"), a1 = a1buf;
	}

	if (ar.ar_md5sess)
		auth_digest_a1sess(&ar, a1buf, a1), a1 = a1buf;

	auth_digest_response(&ar, response, a1, as.method(), as.body(), as.bodyLen());
	return !passwd || strcmp(response, ar.ar_response);
}

std::string FlexisipAuthModule::auth_digest_a1_for_algorithm(const ::auth_response_t *ar, const std::string &secret) {
	ostringstream data;
	data << ar->ar_username << ':' << ar->ar_realm << ':' << secret;
	string ha1 = sha256(data.str());
	SLOGD << "auth_digest_ha1() has A1 = SHA256(" << ar->ar_username << ':' << ar->ar_realm << ":*******) = " << ha1 << endl;
	return ha1;
}

std::string FlexisipAuthModule::auth_digest_a1sess_for_algorithm(const ::auth_response_t *ar, const std::string &ha1) {
	ostringstream data;
	data << ha1 << ':' << ar->ar_nonce << ':' << ar->ar_cnonce;
	string newHa1 = sha256(data.str());
	SLOGD << "auth_sessionkey has A1' = SHA256(" << data.str() << ") = " << newHa1 << endl;
	return newHa1;
}

std::string FlexisipAuthModule::auth_digest_response_for_algorithm(
	::auth_response_t *ar,
	char const *method_name,
	void const *data,
	isize_t dlen,
	const std::string &ha1
) {
	if (ar->ar_auth_int)
		ar->ar_qop = "auth-int";
	else if (ar->ar_auth)
		ar->ar_qop = "auth";
	else
		ar->ar_qop = NULL;

	/* Calculate Hentity */
	string Hentity;
	if (ar->ar_auth_int) {
		if (data && dlen) {
			Hentity = sha256(data, dlen);
		} else {
			Hentity = "d7580069de562f5c7fd932cc986472669122da91a0f72f30ef1b20ad6e4f61a3";
		}
	}

	/* Calculate A2 */
	ostringstream input;
	if (ar->ar_auth_int) {
		input << method_name << ':' << ar->ar_uri << ':' << Hentity;
	} else
		input << method_name << ':' << ar->ar_uri;
	string ha2 = sha256(input.str());
	SLOGD << "A2 = SHA256(" << input.str() << ")" << endl;

	/* Calculate response */
	ostringstream input2;
	input2 << ha1 << ':' << ar->ar_nonce;
	if (ar->ar_auth || ar->ar_auth_int) {
		input2 << ':' << ar->ar_nc << ':' << ar->ar_cnonce << ':' << ar->ar_qop;
	}
	input2 << ':' << ha2;
	string response = sha256(input2.str());
	const char *qop = ar->ar_qop ? ar->ar_qop : "NONE";
	SLOGD << "auth_response: " << response << " = SHA256(" << input2.str() << ") (qop=" << qop << ")" << endl;

	return response;
}

std::string FlexisipAuthModule::sha256(const std::string &data) {
	vector<uint8_t> hash(32);
	bctbx_sha256(reinterpret_cast<const uint8_t *>(data.c_str()), data.size(), hash.size(), hash.data());
	return toString(hash);
}

std::string FlexisipAuthModule::sha256(const void *data, size_t len) {
	vector<uint8_t> hash(32);
	bctbx_sha256(reinterpret_cast<const uint8_t *>(data), len, hash.size(), hash.data());
	return toString(hash);
}

std::string FlexisipAuthModule::toString(const std::vector<uint8_t> &data) {
	char formatedByte[3];
	string res;

	res.reserve(data.size() * 2);
	for (const uint8_t &byte : data) {
		snprintf(formatedByte, sizeof(formatedByte), "%02hhx", byte);
		res += formatedByte;
	}
	return res;
}

// ====================================================================================================================
