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

#include <sofia-sip/base64.h>

#include "flexisip/module.hh"

#include "utils/string-utils.hh"
#include "utils/uri-utils.hh"

#include "flexisip-auth-module.hh"

using namespace std;


namespace flexisip {

// ====================================================================================================================
//  FlexisipAuthModule::AuthenticationListener class
// ====================================================================================================================

void FlexisipAuthModule::GenericAuthListener::onResult(AuthDbResult result, const std::string &passwd) {
	throw logic_error("FlexisipAuthModule::GenericAuthListener::onResult(AuthDbResult, const std::string &) should never be called");
}

void FlexisipAuthModule::GenericAuthListener::onResult(AuthDbResult result, const AuthDbBackend::PwList &passwd) {
	// invoke callback on main thread (sofia-sip)
	su_msg_r mamc = SU_MSG_R_INIT;
	if (-1 == su_msg_create(mamc, su_root_task(mRoot), su_root_task(mRoot), main_thread_async_response_cb, sizeof(GenericAuthListener *))) {
		LOGF("Couldn't create auth async message");
	}

	auto **listenerStorage = reinterpret_cast<GenericAuthListener **>(su_msg_data(mamc));
	*listenerStorage = this;
	(*listenerStorage)->mResult = result;
	(*listenerStorage)->mPasswords = passwd;

	if (-1 == su_msg_send(mamc)) {
		LOGF("Couldn't send auth async message to main thread.");
	}
}

void FlexisipAuthModule::GenericAuthListener::main_thread_async_response_cb(su_root_magic_t *rm, su_msg_r msg, void *u) noexcept {
	auto *listener = *reinterpret_cast<GenericAuthListener **>(su_msg_data(msg));
	if (listener->mFunc) listener->mFunc(listener->mResult, listener->mPasswords);
	delete listener;
}
// ====================================================================================================================



// ====================================================================================================================
//  FlexisipAuthModule class
// ====================================================================================================================

void FlexisipAuthModule::challenge(const std::shared_ptr<FlexisipAuthStatus> &as, const auth_challenger_t &ach) {
	auto cleanUsedAlgo = [this, &as, ach](AuthDbResult r, const AuthDbBackend::PwList &passwords) {
		switch (r) {
			case PASSWORD_FOUND: {
				// Make a challenge for each algorithm found in database which has been authorized in Flexisip settings.
				// Make a challenge for each authorized algorithm if no algorithm found in database is allowed in settings.
				SLOGD << "AuthStatus[" << &as << "]: password found with the following algorithms: "
					<< StringUtils::toString(passwords, [](const passwd_algo_t &pw){return pw.algo;});
				list<string> usedAlgo = as->mUsedAlgo;
				usedAlgo.remove_if([&passwords](const std::string &algo){
					return passwords.cend() == find_if(passwords.cbegin(), passwords.cend(), [&algo](const passwd_algo_t &pw) {
						return algo == pw.algo;
					});
				});
				if (usedAlgo.empty()) {
					LOGD("AuthStatus[%p]: no algorithm from database are in the list of authorized algorithm. A challenge will be generated for all authorized algorithms", &as);
				} else {
					as->mUsedAlgo = move(usedAlgo);
				}
				FlexisipAuthModuleBase::challenge(as, ach); // Calling FlexisipAuthModuleBase::onChallenge() directly here is forbidden with GCC 4.9 and earlier.
				break;
			}
			case PASSWORD_NOT_FOUND:
				// Make a challenge for each algorithm allowed by Flexisip settings.
				LOGD("AuthStatus[%p]: no password found. Making challenge for each authorized algorithm", &as);
				FlexisipAuthModuleBase::challenge(as, ach); // Calling FlexisipAuthModuleBase::onChallenge() directly here is forbidden with GCC 4.9 and earlier.
				break;
			case AUTH_ERROR:
				this->onError(*as);
				break;
			case PENDING:
				throw logic_error("unexpected AuthDbResult (PENDING)");
				break;
		}
		notify(as);
	};

	auto *listener = new GenericAuthListener(getRoot(), cleanUsedAlgo);
	string unescpapedUrlUser = UriUtils::unescape(as->as_user_uri->url_user);
	LOGD("AuthStatus[%p]: searching for digest passwords of '%s@%s'", &as, unescpapedUrlUser.c_str(), as->as_user_uri->url_host);
	AuthDbBackend::get().getPassword(unescpapedUrlUser, as->as_user_uri->url_host, unescpapedUrlUser, listener);
	as->as_status = 100;
}

#define PA "Authorization missing "

/** Verify digest authentication */
void FlexisipAuthModule::checkAuthHeader(const std::shared_ptr<FlexisipAuthStatus> &as, msg_auth_t &au, const auth_challenger_t &ach) {
	auto *ar = static_cast<auth_response_t *>(su_alloc(as->mHome.home(), sizeof(auth_response_t)));
	ar->ar_size = sizeof(auth_response_t);

	auth_digest_response_get(as->mHome.home(), ar, au.au_params);
	SLOGD << "AuthStatus[" << as << "]: checking auth digest response for realm '" << ar->ar_realm << "'";

	char const *phrase = "Bad authorization ";
	if ((!ar->ar_username && (phrase = PA "username")) || (!ar->ar_nonce && (phrase = PA "nonce")) ||
		(mQOPAuth && !ar->ar_nc && (phrase = PA "nonce count")) ||
		(!ar->ar_uri && (phrase = PA "URI")) || (!ar->ar_response && (phrase = PA "response")) ||
		/* (!ar->ar_opaque && (phrase = PA "opaque")) || */
		/* Check for qop */
		(ar->ar_qop &&
		((ar->ar_auth && !strcasecmp(ar->ar_qop, "auth") && !strcasecmp(ar->ar_qop, "\"auth\"")) ||
		(ar->ar_auth_int && !strcasecmp(ar->ar_qop, "auth-int") && !strcasecmp(ar->ar_qop, "\"auth-int\""))) &&
		(phrase = PA "has invalid qop"))) {

		// assert(phrase);
		LOGE("AuthStatus[%p]: %s", &as, phrase);
		as->as_status = 400;
		as->as_phrase = phrase;
		as->as_response = nullptr;
		notify(as);
		return;
	}

	if (!ar->ar_username || !as->as_user_uri->url_user || !ar->ar_realm || !as->as_user_uri->url_host) {
		SLOGE << "Registration failure, authentication info are missing: usernames " <<
		ar->ar_username << "/" << as->as_user_uri->url_user << ", hosts " << ar->ar_realm << "/" << as->as_user_uri->url_host;
		LOGD("from and authentication usernames [%s/%s] or from and authentication hosts [%s/%s] empty",
				ar->ar_username, as->as_user_uri->url_user, ar->ar_realm, as->as_user_uri->url_host);
		onAccessForbidden(as, ach, "Authentication info missing");
		notify(as);
		return;
	}

	msg_time_t now = msg_now();
	if (as->as_nonce_issued == 0 /* Already validated nonce */ && validateDigestNonce(*as, *ar, now) < 0) {
		as->as_blacklist = am_blacklist;
		challenge(as, ach);;
		notify(as);
		return;
	}

	if (as->as_stale) {
		challenge(as, ach);
		notify(as);
		return;
	}

	if (mQOPAuth) {
		int pnc = mNonceStore.getNc(ar->ar_nonce);
		int nnc = (int)strtoul(ar->ar_nc, NULL, 16);
		if (pnc == -1 || pnc >= nnc) {
			LOGE("Bad nonce count %d -> %d for %s", pnc, nnc, ar->ar_nonce);
			as->as_blacklist = am_blacklist;
			challenge(as, ach);
			notify(as);
			return;
		} else {
			mNonceStore.updateNc(ar->ar_nonce, nnc);
		}
	}

	auto *listener = new GenericAuthListener(
		getRoot(),
		[this, as, ar, ach](AuthDbResult result, const AuthDbBackend::PwList &passwords){
			this->processResponse(as, *ar, ach, result, passwords);
		}
	);
	string unescpapedUrlUser = UriUtils::unescape(as->as_user_uri->url_user);
	AuthDbBackend::get().getPassword(unescpapedUrlUser, as->as_user_uri->url_host, ar->ar_username, listener);
	as->as_status = 100;
}

void FlexisipAuthModule::processResponse(const std::shared_ptr<FlexisipAuthStatus> &as, const auth_response_t &ar, const auth_challenger_t &ach, AuthDbResult result, const AuthDbBackend::PwList &passwords) {
	if (result == PASSWORD_FOUND || result == PASSWORD_NOT_FOUND) {
		if (mPassworFetchResultCb) mPassworFetchResultCb(result == PASSWORD_FOUND);
		as->mPasswordFound = (result == PASSWORD_FOUND);
	}
	switch (result) {
		case PASSWORD_FOUND: {
			auto algosStr = StringUtils::toString(passwords,
				[] (const passwd_algo_t &pw) -> const std::string & {return pw.algo;}
			);
			LOGD("AuthStatus[%p]: password found for '%s@%s', algorithms=%s", &as, ar.ar_username, as->as_realm.c_str(), algosStr.c_str());
			auto algo = ar.ar_algorithm ? ar.ar_algorithm : "MD5";
			if (find(as->mUsedAlgo.cbegin(), as->mUsedAlgo.cend(), algo) == as->mUsedAlgo.cend()) {
				LOGD("AuthStatus[%p]: '%s' not allowed", &as, algo);
				onAccessForbidden(as, ach);
				break;
			}
			auto pw = find_if(passwords.cbegin(), passwords.cend(), [&algo](const passwd_algo_t &pw) {
				return pw.algo == algo;
			});
			if (pw == passwords.cend()) {
				LOGD("AuthStatus[%p]: no %s password in database for user '%s@%s'", &as, algo, ar.ar_username, ar.ar_realm);
				onAccessForbidden(as, ach);
				break;
			}
			checkPassword(as, ach, ar, pw->pass);
			break;
		}
		case PASSWORD_NOT_FOUND:
			LOGD("password not found for '%s' user, realm=%s", ar.ar_username, as->as_realm.c_str());
			onAccessForbidden(as, ach);
			break;
		case AUTH_ERROR:
			LOGD("password fetching has failed for '%s' user, realm=%s", ar.ar_username, as->as_realm.c_str());
			onError(*as);
			break;
		case PENDING:
			LOGE("Unhandled asynchronous response %u", result);
			onError(*as);
			break;
	}
	notify(as);
}

/**
 * NULL if passwd not found.
 */
void FlexisipAuthModule::checkPassword(const std::shared_ptr<FlexisipAuthStatus> &as, const auth_challenger_t &ach, const auth_response_t &ar, const std::string &password) {
	if (checkPasswordForAlgorithm(*as, ar, password)) {
		LOGD("AuthStatus[%p]: passwords did not match", as.get());
		onAccessForbidden(as, ach);
		return;
	}

	// assert(apw);
	as->as_user = ar.ar_username;
	as->as_anonymous = false;

	if (am_nextnonce)
		infoDigest(*as, ach);

	LOGD("AuthStatus[%p]: successful authentication", &as);

	as->as_status = 0; /* Successful authentication! */
	as->as_phrase = "";
}

int FlexisipAuthModule::checkPasswordForAlgorithm(FlexisipAuthStatus &as, const auth_response_t &ar, std::string ha1) {
	if (ha1.empty()) return -1;

	unique_ptr<Digest> algo{};
	try {
		auto algoName = ar.ar_algorithm ? ar.ar_algorithm : "MD5";
		algo.reset(Digest::create(algoName));
	} catch (const invalid_argument &e) {
		SLOGE << e.what();
		return -1;
	}

	if (ar.ar_md5sess) {
		ha1 = computeA1SESS(*algo, ar, ha1);
	}

	auto response = computeDigestResponse(*algo, ar, as.as_method, as.as_body.data(), as.as_body.size(), ha1);
	return response == ar.ar_response ? 0 : -1;
}

void FlexisipAuthModule::onAccessForbidden(const std::shared_ptr<FlexisipAuthStatus> &as, const auth_challenger_t &ach, const char *phrase) {
	if (am_forbidden && !as->mNo403) {
		as->as_status = 403;
		as->as_phrase = phrase;
		as->as_response = nullptr;
	} else {
		challenge(as, ach);
	}
	as->as_blacklist = am_blacklist;
}

std::string FlexisipAuthModule::computeA1(Digest &algo, const auth_response_t &ar, const std::string &secret) {
	ostringstream data;
	data << ar.ar_username << ':' << ar.ar_realm << ':' << secret;
	string ha1 = algo.compute<string>(data.str());
	SLOGD << "A1 = " << algo.name() << "(" << ar.ar_username << ':' << ar.ar_realm << ":*******) = " << ha1;
	return ha1;
}

std::string FlexisipAuthModule::computeA1SESS(Digest &algo, const ::auth_response_t &ar, const std::string &ha1) {
	ostringstream data;
	data << ha1 << ':' << ar.ar_nonce << ':' << ar.ar_cnonce;
	string newHa1 = algo.compute<string>(data.str());
	SLOGD << "A1 = " << algo.name() << "(" << data.str() << ") = " << newHa1;
	return newHa1;
}

std::string FlexisipAuthModule::computeDigestResponse(
	Digest &algo,
	const ::auth_response_t &ar,
	const std::string &method_name,
	const void *body, size_t bodyLen,
	const std::string &ha1
) {
	/* Calculate Hentity */
	string Hentity = ar.ar_auth_int ? algo.compute<string>(body, bodyLen) : "";

	/* Calculate A2 */
	ostringstream input;
	if (ar.ar_auth_int) {
		input << method_name << ':' << ar.ar_uri << ':' << Hentity;
	} else
		input << method_name << ':' << ar.ar_uri;
	string ha2 = algo.compute<string>(input.str());
	SLOGD << "A2 = " << algo.name() << "(" << input.str() << ")";

	/* Calculate response */
	ostringstream input2;
	input2 << ha1 << ':' << ar.ar_nonce;
	if (ar.ar_auth || ar.ar_auth_int) {
		input2 << ':' << ar.ar_nc << ':' << ar.ar_cnonce << ':' << ar.ar_qop;
	}
	input2 << ':' << ha2;
	string response = algo.compute<string>(input2.str());
	const char *qop = ar.ar_qop ? ar.ar_qop : "NONE";
	SLOGD << __func__ << "(): " << response << " = " << algo.name() << "(" << input2.str() << ") (qop=" << qop << ")";

	return response;
}

int FlexisipAuthModule::validateDigestNonce(FlexisipAuthStatus &as, auth_response_t &ar, msg_time_t now) {
	Nonce nonce[1] = {{0}};

	/* Check nonce */
	if (!ar.ar_nonce) {
		LOGD("%s: no nonce", __func__);
		return -1;
	}
	if (base64_d(reinterpret_cast<char *>(nonce), sizeof(nonce), ar.ar_nonce) != sizeof(nonce)) {
		LOGD("%s: too short nonce", __func__);
		return -1;
	}

	Md5 md5{};
	auto len = reinterpret_cast<char *>(nonce->digest) - reinterpret_cast<char *>(nonce);
	auto hmac = md5.compute<vector<uint8_t>>(&nonce, len);

	if (hmac.size() != sizeof(nonce->digest) || memcmp(nonce->digest, hmac.data(), hmac.size()) != 0) {
		LOGD("%s: bad nonce", __func__);
		return -1;
	}

	as.as_nonce_issued = nonce->issued;
	as.as_nextnonce = (nonce->nextnonce != 0);

	if (nonce->issued > now || (am_expires && nonce->issued + am_expires < now)) {
		LOGD("%s: nonce expired %lu seconds ago "
			 "(lifetime %u)",
			 __func__, now - (nonce->issued + am_expires), am_expires);
		as.as_stale = true;
	}

	if (am_max_ncount && ar.ar_nc) {
		unsigned long nc = strtoul(ar.ar_nc, NULL, 10);

		if (nc == 0 || nc > am_max_ncount) {
			LOGD("%s: nonce used %s times, max %u\n", __func__, ar.ar_nc, am_max_ncount);
			as.as_stale = true;
		}
	}

	/* We should also check cnonce, nc... */

	return 0;
}

void FlexisipAuthModule::infoDigest(FlexisipAuthStatus &as, const auth_challenger_t &ach) {
	if (am_nextnonce) {
		auto nonce = generateDigestNonce(true, msg_now());
		as.as_info = msg_header_format(as.mHome.home(), ach.ach_info, "nextnonce=\"%s\"", nonce.c_str());
	}
}

// ====================================================================================================================

} // namespace flexisip
