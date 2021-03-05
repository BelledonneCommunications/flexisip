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

#include "digest-authentifier.hh"

using namespace std;


namespace flexisip {

// ====================================================================================================================
//  FlexisipAuthModule::AuthenticationListener class
// ====================================================================================================================

void DigestAuthentifier::GenericAuthListener::onResult(AuthDbResult result, const std::string &passwd) {
	throw logic_error("FlexisipAuthModule::GenericAuthListener::onResult(AuthDbResult, const std::string &) should never be called");
}

void DigestAuthentifier::GenericAuthListener::onResult(AuthDbResult result, const AuthDbBackend::PwList &passwd) {
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

void DigestAuthentifier::GenericAuthListener::main_thread_async_response_cb(su_root_magic_t *rm, su_msg_r msg, void *u) noexcept {
	auto *listener = *reinterpret_cast<GenericAuthListener **>(su_msg_data(msg));
	if (listener->mFunc) listener->mFunc(listener->mResult, listener->mPasswords);
	delete listener;
}
// ====================================================================================================================



// ====================================================================================================================
//  FlexisipAuthModule class
// ====================================================================================================================

void DigestAuthentifier::challenge(const std::shared_ptr<AuthStatus> &as) {
	auto cleanUsedAlgo = [this, &as](AuthDbResult r, const AuthDbBackend::PwList &passwords) {
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
				DigestAuthBase::challenge(as); // Calling FlexisipAuthModuleBase::onChallenge() directly here is forbidden with GCC 4.9 and earlier.
				break;
			}
			case PASSWORD_NOT_FOUND:
				// Make a challenge for each algorithm allowed by Flexisip settings.
				LOGD("AuthStatus[%p]: no password found. Making challenge for each authorized algorithm", &as);
				DigestAuthBase::challenge(as); // Calling FlexisipAuthModuleBase::onChallenge() directly here is forbidden with GCC 4.9 and earlier.
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
void DigestAuthentifier::checkAuthHeader(const std::shared_ptr<AuthStatus> &as, msg_auth_t &au) {
	auto ar = make_shared<AuthResponse>();
	try {
		ar->parse(au.au_params);
	} catch (const runtime_error &e) {
		LOGE("AuthStatus[%p]: %s", &as, e.what());
		as->as_status = 400;
		as->as_phrase = e.what();
		as->as_response = nullptr;
		notify(as);
		return;
	}

	SLOGD << "AuthStatus[" << as << "]: checking auth digest response for realm '" << ar->ar_realm << "'";
	if (ar->ar_username.empty() || !as->as_user_uri->url_user || ar->ar_realm.empty() || !as->as_user_uri->url_host) {
		SLOGE << "Registration failure, authentication info are missing: usernames " <<
		ar->ar_username << "/" << as->as_user_uri->url_user << ", hosts " << ar->ar_realm << "/" << as->as_user_uri->url_host;
		LOGD("from and authentication usernames [%s/%s] or from and authentication hosts [%s/%s] empty",
				ar->ar_username.c_str(), as->as_user_uri->url_user, ar->ar_realm.c_str(), as->as_user_uri->url_host);
		onAccessForbidden(as, "Authentication info missing");
		notify(as);
		return;
	}

	msg_time_t now = msg_now();
	if (as->as_nonce_issued == 0 /* Already validated nonce */ && validateDigestNonce(*as, *ar, now) < 0) {
		challenge(as);;
		notify(as);
		return;
	}

	if (as->as_stale) {
		challenge(as);
		notify(as);
		return;
	}

	if (mQOPAuth) {
		auto pnc = mNonceStore.getNc(ar->ar_nonce);
		auto nnc = ar->getNc<uint32_t>();
		if (pnc >= nnc) {
			SLOGE << "Bad nonce count " << pnc << " -> " << nnc << " for " << ar->ar_nonce;
			challenge(as);
			notify(as);
			return;
		} else {
			mNonceStore.updateNc(ar->ar_nonce, nnc);
		}
	}

	auto unescpapedUrlUser = UriUtils::unescape(as->as_user_uri->url_user);
	auto listener = new GenericAuthListener(
		getRoot(),
		[this, as, ar](AuthDbResult result, const AuthDbBackend::PwList &passwords){
			this->processResponse(as, *ar, result, passwords);
		}
	);
	AuthDbBackend::get().getPassword(unescpapedUrlUser, as->as_user_uri->url_host, ar->ar_username, listener);
	as->as_status = 100;
}

void DigestAuthentifier::processResponse(const std::shared_ptr<AuthStatus> &as, const AuthResponse &ar, AuthDbResult result, const AuthDbBackend::PwList &passwords) {
	ostringstream logPrefixOs{};
	logPrefixOs << "AuthStatus[" << as << "]";

	const auto userId = string{ar.ar_username} + "@" + as->as_realm;
	const auto logPrefix = logPrefixOs.str();

	if (result == PASSWORD_FOUND || result == PASSWORD_NOT_FOUND) {
		if (mPassworFetchResultCb) mPassworFetchResultCb(result == PASSWORD_FOUND);
		as->mPasswordFound = (result == PASSWORD_FOUND);
	}
	switch (result) {
		case PASSWORD_FOUND: {
			auto algosStr = StringUtils::toString(passwords,
				[] (const passwd_algo_t &pw) -> const std::string & {return pw.algo;}
			);
			LOGD("%s: password found for '%s', algorithms=%s", logPrefix.c_str(), userId.c_str(), algosStr.c_str());
			const auto algo = to_string(ar.ar_algorithm);
			if (find(as->mUsedAlgo.cbegin(), as->mUsedAlgo.cend(), algo) == as->mUsedAlgo.cend()) {
				LOGD("%s: '%s' not allowed", logPrefix.c_str(), algo.c_str());
				onAccessForbidden(as);
				break;
			}
			auto pw = find_if(passwords.cbegin(), passwords.cend(), [&algo](const passwd_algo_t &pw) {
				return pw.algo == algo;
			});
			if (pw == passwords.cend()) {
				LOGD("%s: no %s password in database for user '%s'", logPrefix.c_str(), algo.c_str(), userId.c_str());
				onAccessForbidden(as);
				break;
			}
			checkPassword(as, ar, pw->pass);
			break;
		}
		case PASSWORD_NOT_FOUND:
			LOGD("%s: no password found for '%s'", logPrefix.c_str(), userId.c_str());
			onAccessForbidden(as);
			break;
		case AUTH_ERROR:
			LOGD("%s: password fetching failed for '%s'", logPrefix.c_str(), userId.c_str());
			onError(*as);
			break;
		case PENDING:
			LOGD("%s: unhandled asynchronous response %u", logPrefix.c_str(), result);
			onError(*as);
			break;
	}
	notify(as);
}

/**
 * NULL if passwd not found.
 */
void DigestAuthentifier::checkPassword(const std::shared_ptr<AuthStatus> &as, const AuthResponse &ar, const std::string &password) {
	if (checkPasswordForAlgorithm(*as, ar, password)) {
		LOGD("AuthStatus[%p]: passwords did not match", as.get());
		onAccessForbidden(as);
		return;
	}

	if (am_nextnonce)
		infoDigest(*as);

	LOGD("AuthStatus[%p]: successful authentication", &as);

	as->as_status = 0; /* Successful authentication! */
	as->as_phrase = "";
}

int DigestAuthentifier::checkPasswordForAlgorithm(AuthStatus &as, const AuthResponse &ar, std::string ha1) {
	if (ha1.empty()) return -1;

	unique_ptr<Digest> algo{};
	try {
		algo.reset(Digest::create(to_string(ar.ar_algorithm)));
	} catch (const invalid_argument &e) {
		SLOGE << e.what();
		return -1;
	}

	if (ar.ar_algorithm == Algo::Md5sess) {
		ha1 = computeA1SESS(*algo, ar, ha1);
	}

	auto response = computeDigestResponse(*algo, ar, as.as_method, as.as_body.data(), as.as_body.size(), ha1);
	return response == ar.ar_response ? 0 : -1;
}

void DigestAuthentifier::onAccessForbidden(const std::shared_ptr<AuthStatus> &as, std::string phrase) {
	if (!as->mNo403) {
		as->as_status = 403;
		as->as_phrase = move(phrase);
		as->as_response = nullptr;
	} else {
		challenge(as);
	}
}

std::string DigestAuthentifier::computeA1(Digest &algo, const AuthResponse &ar, const std::string &secret) {
	ostringstream data;
	data << ar.ar_username << ':' << ar.ar_realm << ':' << secret;
	string ha1 = algo.compute<string>(data.str());
	SLOGD << "A1 = " << algo.name() << "(" << ar.ar_username << ':' << ar.ar_realm << ":*******) = " << ha1;
	return ha1;
}

std::string DigestAuthentifier::computeA1SESS(Digest &algo, const AuthResponse &ar, const std::string &ha1) {
	ostringstream data;
	data << ha1 << ':' << ar.ar_nonce << ':' << ar.ar_cnonce;
	string newHa1 = algo.compute<string>(data.str());
	SLOGD << "A1 = " << algo.name() << "(" << data.str() << ") = " << newHa1;
	return newHa1;
}

std::string DigestAuthentifier::computeDigestResponse(
	Digest &algo,
	const AuthResponse &ar,
	const std::string &method_name,
	const void *body, size_t bodyLen,
	const std::string &ha1
) {
	/* Calculate Hentity */
	string Hentity = ar.ar_qop == Qop::Auth ? algo.compute<string>(body, bodyLen) : "";

	/* Calculate A2 */
	ostringstream input;
	if (ar.ar_qop == Qop::AuthInt) {
		input << method_name << ':' << ar.ar_uri << ':' << Hentity;
	} else
		input << method_name << ':' << ar.ar_uri;
	auto ha2 = algo.compute<string>(input.str());
	LOGD("A2= %s(%s)", algo.name().c_str(), input.str().c_str());

	/* Calculate response */
	ostringstream input2;
	input2 << ha1 << ':' << ar.ar_nonce;
	if (ar.ar_qop == Qop::Auth || ar.ar_qop == Qop::AuthInt) {
		input2 << ':' << ar.getNc<string>() << ':' << ar.ar_cnonce << ':' << to_string(ar.ar_qop);
	}
	input2 << ':' << ha2;
	auto response = algo.compute<string>(input2.str());
	LOGD("%s(): %s = %s(%s) (qop=%s)", __func__, response.c_str(), algo.name().c_str(),
		 input2.str().c_str(), to_string(ar.ar_qop).c_str());

	return response;
}

int DigestAuthentifier::validateDigestNonce(AuthStatus &as, AuthResponse &ar, msg_time_t now) {
	Nonce nonce[1] = {{0}};

	/* Check nonce */
	if (ar.ar_nonce.empty()) {
		LOGD("%s(): no nonce", __func__);
		return -1;
	}
	if (base64_d(reinterpret_cast<char *>(nonce), sizeof(nonce), ar.ar_nonce.c_str()) != sizeof(nonce)) {
		LOGD("%s(): too short nonce", __func__);
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

	if (nonce->issued > now || (am_expires && nonce->issued + am_expires < now)) {
		LOGD("%s: nonce expired %lu seconds ago "
			 "(lifetime %u)",
			 __func__, now - (nonce->issued + am_expires), am_expires);
		as.as_stale = true;
	}

	auto nc = ar.getNc<uint32_t>();
	if (am_max_ncount) {
		if (nc == AuthResponse::INVALID_NC || nc > am_max_ncount) {
			LOGD("%s: nonce used %u times, max %u\n", __func__, unsigned(nc), am_max_ncount);
			as.as_stale = true;
		}
	}

	/* We should also check cnonce, nc... */

	return 0;
}

void DigestAuthentifier::infoDigest(AuthStatus &as) {
	const auto &method = as.mEvent->getSip()->sip_request->rq_method;
	const auto &ach = method == sip_method_register ? sRegistrarChallenger : sProxyChallenger;
	if (am_nextnonce) {
		auto nonce = generateDigestNonce(true, msg_now());
		as.as_info = msg_header_format(as.mHome.home(), ach.ach_info, "nextnonce=\"%s\"", nonce.c_str());
	}
}

// ====================================================================================================================

} // namespace flexisip
