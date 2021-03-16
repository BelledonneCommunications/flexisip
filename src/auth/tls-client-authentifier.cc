/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2021  Belledonne Communications SARL, All rights reserved.
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

#include <flexisip/logmanager.hh>

#include "tls-client-authentifier.hh"

using namespace std;

namespace flexisip {

void TlsClientAuthentifier::verify(const std::shared_ptr<AuthStatus> &as) {
	const auto &ev = as->mEvent;
	sip_t *sip = ev->getSip();
	shared_ptr<tport_t> inTport = ev->getIncomingTport();
	unsigned int policy = 0;

	tport_get_params(inTport.get(), TPTAG_TLS_VERIFY_POLICY_REF(policy), NULL);
	// Check TLS certificate
	if ((policy & TPTLS_VERIFY_INCOMING) && tport_is_server(inTport.get())) {
		/* tls client certificate is required for this transport*/
		if (tport_is_verified(inTport.get())) {
			/*the certificate looks good, now match subjects*/
			const url_t *from = sip->sip_from->a_url;
			const char *fromDomain = from->url_host;
			const char *res = NULL;
			url_t searched_uri = URL_INIT_AS(sip);
			sofiasip::Home home;
			char *searched;

			searched_uri.url_host = from->url_host;
			searched_uri.url_user = from->url_user;
			searched = url_as_string(home.home(), &searched_uri);

			if (ev->findIncomingSubject(searched)) {
				SLOGD << "Allowing message from matching TLS certificate";
				goto postcheck;
			} else if (sip->sip_request->rq_method != sip_method_register &&
					   (res = findIncomingSubjectInTrusted(ev, fromDomain))) {
				SLOGD << "Found trusted TLS certificate " << res;
				goto postcheck;
			} else {
				/*case where the certificate would work for the entire domain*/
				searched_uri.url_user = NULL;
				searched = url_as_string(home.home(), &searched_uri);
				if (ev->findIncomingSubject(searched)) {
					SLOGD << "Found TLS certificate for entire domain";
					goto postcheck;
				}
			}

			if (sip->sip_request->rq_method != sip_method_register && mTrustDomainCertificates) {
				searched_uri.url_user = NULL;
				searched_uri.url_host = sip->sip_request->rq_url->url_host;
				searched = url_as_string(home.home(), &searched_uri);
				if (ev->findIncomingSubject(searched)) {
					SLOGD << "Found trusted TLS certificate for the request URI domain";
					goto postcheck;
				}
			}

			LOGE("Client is presenting a TLS certificate not matching its identity.");
			SLOGUE << "Registration failure for " << url_as_string(home.home(), from)
				   << ", TLS certificate doesn't match its identity";
			goto bad_certificate;

		postcheck:
			if (tlsClientCertificatePostCheck(ev)) {
				/*all is good, return true*/
				notify(as, Status::Pass);
				return;
			} else
				goto bad_certificate;
		} else
			goto bad_certificate;

	bad_certificate:
		if (mRejectWrongClientCertificates) {
			as->as_status = 403;
			as->as_phrase = "Bad tls client certificate";
			notify(as, Status::Reject);
			return; /*the request is responded, no further processing required*/
		}
		/*fallback to digest*/
		continue_(as);
		return;
	}
	/*no client certificate requested, go to digest auth*/
	continue_(as);
}

const char *TlsClientAuthentifier::findIncomingSubjectInTrusted(const std::shared_ptr<RequestSipEvent> &ev, const char *fromDomain) {
	if (mTrustedClientCertificates.empty())
		return NULL;
	list<string> toCheck;
	for (auto it = mTrustedClientCertificates.cbegin(); it != mTrustedClientCertificates.cend(); ++it) {
		if (it->find("@") != string::npos)
			toCheck.push_back(*it);
		else
			toCheck.push_back(*it + "@" + string(fromDomain));
	}
	const char *res = ev->findIncomingSubject(toCheck);
	return res;
}

bool TlsClientAuthentifier::tlsClientCertificatePostCheck(const std::shared_ptr<RequestSipEvent> &ev) {
	if (mRequiredSubjectCheckSet){
		bool ret = ev->matchIncomingSubject(mRequiredSubject);
		if (ret){
			SLOGD<<"TLS certificate postcheck successful.";
		}else{
			SLOGUE<<"TLS certificate postcheck failed.";
		}
		return ret;
	}
	return true;
}

}
