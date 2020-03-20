/*
  Flexisip, a flexible SIP proxy server with media capabilities.
  Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as
  published by the Free Software Foundation, either version 3 of the
  License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "auth-module.hh"
#include "module-authentication-base.hh"

namespace flexisip {

class Authentication : public ModuleAuthenticationBase {
public:
	StatCounter64 *mCountAsyncRetrieve = nullptr;
	StatCounter64 *mCountSyncRetrieve = nullptr;
	StatCounter64 *mCountPassFound = nullptr;
	StatCounter64 *mCountPassNotFound = nullptr;

	Authentication(Agent *ag);
	~Authentication() override;

	void onDeclare(GenericStruct *mc) override;
	void onLoad(const GenericStruct *mc) override;
	bool handleTestAccountCreationRequests(const std::shared_ptr<RequestSipEvent> &ev);
	bool isTrustedPeer(const std::shared_ptr<RequestSipEvent> &ev);
	bool tlsClientCertificatePostCheck(const std::shared_ptr<RequestSipEvent> &ev);
	virtual bool handleTlsClientAuthentication(const std::shared_ptr<RequestSipEvent> &ev);
	void onResponse(std::shared_ptr<ResponseSipEvent> &ev) override;
	void onIdle() override;
	bool doOnConfigStateChanged(const ConfigValue &conf, ConfigState state) override;

private:
	FlexisipAuthModuleBase *createAuthModule(const std::string &domain, int nonceExpire, bool qopAuth) override;

	void validateRequest(const std::shared_ptr<RequestSipEvent> &request) override;
	void processAuthentication(const std::shared_ptr<RequestSipEvent> &request) override;

	bool empty(const char *value) {return value == NULL || value[0] == '\0';}
	const char *findIncomingSubjectInTrusted(const std::shared_ptr<RequestSipEvent> &ev, const char *fromDomain);
	void loadTrustedHosts(const ConfigStringList &trustedHosts);

	static ModuleInfo<Authentication> sInfo;
	std::list<BinaryIp> mTrustedHosts;
	std::list<std::string> mTrustedClientCertificates;
	regex_t mRequiredSubject;
	bool mNewAuthOn407 = false;
	bool mTestAccountsEnabled = false;
	bool mRequiredSubjectCheckSet = false;
	bool mRejectWrongClientCertificates = false;
	bool mTrustDomainCertificates = false;
};

}
