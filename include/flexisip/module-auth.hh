/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "flexisip/module-authentication-base.hh"
#include "flexisip/module.hh"
#include "flexisip/sofia-wrapper/auth-module.hh"

namespace flexisip {

class Agent;
class AuthDb;

class Authentication : public ModuleAuthenticationBase {
	friend std::shared_ptr<Module> ModuleInfo<Authentication>::create(Agent*);

public:
	StatCounter64* mCountAsyncRetrieve = nullptr;
	StatCounter64* mCountSyncRetrieve = nullptr;
	StatCounter64* mCountPassFound = nullptr;
	StatCounter64* mCountPassNotFound = nullptr;

	~Authentication() override;

	void onLoad(const GenericStruct* mc) override;
	bool tlsClientCertificatePostCheck(const std::shared_ptr<RequestSipEvent>& ev);
	virtual bool handleTlsClientAuthentication(const std::shared_ptr<RequestSipEvent>& ev);
	void onResponse(std::shared_ptr<ResponseSipEvent>& ev) override;
	void onIdle() override;
	bool doOnConfigStateChanged(const ConfigValue& conf, ConfigState state) override;

	static void declareConfig(GenericStruct& moduleConfig);

protected:
	Authentication(Agent* ag, const ModuleInfoBase* moduleInfo);

private:
	FlexisipAuthModuleBase* createAuthModule(const std::string& domain, int nonceExpire, bool qopAuth) override;

	void processAuthentication(const std::shared_ptr<RequestSipEvent>& request, FlexisipAuthModuleBase& am) override;

	const char* findIncomingSubjectInTrusted(const std::shared_ptr<RequestSipEvent>& ev, const char* fromDomain);

	static ModuleInfo<Authentication> sInfo;
	std::list<std::string> mTrustedClientCertificates;
	regex_t mRequiredSubject;
	bool mNewAuthOn407 = false;
	bool mRequiredSubjectCheckSet = false;
	bool mRejectWrongClientCertificates = false;
	bool mTrustDomainCertificates = false;
	AuthDb& mAuthDb;
};

} // namespace flexisip
