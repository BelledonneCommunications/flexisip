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

#include <flexisip/auth-module.hh>
#include <flexisip/module.hh>

namespace flexisip {

class Authentication : public Module {
public:
	StatCounter64 *mCountAsyncRetrieve = nullptr;
	StatCounter64 *mCountSyncRetrieve = nullptr;
	StatCounter64 *mCountPassFound = nullptr;
	StatCounter64 *mCountPassNotFound = nullptr;

	Authentication(Agent *ag);
	~Authentication() override;

	void onDeclare(GenericStruct *mc) override;
	void onLoad(const GenericStruct *mc) override;
	AuthModule *findAuthModule(const std::string name);
	static bool containsDomain(const std::list<std::string> &d, const char *name);
	bool handleTestAccountCreationRequests(std::shared_ptr<RequestSipEvent> &ev);
	bool isTrustedPeer(std::shared_ptr<RequestSipEvent> &ev);
	bool tlsClientCertificatePostCheck(const std::shared_ptr<RequestSipEvent> &ev);
	virtual bool handleTlsClientAuthentication(std::shared_ptr<RequestSipEvent> &ev);
	void onRequest(std::shared_ptr<RequestSipEvent> &ev) override;
	void onResponse(std::shared_ptr<ResponseSipEvent> &ev) override;
	void onIdle() override;
	bool doOnConfigStateChanged(const ConfigValue &conf, ConfigState state) override;

private:
	void processAuthModuleResponse(AuthStatus &as);
	bool empty(const char *value) {return value == NULL || value[0] == '\0';}
	const char *findIncomingSubjectInTrusted(std::shared_ptr<RequestSipEvent> &ev, const char *fromDomain);
	void loadTrustedHosts(const ConfigStringList &trustedHosts);

	static ModuleInfo<Authentication> sInfo;
	std::map<std::string, std::unique_ptr<AuthModule>> mAuthModules;
	std::list<std::string> mDomains;
	std::list<BinaryIp> mTrustedHosts;
	std::list<std::string> mTrustedClientCertificates;
	std::list<std::string> mAlgorithms;
	regex_t mRequiredSubject;
	auth_challenger_t mRegistrarChallenger;
	auth_challenger_t mProxyChallenger;
	std::shared_ptr<SipBooleanExpression> mNo403Expr;
	bool mNewAuthOn407 = false;
	bool mTestAccountsEnabled = false;
	bool mDisableQOPAuth = false;
	bool mRequiredSubjectCheckSet = false;
	bool mRejectWrongClientCertificates = false;
	bool mTrustDomainCertificates = false;
};

}
