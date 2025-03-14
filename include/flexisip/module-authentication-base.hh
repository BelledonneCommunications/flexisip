/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include <array>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>

#include "flexisip/auth/flexisip-auth-module-base.hh"
#include "flexisip/module.hh"

namespace flexisip {

// Forward declaration to avoid to have to publish the RealmExtractor class header.
class RealmExtractor;

/**
 * Base class for Flexisip authentication modules.
 */
class ModuleAuthenticationBase : public Module {
public:
	ModuleAuthenticationBase(Agent* agent, const ModuleInfoBase* moduleInfo);
	~ModuleAuthenticationBase();

	bool isTrustedPeer(const sofiasip::MsgSip& ms);
	static void declareConfig(GenericStruct& root);

protected:
	// ================
	//  Protected types
	// ================

	void onLoad(const GenericStruct* root) override;
	std::unique_ptr<RequestSipEvent> onRequest(std::unique_ptr<RequestSipEvent>&& ev) override;
	std::unique_ptr<ResponseSipEvent> onResponse(std::unique_ptr<ResponseSipEvent>&& ev) override {
		return std::move(ev);
	}

	/**
	 * Override this method to specify the specialization of #FlexisipAuthModuleBase to instantiate.
	 */
	virtual FlexisipAuthModuleBase* createAuthModule(const std::string& domain, int nonceExpire, bool qopAuth) = 0;
	/**
	 * @brief Create and configure a #FlexisipAuthStatus according the information extracted from ev.
	 *
	 * This method may be overridden in order to instantiate a specialization of #FlexisipAuthStatus. Should it be,
	 * the overriding method might call #configureAuthStatus() for configuring the base of the returned object.
	 */
	virtual FlexisipAuthStatus* createAuthStatus(const std::shared_ptr<MsgSip>& msgSip);
	/**
	 * Called by createAuthStatus() for setting #FlexisipAuthStatus attribute for the event request information.
	 */
	void configureAuthStatus(FlexisipAuthStatus& as);

	bool validateRequest(const sofiasip::MsgSip& ms);
	virtual std::unique_ptr<RequestSipEvent> processAuthentication(std::unique_ptr<RequestSipEvent>&& request,
	                                                               FlexisipAuthModuleBase& am);

	/**
	 * Called by onRequest() for getting a #FlexisipAuthModuleBase instance from a domain name.
	 */
	FlexisipAuthModuleBase* findAuthModule(const std::string name);

	/**
	 * This method is called synchronously or asynchronously on result of AuthModule::verify() method.
	 * It calls onSuccess() and errorReply() according the authentication result.
	 */
	std::unique_ptr<RequestSipEvent> processAuthModuleResponse(std::unique_ptr<RequestSipEvent>&& ev, AuthStatus& as);
	virtual void onSuccess(const FlexisipAuthStatus& as);
	virtual void errorReply(RequestSipEvent& ev, const FlexisipAuthStatus& as);

	void loadTrustedHosts(const ConfigStringList& trustedHosts);
	bool empty(const char* value) {
		return value == NULL || value[0] == '\0';
	}

	/**
	 * Test whether a string match a valid algorithm in specified by sValidAlgos.
	 */
	static bool validAlgo(const std::string& algo);

	// =====================
	//  Protected attributes
	// =====================
	std::set<BinaryIp> mTrustedHosts;
	std::map<std::string, std::unique_ptr<FlexisipAuthModuleBase>> mAuthModules;
	std::list<std::string> mAlgorithms;
	auth_challenger_t mRegistrarChallenger;
	auth_challenger_t mProxyChallenger;
	RealmExtractor* mRealmExtractor{nullptr}; /* initially, this attribute was declared as
	    std::unique_ptr<RealmExtractor> but that broke the compilation on Debian/Ubuntu platforms although the default
	    destructor of ModuleAuthenticationBase was declared in the .cc file */
	std::shared_ptr<SipBooleanExpression> mNo403Expr;

	static const std::array<std::string, 2> sValidAlgos;
};

} // namespace flexisip