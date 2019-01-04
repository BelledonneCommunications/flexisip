/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2019  Belledonne Communications SARL.

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

#include "module.hh"
#include "agent.hh"
#include "registrardb.hh"
#include "forkcallcontext.hh"
#include "forkmessagecontext.hh"
#include "forkbasiccontext.hh"

struct RouterStats {
	std::unique_ptr<StatPair> mCountForks;
	std::unique_ptr<StatPair> mCountForkTransactions;
	StatCounter64 *mCountNonForks = nullptr;
	StatCounter64 *mCountLocalActives = nullptr;
};

class ModuleRouter : public Module, public ModuleToolbox, public ForkContextListener {
	RouterStats mStats;
	bool rewriteContactUrl(const std::shared_ptr<MsgSip> &ms, const url_t *ct_url, const char *route);

  public:
	ModuleRouter(Agent *ag) : Module(ag) {
	}

	~ModuleRouter() {
	}

	virtual void onDeclare(GenericStruct *mc) override;

	virtual void onLoad(const GenericStruct *mc) override;

	virtual void onUnload() override {}

	virtual void onRequest(std::shared_ptr<RequestSipEvent> &ev) override;

	virtual void onResponse(std::shared_ptr<ResponseSipEvent> &ev) override;

	virtual void onForkContextFinished(std::shared_ptr<ForkContext> ctx) override;

	void sendReply(std::shared_ptr<RequestSipEvent> &ev, int code, const char *reason, int warn_code = 0, const char *warning = nullptr);
	void routeRequest(std::shared_ptr<RequestSipEvent> &ev, Record *aor, const url_t *sipUri);
	void onContactRegistered(const std::string &uid, Record *aor, const url_t *sipUri);

	const std::string &getFallbackRoute() const {
		return mFallbackRoute;
	}

	bool isFallbackToParentDomainEnabled() const {
		return mFallbackParentDomain;
	}

	bool isDomainRegistrationAllowed() const {
		return mAllowDomainRegistrations;
	}

	bool isManagedDomain(const url_t *url) {
		return ModuleToolbox::isManagedDomain(getAgent(), mDomains, url);
	}

  protected:
	bool makeGeneratedContactRoute(std::shared_ptr<RequestSipEvent> &ev, Record *aor,
								   std::list<std::shared_ptr<ExtendedContact>> &ec_list);
	virtual bool dispatch(const std::shared_ptr<RequestSipEvent> &ev, const std::shared_ptr<ExtendedContact> &contact,
				  std::shared_ptr<ForkContext> context, const std::string &targetUris);
	std::string routingKey(const url_t *sipUri);

	std::list<std::string> mDomains;
	bool mFork = false;
	std::shared_ptr<ForkContextConfig> mForkCfg;
	std::shared_ptr<ForkContextConfig> mMessageForkCfg;
	std::shared_ptr<ForkContextConfig> mOtherForkCfg;
	typedef std::multimap<std::string, std::shared_ptr<ForkContext>> ForkMap;
	ForkMap mForks;
	std::string mGeneratedContactRoute;
	std::string mExpectedRealm;
	bool mUseGlobalDomain = false;
	bool mStateful = false;

	bool mGenerateContactEvenOnFilledAor = false;
	bool mAllowDomainRegistrations = false;
	bool mAllowTargetFactorization = false;
	std::string mPreroute;
	bool mResolveRoutes = false;
	std::string mFallbackRoute;
	bool mFallbackParentDomain = false;

  private:
	static ModuleInfo<ModuleRouter> sInfo;
};