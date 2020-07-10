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

#include <flexisip/module.hh>
#include <flexisip/agent.hh>
#include <flexisip/registrardb.hh>
#include <flexisip/forkcallcontext.hh>
#include <flexisip/forkmessagecontext.hh>
#include <flexisip/forkbasiccontext.hh>

namespace flexisip {

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

	virtual void onForkContextFinished(ForkContext &ctx) override;

	void sendReply(std::shared_ptr<RequestSipEvent> &ev, int code, const char *reason, int warn_code = 0, const char *warning = nullptr);
	void routeRequest(std::shared_ptr<RequestSipEvent> &ev, const std::shared_ptr<Record> &aor, const url_t *sipUri);
	void onContactRegistered(const std::shared_ptr<OnContactRegisteredListener> &listener, const std::string &uid, const std::shared_ptr<Record> &aor, const url_t *sipUri);

	const std::string &getFallbackRoute() const {
		return mFallbackRoute;
	}
	const url_t *getFallbackRouteParsed() const{
		return mFallbackRouteParsed;
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
	virtual bool dispatch(const std::shared_ptr<RequestSipEvent> &ev, const std::shared_ptr<ExtendedContact> &contact,
				  std::shared_ptr<ForkContext> context, const std::string &targetUris);
	virtual bool lateDispatch(const std::shared_ptr<RequestSipEvent> &ev, const std::shared_ptr<ExtendedContact> &contact,
				  std::shared_ptr<ForkContext> context, const std::string &targetUris);
	std::string routingKey(const url_t *sipUri);
	std::vector<std::string> split(const char *data, const char *delim);

	std::list<std::string> mDomains;
	std::shared_ptr<ForkContextConfig> mForkCfg;
	std::shared_ptr<ForkContextConfig> mMessageForkCfg;
	std::shared_ptr<ForkContextConfig> mOtherForkCfg;
	typedef std::multimap<std::string, std::shared_ptr<ForkContext>> ForkMap;
	ForkMap mForks;
	bool mUseGlobalDomain = false;

	bool mAllowDomainRegistrations = false;
	bool mAllowTargetFactorization = false;
	bool mResolveRoutes = false;
	std::string mFallbackRoute;
	url_t *mFallbackRouteParsed = nullptr;
	bool mFallbackParentDomain = false;

  private:
	static ModuleInfo<ModuleRouter> sInfo;
};

class OnContactRegisteredListener : public ContactRegisteredListener, public ContactUpdateListener, public std::enable_shared_from_this<OnContactRegisteredListener> {
	friend class ModuleRouter;
	ModuleRouter *mModule;
	url_t *mSipUri;
	std::string mSipUriAsString;
	sofiasip::Home mHome;

  public:
	OnContactRegisteredListener(ModuleRouter *module, const url_t *sipUri)
	: mModule(module) {
		mSipUri = url_hdup(mHome.home(), sipUri);
		if (url_has_param(mSipUri, "gr")) {
			LOGD("Trying to create a ContactRegistered listener using a SIP URI with a gruu, let's remove it");
			mSipUri->url_params = url_strip_param_string((char*)mSipUri->url_params, "gr");
		}
		mSipUriAsString = url_as_string(mHome.home(), mSipUri);
		LOGD("Listener created for sipUri = %s", mSipUriAsString.c_str());
	}

	~OnContactRegisteredListener() = default;

	void onContactRegistered(const std::shared_ptr<Record> &r, const std::string &uid) override{
		LOGD("Listener invoked for topic = %s, uid = %s, sipUri = %s", r->getKey().c_str(), uid.c_str(), mSipUriAsString.c_str());
		if (r) mModule->onContactRegistered(shared_from_this(), uid, r, mSipUri);
	}
	void onRecordFound(const std::shared_ptr<Record> &r) override{
	}
	void onError() override{
	}
	void onInvalid() override{
	}
	void onContactUpdated(const std::shared_ptr<ExtendedContact> &ec) override{
	}
};

}
