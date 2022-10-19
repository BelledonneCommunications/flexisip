/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <memory>

#include "flexisip/agent.hh"
#include "flexisip/fork-context/fork-context.hh"
#include "flexisip/module.hh"
#include "flexisip/registrardb.hh"
#include "router/injector.hh"

namespace flexisip {

class OnContactRegisteredListener;

struct RouterStats {
	std::unique_ptr<StatPair> mCountForks;
	std::shared_ptr<StatPair> mCountBasicForks;
	std::shared_ptr<StatPair> mCountCallForks;
	std::shared_ptr<StatPair> mCountMessageForks;
	std::shared_ptr<StatPair> mCountMessageProxyForks;
};

class ModuleRouter : public Module,
                     public ModuleToolbox,
                     public ForkContextListener,
                     public std::enable_shared_from_this<ModuleRouter> {
public:
	ModuleRouter(Agent* ag) : Module(ag){};

	~ModuleRouter(){};

	virtual void onDeclare(GenericStruct* mc) override;

	virtual void onLoad(const GenericStruct* mc) override;

	virtual void onUnload() override{};

	virtual void onRequest(std::shared_ptr<RequestSipEvent>& ev) override;

	virtual void onResponse(std::shared_ptr<ResponseSipEvent>& ev) override;

	void onForkContextFinished(const std::shared_ptr<ForkContext>& ctx) override;
	std::shared_ptr<BranchInfo> onDispatchNeeded(const std::shared_ptr<ForkContext>& ctx,
	                                             const std::shared_ptr<ExtendedContact>& newContact) override;
	void onUselessRegisterNotification(const std::shared_ptr<ForkContext>& ctx,
	                                   const std::shared_ptr<ExtendedContact>& newContact,
	                                   const SipUri& dest,
	                                   const std::string& uid,
	                                   const DispatchStatus reason) override;

	void sendReply(std::shared_ptr<RequestSipEvent>& ev,
	               int code,
	               const char* reason,
	               int warn_code = 0,
	               const char* warning = nullptr);
	void routeRequest(std::shared_ptr<RequestSipEvent>& ev, const std::shared_ptr<Record>& aor, const url_t* sipUri);
	void onContactRegistered(const std::shared_ptr<OnContactRegisteredListener>& listener,
	                         const std::string& uid,
	                         const std::shared_ptr<Record>& aor);

	const std::string& getFallbackRoute() const {
		return mFallbackRoute;
	}
	const url_t* getFallbackRouteParsed() const {
		return mFallbackRouteParsed;
	}

	bool isFallbackToParentDomainEnabled() const {
		return mFallbackParentDomain;
	}

	bool isDomainRegistrationAllowed() const {
		return mAllowDomainRegistrations;
	}

	bool isManagedDomain(const url_t* url) {
		return ModuleToolbox::isManagedDomain(getAgent(), mDomains, url);
	}

	const std::shared_ptr<SipBooleanExpression>& getFallbackRouteFilter() const {
		return mFallbackRouteFilter;
	}

	const std::shared_ptr<ForkContextConfig>& getCallForkCfg() const {
		return mCallForkCfg;
	}
	const std::shared_ptr<ForkContextConfig>& getMessageForkCfg() const {
		return mMessageForkCfg;
	}
	const std::shared_ptr<ForkContextConfig>& getOtherForkCfg() const {
		return mOtherForkCfg;
	}

	void sendToInjector(const std::shared_ptr<RequestSipEvent>& ev,
	                    const std::shared_ptr<ForkContext>& context,
	                    const std::string& contactId) {
		mInjector->injectRequestEvent(ev, context, contactId);
	};

	void removeInjectContext(const std::shared_ptr<ForkContext>& context, const std::string& contactId) {
		mInjector->removeContext(context, contactId);
	}

	static void setMaxPriorityHandled(sofiasip::MsgSipPriority maxPriorityHandled) {
		sMaxPriorityHandled = maxPriorityHandled;
	}

	std::shared_ptr<BranchInfo> dispatch(const std::shared_ptr<ForkContext>& context,
	                                     const std::shared_ptr<ExtendedContact>& contact,
	                                     const std::string& targetUris = "");

	RouterStats mStats;

protected:
	using ForkMapElem = std::shared_ptr<ForkContext>;
	using ForkMap = std::multimap<std::string, ForkMapElem>;
	using ForkRefList = std::vector<ForkMapElem>;

	std::string routingKey(const url_t* sipUri);
	std::vector<std::string> split(const char* data, const char* delim);
	ForkRefList getLateForks(const std::string& key) const noexcept;

	std::list<std::string> mDomains;
	std::shared_ptr<ForkContextConfig> mCallForkCfg;
	std::shared_ptr<ForkContextConfig> mMessageForkCfg;
	std::shared_ptr<ForkContextConfig> mOtherForkCfg;
	ForkMap mForks;
	bool mUseGlobalDomain = false;
	bool mAllowDomainRegistrations = false;
	bool mAllowTargetFactorization = false;
	bool mResolveRoutes = false;
	bool mFallbackParentDomain = false;
	std::string mFallbackRoute;
	url_t* mFallbackRouteParsed = nullptr;

private:
	void restoreForksFromDatabase();

	static ModuleInfo<ModuleRouter> sInfo;
	static sofiasip::MsgSipPriority sMaxPriorityHandled;
	std::shared_ptr<SipBooleanExpression> mFallbackRouteFilter;
	std::shared_ptr<OnContactRegisteredListener> mOnContactRegisteredListener{nullptr};
	std::unique_ptr<Injector> mInjector;
};

class OnContactRegisteredListener : public ContactRegisteredListener,
                                    public ContactUpdateListener,
                                    public std::enable_shared_from_this<OnContactRegisteredListener> {
	friend class ModuleRouter;
	ModuleRouter* mModule;
	sofiasip::Home mHome;

public:
	OnContactRegisteredListener(ModuleRouter* module) : mModule(module) {
		SLOGD << "OnContactRegisteredListener created";
	}

	~OnContactRegisteredListener() = default;

	void onContactRegistered(const std::shared_ptr<Record>& r, const std::string& uid) override {
		LOGD("Listener invoked for topic = %s, uid = %s", r->getKey().c_str(), uid.c_str());
		if (r) mModule->onContactRegistered(shared_from_this(), uid, r);
	}

	void onRecordFound(const std::shared_ptr<Record>& r) override {
	}
	void onError() override {
	}
	void onInvalid() override {
	}
	void onContactUpdated(const std::shared_ptr<ExtendedContact>& ec) override {
	}
};

} // namespace flexisip
