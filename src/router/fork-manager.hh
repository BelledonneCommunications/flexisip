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

#include "flexisip/configmanager.hh"
#include "fork-context/fork-context-factory.hh"
#include "fork-group-sorter.hh"
#include "injector.hh"

namespace flexisip {

/**
 * @brief Manages the forking of SIP requests. It is responsible for coordinating the handling and dispatching of forked
 * SIP requests along with managing forked contexts during the SIP transaction lifecycle.
 */
class ForkManager : public InjectorListener,
                    public ForkContextListener,
                    public ContactRegisteredListener,
                    public std::enable_shared_from_this<ForkManager> {
public:
	~ForkManager() override = default;

	static std::shared_ptr<ForkManager>
	make(Agent* agent, ModuleRouter* router, const GenericStruct* moduleRouterConfig);

	/**
	 * @brief Inject event into the injector.
	 *
	 * @note Method called from ForkContext instances to inject SIP events into the injector (see @Injector).
	 */
	void inject(std::unique_ptr<RequestSipEvent>&& event,
	            const std::shared_ptr<ForkContext>& forkContext,
	            const std::string& contactId) override;

	/**
	 * @brief Execute the forking process on the provided SIP request event.
	 *
	 * @param ev SIP request to be forked
	 * @param sipUri SIP request URI
	 * @param forkContacts list of contacts to which the request will be forked
	 * @param domains the list of SIP domains managed by the registrar
	 */
	void fork(std::unique_ptr<RequestSipEvent>&& ev,
	          const url_t* sipUri,
	          const ForkGroupSorter::ForkContacts& forkContacts,
	          const std::list<std::string>& domains);

	std::shared_ptr<const ForkContextFactory> getFactory() const {
		return mFactory;
	}

	/**
	 * Allows executing the 'dispatch' function (creation of a new branch) under specific conditions.
	 */
	void setDispatchFilter(const std::function<bool(const sip_t*)>& filter) {
		mDispatchFilter = filter;
	}

#if ENABLE_UNIT_TESTS
	void setMaxPriorityHandled(sofiasip::MsgSipPriority maxPriority) const {
		mMaxPriorityHandled = maxPriority;
	}
#endif

private:
	using ForkMapElem = std::shared_ptr<ForkContext>;
	using ForkRefList = std::vector<ForkMapElem>;
	using ForkMap = std::multimap<std::string, ForkMapElem>;

	static constexpr std::string_view mXTargetUrisHeader{"X-Target-Uris"};
	static constexpr std::string_view mLogPrefix{"ForkManager"};

	ForkManager() = default;

	void onForkContextFinished(const std::shared_ptr<ForkContext>& ctx) override;
	std::shared_ptr<BranchInfo> onDispatchNeeded(const std::shared_ptr<ForkContext>& ctx,
	                                             const std::shared_ptr<ExtendedContact>& newContact) override;
	void onUselessRegisterNotification(const std::shared_ptr<ForkContext>& ctx,
	                                   const std::shared_ptr<ExtendedContact>& newContact,
	                                   const SipUri& dest,
	                                   const std::string& uid,
	                                   DispatchStatus reason) override;

	void onContactRegistered(const std::shared_ptr<Record>& record, const std::string& uid) override;

	/**
	 * @brief Create a new fork branch if needed.
	 *
	 * @param context fork context to which add a new branch
	 * @param contact target of the branch to create
	 * @param targetUris list of SIP URIs to add in the custom header 'X-Target-Uris'
	 * @return new fork branch or nullptr if it could not be created (or not needed)
	 */
	std::shared_ptr<BranchInfo> dispatch(const std::shared_ptr<ForkContext>& context,
	                                     const std::shared_ptr<ExtendedContact>& contact,
	                                     const std::string& targetUris = "") const;

#if ENABLE_SOCI
	void restoreForkMessageContextsFromDatabase();
#endif

	/**
	 * @param key key associated with one or more ForkContext instances
	 * @return the list of ForkContext with 'fork-late' enabled related to the provided key
	 */
	ForkRefList getLateForks(const std::string& key) const;

	/**
	 * @return 'true' if 'fork-late' or 'message-fork-late' is enabled.
	 */
	bool forkLateModeEnabled() const;

	Agent* mAgent{};
	ForkMap mForks{};
	bool mUseGlobalDomain{};
	bool mAllowTargetFactorization{};
	mutable sofiasip::MsgSipPriority mMaxPriorityHandled{sofiasip::MsgSipPriority::Normal};
	std::weak_ptr<ForkStats> mStats{};
	std::unique_ptr<Injector> mInjector{};
	std::shared_ptr<ForkContextFactory> mFactory{};
	std::function<bool(const sip_t*)> mDispatchFilter{[](const sip_t*) { return true; }};
};

} // namespace flexisip