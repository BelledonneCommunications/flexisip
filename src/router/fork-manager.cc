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

#include "fork-manager.hh"

#include "agent-injector.hh"
#include "conference/chatroom-prefix.hh"
#include "inject-context.hh"
#include "modules/module-toolbox.hh"

#if ENABLE_SOCI
#include "fork-context/fork-message-context-soci-repository.hh"
#include "schedule-injector.hh"
#endif

using namespace std;
using namespace sofiasip;

namespace flexisip {

std::shared_ptr<ForkManager>
ForkManager::make(Agent* agent, ModuleRouter* router, const GenericStruct* moduleRouterConfig) {
	const auto manager = shared_ptr<ForkManager>{new ForkManager{}};
	manager->mAgent = agent;
	manager->mStats = router->mStats.mForkStats;
	manager->mUseGlobalDomain = moduleRouterConfig->get<ConfigBoolean>("use-global-domain")->read();
	manager->mAllowTargetFactorization = moduleRouterConfig->get<ConfigBoolean>("allow-target-factorization")->read();
	manager->mFactory = make_shared<ForkContextFactory>(agent, manager->mStats, manager, manager, moduleRouterConfig);

#if ENABLE_SOCI
	if (manager->mFactory->messageStorageInDbEnabled()) {
		InjectContext::setMaxRequestRetentionTime(
		    moduleRouterConfig->get<ConfigDuration<chrono::seconds>>("max-request-retention-time")->read());
		manager->mForkMessageDatabase = make_shared<ForkMessageContextSociRepository>(
		    moduleRouterConfig->get<ConfigString>("message-database-backend")->read(),
		    moduleRouterConfig->get<ConfigString>("message-database-connection-string")->read(),
		    moduleRouterConfig->get<ConfigInt>("message-database-pool-size")->read());
		manager->mInjector = make_unique<ScheduleInjector>(router);
		manager->mFactory->setForkMessageDatabase(manager->mForkMessageDatabase);

		manager->restoreForkMessageContextsFromDatabase();
	}
#endif

	if (manager->mInjector == nullptr) manager->mInjector = make_unique<AgentInjector>(router);

	return manager;
}

void ForkManager::inject(std::unique_ptr<RequestSipEvent>&& event,
                         const std::shared_ptr<ForkContext>& forkContext,
                         const std::string& contactId) {
	mInjector->injectRequestEvent(std::move(event), forkContext, contactId);
}

void ForkManager::fork(std::unique_ptr<RequestSipEvent>&& ev,
                       const url_t* sipUri,
                       const ForkGroupSorter::ForkContacts& forkContacts,
                       const std::list<std::string>& domains) {
	const auto ms = ev->getMsgSip();
	const auto* sip = ms->getSip();
	bool isInviteRequest = false;

	if (const auto forkStats = mStats.lock()) {
		forkStats->mCountForks->incrStart();
	} else {
		LOGE << "Failed to increment counter 'count-forks' (std::weak_ptr is empty)";
	}

	shared_ptr<ForkContext> context;
	const auto method = sip->sip_request->rq_method;
	const auto priority = ms->getPriority() <= mMaxPriorityHandled ? ms->getPriority() : mMaxPriorityHandled;
	const auto imIsComposingXml =
	    sip->sip_content_type && strcasecmp(sip->sip_content_type->c_type, "application/im-iscomposing+xml") == 0;
	const auto sipExDeltaIsZero = sip->sip_expires && sip->sip_expires->ex_delta == 0;

	if (method == sip_method_invite) {
		isInviteRequest = true;
		context = mFactory->makeForkCallContext(std::move(ev), MsgSipPriority::Urgent);
	} else if (method == sip_method_message && !imIsComposingXml && !sipExDeltaIsZero) {
		// Note: use the basic fork context for "im-iscomposing+xml" messages to prevent storing useless messages.
		context = mFactory->makeForkMessageContext(std::move(ev), priority);
	} else {
		context = mFactory->makeForkBasicContext(std::move(ev), priority);
	}

	const Record::Key key{sipUri, mUseGlobalDomain};
	context->addKey(key.asString());
	mForks.emplace(key.asString(), context);
	LOGD << "Added new ForkContext[" << context.get() << "] related to key '" << key
	     << "' (count = " << mForks.count(key.asString()) << ")";

	if (context->getConfig()->mForkLate) mAgent->getRegistrarDb().subscribe(key, shared_from_this());

	// Sort the list of 'usable' contacts to form groups (if grouping is allowed).
	ForkGroupSorter sorter(forkContacts);
	if (isInviteRequest && mAllowTargetFactorization) {
		sorter.makeGroups();
	} else {
		sorter.makeDestinations();
	}

	for (const auto& [targetUris, ct, ec] : sorter.getDestinations()) {
		if (!ec->mAlias) {
			mInjector->addContext(context, ec->contactId());
			std::ignore = dispatch(context, ec, targetUris);
			continue;
		}

		if (context->getConfig()->mForkLate && ModuleToolbox::isManagedDomain(mAgent, domains, ct->m_url)) {
			auto* tmpContact =
			    sip_contact_create(ms->getHome(), reinterpret_cast<url_string_t*>(ec->mSipContact->m_url), nullptr);

			if (mUseGlobalDomain) {
				tmpContact->m_url->url_host = "merged";
				tmpContact->m_url->url_port = nullptr;
			}

			const Record::Key aliasKey{tmpContact->m_url, mUseGlobalDomain};
			context->addKey(aliasKey.asString());
			mForks.emplace(aliasKey.asString(), context);
			LOGD << "Added new ForkContext[" << context.get() << "] related to key '" << key
			     << "' (count = " << mForks.count(key.asString()) << ") because it is an alias";

			if (context->getConfig()->mForkLate) mAgent->getRegistrarDb().subscribe(aliasKey, shared_from_this());
		}
	}

	context->start();
}

shared_ptr<BranchInfo> ForkManager::onDispatchNeeded(const shared_ptr<ForkContext>& ctx,
                                                     const shared_ptr<ExtendedContact>& newContact) {
	return dispatch(ctx, newContact);
}

void ForkManager::onUselessRegisterNotification(const std::shared_ptr<ForkContext>& ctx,
                                                const std::shared_ptr<ExtendedContact>& newContact,
                                                const SipUri&,
                                                const std::string&,
                                                const DispatchStatus) {
	mInjector->removeContext(ctx, newContact->contactId());
}

void ForkManager::onForkContextFinished(const shared_ptr<ForkContext>& ctx) {
	for (const auto& key : ctx->getKeys()) {
		const auto [forkKeyIt, forkContextIt] = mForks.equal_range(key);
		for (auto iterator = forkKeyIt; iterator != forkContextIt;) {
			if (iterator->second == ctx) {
				LOGD << "Removing ForkContext[" << iterator->second << "] related to key '" << iterator->first
				     << "' (count = " << mForks.count(iterator->first) << ")";

				if (const auto forkStats = mStats.lock()) {
					forkStats->mCountForks->incrFinish();
				} else {
					LOGE << "Failed to increment counter 'count-forks-finished' (std::weak_ptr is empty)";
				}

				const auto currentIterator = iterator;
				++iterator;
				// For some reason the multimap 'erase' function does not return the next iterator!
				mForks.erase(currentIterator);
				// WARNING: do not break, because a single fork context might appear several times in the map because of
				// aliases.
			} else ++iterator;
		}
	}
}

void ForkManager::onContactRegistered(const std::shared_ptr<Record>& record, const std::string& uid) {
	if (record == nullptr) {
		LOGD << "Received registration event for null record (uid = " << uid << ")";
		return;
	}

	if (!forkLateModeEnabled()) return;
	LOGD << "Received registration event for topic '" << record->getKey() << "' (uid = " << uid << ")";

	Home home{};
	bool forksFound{false};
	sip_contact_t* contact{};

	LOGD << "Retrieving fork contexts with key '" << record->getKey() << "'";

	if (const auto range = getLateForks(record->getKey().asString()); !range.empty()) {
		forksFound = true;
		if (const auto extendedContact = record->extractContactByUniqueId(uid)) {
			contact = extendedContact->toSofiaContact(home.home());
			// First use sipURI
			mInjector->addContext(range, extendedContact->contactId());
			for (const auto& context : range)
				context->onNewRegister(SipUri{contact->m_url}, uid, extendedContact);
		}
	}

	const auto& contacts = record->getExtendedContacts();
	for (const auto& extendedContact : contacts) {
		if (!extendedContact || !extendedContact->mAlias) continue;

		// Find all fork contexts.
		contact = extendedContact->toSofiaContact(home.home());
		const auto range = getLateForks(ExtendedContact::urlToString(extendedContact->mSipContact->m_url));
		mInjector->addContext(range, extendedContact->contactId());
		for (const auto& context : range) {
			forksFound = true;
			context->onNewRegister(SipUri{contact->m_url}, uid, extendedContact);
		}
	}

	if (!forksFound) {
		/*
		 * REVISIT: late cleanup. This is really not the best option. I did this change because the previous way of
		 * cleaning was not working. A better option would be to get rid of the mForks totally and instead rely only on
		 * RegistrarDb::subscribe()/unsubscribe(). Another option would be to keep mForks but make it a simple map of
		 * structure containing the OnContactRegisteredListener handling the topic and a list of ForkContext. When the
		 * list becomes empty, we know that we can clear the structure from mForks.
		 * --SM
		 */
		LOGD << "No longer interested in registration notifications for topic '" << record->getKey() << "'";
		mAgent->getRegistrarDb().unsubscribe(record->getKey(), shared_from_this());
	}
}

std::shared_ptr<BranchInfo> ForkManager::dispatch(const shared_ptr<ForkContext>& context,
                                                  const std::shared_ptr<ExtendedContact>& contact,
                                                  const std::string& targetUris) const {

	const auto& ev = context->getEvent();
	const auto& ms = ev.getMsgSip();

	if (mDispatchFilter(ms->getSip()) == false) return nullptr;

	const auto* ct = contact->toSofiaContact(ms->getHome());
	const auto* dest = ct->m_url;

	// Sanity check on the contact address: might be '*' or whatever useless information.
	if (dest->url_host == nullptr || dest->url_host[0] == '\0') {
		LOGD << "Request is not routed because the contact address is empty";
		mInjector->removeContext(context, contact->contactId());
		return nullptr;
	}

	const auto* contactUrlStr = url_as_string(ms->getHome(), dest);
	auto newRequestEvent = make_unique<RequestSipEvent>(ev);
	const auto newMs = newRequestEvent->getMsgSip();
	msg_t* newMsg = newMs->getMsg();
	auto* newSip = newMs->getSip();

	// Convert 'Path' headers to 'Route' headers.
	auto* routes = contact->toSofiaRoute(newRequestEvent->getHome());
	if (!contact->mUsedAsRoute) {
		if (targetUris.empty()) {
			// Rewrite request-uri.
			newSip->sip_request->rq_url[0] = *url_hdup(msg_home(newMsg), dest);
		}
		// Else leave the request URI as it is, the 'X-target-uris' header will provide the resolved destinations.
		// The cleaning of push notification parameters will be done just before forwarding the request.
	} else {
		// Leave the request URI as it is, but append a 'Route' header for the final destination.
		auto* finalRoute = sip_route_create(newMs->getHome(), dest, NULL);
		if (!url_has_param(finalRoute->r_url, "lr")) url_param_add(newMs->getHome(), finalRoute->r_url, "lr");
		if (routes == nullptr) routes = finalRoute;
		else {
			auto* route = routes;

			while (route->r_next != nullptr)
				route = route->r_next;

			route->r_next = finalRoute;
		}
	}

	if (!contact->mIsFallback) {
		// If the original request received contained an 'X-Target-Uris' header, it shall be removed now, except
		// in the case where we send to a fallback route. In this case the actual resolution of the 'X-Target-Uris'
		// header is actually not done at all.
		if (auto* header =
		        ModuleToolbox::getCustomHeaderByName(newRequestEvent->getMsgSip()->getSip(), mXTargetUrisHeader.data()))
			sip_header_remove(newRequestEvent->getMsgSip()->getMsg(), newRequestEvent->getMsgSip()->getSip(),
			                  reinterpret_cast<sip_header_t*>(header));
	}

	if (!targetUris.empty()) {
		sip_header_insert(newMsg, newSip,
		                  reinterpret_cast<sip_header_t*>(sip_unknown_format(
		                      msg_home(newMsg), (string{mXTargetUrisHeader} + ": %s").c_str(), targetUris.c_str())));
	}

	ModuleToolbox::cleanAndPrependRoute(mAgent, newMsg, newSip, routes);

	LOGI << "Adding new branch to ForkContext[" << context << "] with destination '" << contactUrlStr << "'";
	return context->addBranch(std::move(newRequestEvent), contact);
}

#if ENABLE_SOCI
void ForkManager::restoreForkMessageContextsFromDatabase() {
	LOGI << "Storage of messages in database is enabled, retrieving previous messages in the database";
	auto messages = mForkMessageDatabase->findAllForkMessage();
	LOGI << "Retrieved " << messages.size() << " messages from the database";
	for (auto& dbMessage : messages) {
		if (const auto forkStats = mStats.lock()) {
			forkStats->mCountForks->incrStart();
		} else {
			LOGE << "Failed to increment counter 'count-forks' (std::weak_ptr is empty)";
		}

		auto restoredForkMessage = mFactory->restoreForkMessageContextDbProxy(dbMessage, shared_from_this());
		for (const auto& key : dbMessage.dbKeys) {
			mForks.emplace(key, restoredForkMessage);
			mAgent->getRegistrarDb().subscribe(Record::Key{key}, shared_from_this());
		}
	}
	LOGI << "Actually restored " << mForks.size() << " messages from the database";
}
#endif

ForkManager::ForkRefList ForkManager::getLateForks(const std::string& key) const {
	ForkRefList lateForks{};
	lateForks.reserve(mForks.count(key));
	const auto [forkKeyIt, forkContextIt] = mForks.equal_range(key);
	for (auto iterator = forkKeyIt; iterator != forkContextIt; ++iterator) {
		const auto forkContext = iterator->second;
		if (forkContext->getConfig()->mForkLate) lateForks.emplace_back(forkContext);
	}
	return lateForks;
}

bool ForkManager::forkLateModeEnabled() const {
	return mFactory->callForkLateEnabled() || mFactory->messageForkLateEnabled();
}

} // namespace flexisip