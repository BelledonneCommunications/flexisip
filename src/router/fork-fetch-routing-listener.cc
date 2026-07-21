/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "fork-fetch-routing-listener.hh"

#include "agent.hh"
#include "eventlogs/events/eventlogs.hh"
#include "fork-manager.hh"
#include "modules/module-toolbox.hh"

using namespace std;

namespace flexisip {

TargetUriListFetcher::TargetUriListFetcher(Agent* agent,
                                           RequestSipEvent& ev,
                                           const shared_ptr<ContactUpdateListener>& listener,
                                           const sip_unknown_t* target_uris)
    : mListener(listener), mRegistrarDb(agent->getRegistrarDb()) {
	mRecord = make_shared<Record>(SipUri(), mRegistrarDb.getRecordConfig());
	if (target_uris && target_uris->un_value) {
		// The X-target-uris header is parsed like a route, as it is a list of URIs
		const auto routes = sip_route_make(ev.getHome(), target_uris->un_value);

		for (sip_route_t* iter = routes; iter; iter = iter->r_next) {
			try {
				SipUri uri(iter->r_url);
				mUriList.push_back(std::move(uri));
			} catch (const sofiasip::InvalidUrlError& e) {
				vector<char> buffer(1024);
				sip_unknown_e(buffer.data(), buffer.size(), (msg_header_t*)target_uris, 0);
				LOGW << "Invalid URI in X-Target-Uris header [" << e.getUrl() << "], ignoring it, context:" << endl
				     << ev.getMsgSip()->contextAsString() << endl
				     << buffer.data() << endl;
			}
		}
	}
}

void TargetUriListFetcher::fetch(bool allowDomainRegistrations, bool recursive) {
	// Compute the number of asynchronous queries we are going to make, to later know when we are done.
	mPending = mUriList.size();

	// Start the queries for all uris of the target uri list.
	for (const auto& uri : mUriList) {
		mRegistrarDb.fetch(uri, this->shared_from_this(), allowDomainRegistrations, recursive);
	}
}

void TargetUriListFetcher::onRecordFound(const shared_ptr<Record>& r) {
	--mPending;
	if (r != nullptr) {
		mRecord->appendContactsFrom(r);
	}
	checkFinished();
}

void TargetUriListFetcher::onError(const SipStatus&) {
	--mPending;
	mError = true;
	checkFinished();
}

void TargetUriListFetcher::onInvalid(const SipStatus&) {
	--mPending;
	mError = true;
	checkFinished();
}

void TargetUriListFetcher::checkFinished() {
	if (mPending != 0) return;
	if (mError) {
		mListener->onError(SipStatus(SIP_500_INTERNAL_SERVER_ERROR));
	} else {
		if (mRecord->count() > 0) {
			auto& contacts = mRecord->getExtendedContacts();
			// Also add aliases in the ExtendedContact list for the searched AORs, so that they are added to the
			// ForkMap.
			for (const auto& uri : mUriList) {
				shared_ptr<ExtendedContact> alias =
				    make_shared<ExtendedContact>(uri, "", mRegistrarDb.getRecordConfig().messageExpiresName());
				alias->mAlias = true;
				contacts.emplace(std::move(alias));
			}
		}
		mListener->onRecordFound(mRecord);
	}
}

ForkFetchRoutingListener::ForkFetchRoutingListener(const std::shared_ptr<ForkManager>& forkManager,
                                                   const std::shared_ptr<ForkContext>& forkContext,
                                                   const SipUri& sipuri,
                                                   bool isInviteRequest,
                                                   stl_backports::move_only_function<void(bool)>&& onEmptyContacts)

    : mForkManager(forkManager), mForkContext(forkContext), mSipUri(sipuri), mIsInviteRequest(isInviteRequest),
      mEmptyContactsCb(std::move(onEmptyContacts)) {}

void ForkFetchRoutingListener::onRecordFound(const shared_ptr<Record>& arg) {
	shared_ptr<Record> r = arg;

	const auto& routingConfig = mForkManager->getRoutingConfig();
	const string& fallbackRoute = routingConfig.mFallbackRoute;
	const auto& recordConfig = mForkManager->getAgent()->getRegistrarDb().getRecordConfig();
	const auto& msgExpiresName = recordConfig.messageExpiresName();

	if (r == nullptr) {
		r = make_shared<Record>(mSipUri, recordConfig);
	}

	auto& contacts = r->getExtendedContacts();
	for (const auto& uri : routingConfig.mStaticTargets) {
		contacts.emplace(make_shared<ExtendedContact>(uri, "", msgExpiresName));
	}

	if (!ModuleToolbox::isManagedDomain(mForkManager->getAgent(), routingConfig.mDomains, mSipUri.get())) {
		const auto contact =
		    r->getExtendedContacts().emplace(make_shared<ExtendedContact>(mSipUri, "", msgExpiresName));

		LOGD << "Record[" << r << "]: original request URI added because domain is not managed " << **contact;
	}

	auto& event = mForkContext->getEvent();
	if (!fallbackRoute.empty() && routingConfig.mFallbackRouteFilter->eval(*event.getMsgSip()->getSip())) {
		if (!ModuleToolbox::viaContainsUrlHost(event.getMsgSip()->getSip()->sip_via,
		                                       routingConfig.mFallbackRouteParsed)) {
			const auto fallback = make_shared<ExtendedContact>(mSipUri, fallbackRoute, msgExpiresName, 0.0);
			fallback->mIsFallback = true;
			r->getExtendedContacts().emplace(fallback);
			LOGD << "Record[" << r << "] fallback-route '" << fallbackRoute << "' added (" << *fallback << ")";
		} else {
			LOGD << "Cancelled fallback-route addition '" << fallbackRoute
			     << "' to avoid looping (the request comes from there already)";
		}
	}

	if (r->count() == 0 && routingConfig.mFallbackParentDomain) {
		string host = mSipUri.getHost();
		size_t pos = host.find('.');
		size_t end = host.length();
		if (pos == string::npos) {
			LOGE << "Host URL does not have any subdomain: " << host;
			routeRequest(r);
			return;
		} else {
			host = host.substr(pos + 1, end - (pos + 1)); // Gets the host without the first subdomain
		}

		auto urlStr = "sip:" + mSipUri.getUser() + "@" + host;
		SipUri url(urlStr);
		LOGD << "Record[" << r << "] empty, trying to route to parent domain: '" << urlStr << "'";

		auto onRoutingListener = make_shared<ForkFetchRoutingListener>(mForkManager, mForkContext, url,
		                                                               mIsInviteRequest, std::move(mEmptyContactsCb));
		mForkManager->getAgent()->getRegistrarDb().fetch(url, onRoutingListener,
		                                                 routingConfig.mAllowDomainRegistrations, true);
	} else {
		routeRequest(r);
	}
}

void ForkFetchRoutingListener::routeRequest(const shared_ptr<Record>& aor) {
	const shared_ptr<MsgSip>& ms = mForkContext->getEvent().getMsgSip();
	sip_t* sip = ms->getSip();
	ForkGroupSorter::ForkContacts forkContacts{};

	// _Copy_ list of extended contacts
	Record::Contacts contacts{aor->getExtendedContacts()};

	auto now = getCurrentTime();

	// now, create the list of usable contacts to fork to
	bool nonSipsFound = false;
	for (auto it = contacts.begin(); it != contacts.end(); ++it) {
		const shared_ptr<ExtendedContact>& ec = *it;
		sip_contact_t* ct = ec->toSofiaContact(ms->getHome());
		// If it's not a message, verify if it's really expired
		if (sip->sip_request->rq_method != sip_method_message && (ec->getSipExpireTime() <= now)) {
			LOGD << "SIP Contact of " << url_as_string(ms->getHome(), ec->mSipContact->m_url) << " is expired";
			continue;
		}
		if (sip->sip_request->rq_url->url_type == url_sips && ct->m_url->url_type != url_sips) {
			/* https://tools.ietf.org/html/rfc5630 */
			nonSipsFound = true;
			LOGD << "Not dispatching request to non-sips target";
			continue;
		}
		if (ec->mUsedAsRoute && ModuleToolbox::viaContainsUrl(sip->sip_via, ct->m_url)) {
			LOGD << "Skip destination to " << url_as_string(ms->getHome(), ct->m_url)
			     << " because the message is coming from here already";
			continue;
		}
		forkContacts.emplace_back(ct, ec);
	}

	if (forkContacts.empty()) {
		mEmptyContactsCb(std::move(nonSipsFound));
		mForkManager->onForkContextFinished(mForkContext);
		return;
	}

	mForkManager->startForking(mForkContext, forkContacts, mIsInviteRequest);
}

void ForkFetchRoutingListener::onError(const SipStatus& response) {
	ModuleRouter::sendReply(mForkManager->getAgent(), mForkContext->getEvent(), response.getCode(),
	                        response.getReason());
}

void ForkFetchRoutingListener::onInvalid(const SipStatus& response) {
	LOGD << response.getReason();
	ModuleRouter::sendReply(mForkManager->getAgent(), mForkContext->getEvent(), response.getCode(),
	                        response.getReason());
}
} // namespace flexisip
