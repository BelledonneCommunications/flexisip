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

#include "module-router.hh"
#include "log/logmanager.hh"
#include <sofia-sip/sip_status.h>

using namespace std;

void ModuleRouter::onDeclare(GenericStruct *mc) {
	ConfigItemDescriptor configs[] = {
		{Boolean, "use-global-domain", "Store and retrieve contacts without using the domain.", "false"},
		{Boolean, "fork", "Fork messages to all registered devices", "true"},
		{Boolean, "stateful",
			"Force forking and thus the creation of an outgoing transaction even when only one contact found", "true"},
		{Boolean, "fork-late", "Fork invites to late registers", "false"},
		{Boolean, "fork-no-global-decline", "All the forked have to decline in order to decline the caller invite",
			"false"},
		{Boolean, "treat-decline-as-urgent",
			"Treat 603 Declined answers as urgent. Only relevant if fork-no-global-decline is set to true.", "false"},
		{Boolean, "treat-all-as-urgent", "During a fork procedure, treat all failure response as urgent", "false"},
		{Integer, "call-fork-timeout", "Maximum time for a call fork to try to reach a callee, in seconds.", "90"},
		{Integer, "call-fork-urgent-timeout",
			"Maximum time before delivering urgent responses during a call fork, in seconds. "
			"The typical fork process requires to wait the best response from all branches before transmitting it to "
			"the client. "
			"However some error responses are retryable immediately (like 415 unsupported media, 401, 407) thus it is "
			"painful for the client to need to wait the end of the transaction time (32 seconds) for these error "
			"codes.",
			"5"},
		{Integer, "call-fork-current-branches-timeout", "Maximum time before trying the next branches with lower priotiries",
			"10"},
		{Integer, "call-push-response-timeout", "Optional timer to detect lack of push response, in seconds.", "0"},
		{Boolean, "message-fork-late", "Fork messages to client registering lately. ", "true"},
		{Integer, "message-delivery-timeout", "Maximum duration for delivering a text message. This property applies only"
			" if message-fork-late if set to true, otherwise the duration can't exceed the normal transaction duration.", "3600"},
		{Integer, "message-accept-timeout",
			"Maximum duration for accepting a text message if no response is received from any recipients."
			" This property is meaningful when message-fork-late is set to true.", "15"},
		{Boolean, "allow-target-factorization",
			"During a call forking, allow several INVITEs going to the same next hop to be grouped into "
			"a single one. A proprietary custom header 'X-target-uris' is added to the INVITE to indicate the final "
			"targets of the "
			"INVITE.",
			"false"},
		{String, "generated-contact-route",
			"Generate a contact from the TO header and route it to the above destination. [sip:host:port]", ""},
		{String, "generated-contact-expected-realm",
			"Require presence of authorization header for specified realm. [Realm]", ""},
		{Boolean, "generate-contact-even-on-filled-aor", "Generate a contact route even on filled AOR.", "false"},
		{Boolean, "remove-to-tag", "Remove to tag from 183, 180, and 101 responses to workaround buggy gateways",
			"false"},
		{String, "preroute", "Rewrite username with given value.", ""},
		{Boolean, "resolve-routes", "Whether or not to resolve all routes and forward the event to it if it's not us", "false"},
		{String, "fallback-route", "Default route to apply when the recipient is unreachable. [sip:host:port]", ""},
		{Boolean, "parent-domain-fallback", "Whether or not to fallback to the parent domain if there is no fallback route set and the recipient is unreachable", "false"},
		config_item_end};
	mc->addChildrenValues(configs);

	mStats.mCountForks = mc->createStats("count-forks", "Number of forks");
	mStats.mCountForkTransactions =
		mc->createStats("count-fork-transactions", "Number of outgoing transaction created for forking");

	mStats.mCountNonForks = mc->createStat("count-non-forked", "Number of non forked invites.");
	mStats.mCountLocalActives =
		mc->createStat("count-local-registered-users", "Number of users currently registered through this server.");
}

void ModuleRouter::onLoad(const GenericStruct *mc) {
	GenericStruct *cr = GenericManager::get()->getRoot();
	const GenericStruct *mReg = cr->get<GenericStruct>("module::Registrar");

	mDomains = mReg->get<ConfigStringList>("reg-domains")->read();
	mStateful = mc->get<ConfigBoolean>("stateful");
	mFork = mc->get<ConfigBoolean>("fork")->read();
	if (mStateful && !mFork) {
		LOGI("Stateful router implies fork=true");
		mFork = true;
	}
	mGeneratedContactRoute = mc->get<ConfigString>("generated-contact-route")->read();
	mExpectedRealm = mc->get<ConfigString>("generated-contact-expected-realm")->read();
	mGenerateContactEvenOnFilledAor = mc->get<ConfigBoolean>("generate-contact-even-on-filled-aor")->read();

	//Forking configuration for INVITEs
	mForkCfg = make_shared<ForkContextConfig>();
	mForkCfg->mForkLate = mc->get<ConfigBoolean>("fork-late")->read();
	mForkCfg->mTreatAllErrorsAsUrgent = mc->get<ConfigBoolean>("treat-all-as-urgent")->read();
	mForkCfg->mForkNoGlobalDecline = mc->get<ConfigBoolean>("fork-no-global-decline")->read();
	mForkCfg->mUrgentTimeout = mc->get<ConfigInt>("call-fork-urgent-timeout")->read();
	mForkCfg->mPushResponseTimeout = mc->get<ConfigInt>("call-push-response-timeout")->read();
	mForkCfg->mDeliveryTimeout = mc->get<ConfigInt>("call-fork-timeout")->read();
	mForkCfg->mTreatDeclineAsUrgent = mc->get<ConfigBoolean>("treat-decline-as-urgent")->read();
	mForkCfg->mRemoveToTag = mc->get<ConfigBoolean>("remove-to-tag")->read();
	mForkCfg->mCurrentBranchesTimeout = mc->get<ConfigInt>("call-fork-current-branches-timeout")->read();

	//Forking configuration for MESSAGEs
	mMessageForkCfg = make_shared<ForkContextConfig>();
	mMessageForkCfg->mForkLate = mc->get<ConfigBoolean>("message-fork-late")->read();
	mMessageForkCfg->mDeliveryTimeout = mc->get<ConfigInt>("message-delivery-timeout")->read();
	mMessageForkCfg->mUrgentTimeout = mc->get<ConfigInt>("message-accept-timeout")->read();

	//Forking configuration for other kind of requests.
	mOtherForkCfg = make_shared<ForkContextConfig>();
	mOtherForkCfg->mTreatAllErrorsAsUrgent = false;
	mOtherForkCfg->mForkLate = false;
	mOtherForkCfg->mDeliveryTimeout = 30;

	mUseGlobalDomain = mc->get<ConfigBoolean>("use-global-domain")->read();

	mPreroute = mc->get<ConfigString>("preroute")->read();
	mAllowDomainRegistrations = cr->get<GenericStruct>("inter-domain-connections")
									->get<ConfigBoolean>("accept-domain-registrations")
									->read();
	mAllowTargetFactorization = mc->get<ConfigBoolean>("allow-target-factorization")->read();
	mResolveRoutes = mc->get<ConfigBoolean>("resolve-routes")->read();
	mFallbackRoute = mc->get<ConfigString>("fallback-route")->read();
	mFallbackParentDomain = mc->get<ConfigBoolean>("parent-domain-fallback")->read();
}

void ModuleRouter::sendReply(shared_ptr<RequestSipEvent> &ev, int code, const char *reason, int warn_code,
							 const char *warning) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	sip_warning_t *warn = NULL;

	if (sip->sip_request->rq_method == sip_method_invite) {
		shared_ptr<CallLog> calllog = ev->getEventLog<CallLog>();
		if (calllog) {
			calllog->setStatusCode(code, reason);
			calllog->setCompleted();
		}
	} else if (sip->sip_request->rq_method == sip_method_message) {
		shared_ptr<MessageLog> mlog = ev->getEventLog<MessageLog>();
		if (mlog) {
			mlog->setStatusCode(code, reason);
			mlog->setCompleted();
		}
	}
	if (warn_code != 0) {
		warn = sip_warning_format(ev->getHome(), "%i %s \"%s\"", warn_code, mAgent->getPublicIp().c_str(), warning);
	}
	if (warn) {
		ev->reply(code, reason, SIPTAG_SERVER_STR(getAgent()->getServerString()), SIPTAG_WARNING(warn), TAG_END());
	} else {
		ev->reply(code, reason, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	}
}

string ModuleRouter::routingKey(const url_t *sipUri) {
	ostringstream oss;
	if (sipUri->url_user) {
		if (!mPreroute.empty() && strcmp(sipUri->url_user, mPreroute.c_str()) != 0) {
			oss << "merged"
				<< "@"; // all users but preroute are merged
		} else {
			oss << sipUri->url_user << "@";
		}
	}
	if (mUseGlobalDomain) {
		oss << "merged";
	} else {
		oss << sipUri->url_host;
	}
	return oss.str();
}

/**
 * Check if the contact is in one via.
 * Avoid to check a contact information that already known
 */
static bool contactUrlInVia(const url_t *url, sip_via_t *via) {
	while (via != NULL) {
		if (via->v_host && url->url_host && !strcmp(via->v_host, url->url_host)) {
			const char *port1 = (via->v_port) ? via->v_port : "5060";
			const char *port2 = (url->url_port) ? url->url_port : "5060";
			if (!strcmp(port1, port2))
				return true;
		}
		via = via->v_next;
	}

	return false;
}

bool ModuleRouter::rewriteContactUrl(const shared_ptr<MsgSip> &ms, const url_t *ct_url, const char *route) {
	sip_t *sip = ms->getSip();
	su_home_t *home = ms->getHome();

	if (!contactUrlInVia(ct_url, sip->sip_via)) {
		/*sanity check on the contact address: might be '*' or whatever useless information*/
		if (ct_url->url_host != NULL && ct_url->url_host[0] != '\0') {
			LOGD("ModuleRouter: found contact information in database, rewriting request uri");
			/*rewrite request-uri */
			sip->sip_request->rq_url[0] = *url_hdup(home, ct_url);
			if (route && 0 != strcmp(mAgent->getPreferredRoute().c_str(), route)) {
				LOGD("This flexisip instance is not responsible for contact %s:%s:%s -> %s",
					 ct_url->url_user ? ct_url->url_user : "", ct_url->url_host ? ct_url->url_host : "",
					 ct_url->url_params ? ct_url->url_params : "", route);
				cleanAndPrependRoute(mAgent, ms->getMsg(), sip, sip_route_make(home, route));
			}
			// Back to work
			return true;
		} else {
			LOGW("Unrouted request because of incorrect address of record.");
		}
	} else {
		LOGW("Contact is already routed");
	}
	return false;
}

bool ModuleRouter::lateDispatch(const shared_ptr<RequestSipEvent> &ev, const shared_ptr<ExtendedContact> &contact,
							shared_ptr<ForkContext> context, const string &targetUris) {
	return dispatch(ev, contact, context, targetUris);
}

bool ModuleRouter::dispatch(const shared_ptr<RequestSipEvent> &ev, const shared_ptr<ExtendedContact> &contact,
							shared_ptr<ForkContext> context, const string &targetUris) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	time_t now = getCurrentTime();
	sip_contact_t *ct = contact->toSofiaContact(ms->getHome(), now);
	url_t *dest = ct->m_url;


	/*sanity check on the contact address: might be '*' or whatever useless information*/
	if (dest->url_host == NULL || dest->url_host[0] == '\0') {
		LOGW("Unrouted request because of incorrect address of contact");
		return false;
	}

	char *contact_url_string = url_as_string(ms->getHome(), dest);
	shared_ptr<RequestSipEvent> new_ev;
	if (context) {
		// duplicate the SIP event
		new_ev = make_shared<RequestSipEvent>(ev);
	} else {
		new_ev = ev;
	}
	auto new_msgsip = new_ev->getMsgSip();
	msg_t *new_msg = new_msgsip->getMsg();
	sip_t *new_sip = new_msgsip->getSip();

	// Convert path to routes
	sip_route_t *routes = contact->toSofiaRoute(new_ev->getHome());
	if (!contact->mUsedAsRoute) {
		if (targetUris.empty()) {
			/* Rewrite request-uri */
			new_sip->sip_request->rq_url[0] = *url_hdup(msg_home(new_msg), dest);
		} // else leave the request uri as it is, the X-target-uris header will give the resolved destinations.
		  // the cleaning of push notif params will be done just before forward
	} else {
		// leave the request uri as it is, but append a route for the final destination
		sip_route_t *final_route = sip_route_create(new_msgsip->getHome(), dest, NULL);
		if (!url_has_param(final_route->r_url, "lr")) {
			url_param_add(new_msgsip->getHome(), final_route->r_url, "lr");
		}

		if (routes == NULL)
			routes = final_route;
		else {
			sip_route_t *r = routes;
			while (r->r_next != NULL) {
				r = r->r_next;
			}
			r->r_next = final_route;
		}
	}
	if (!targetUris.empty()) {
		sip_header_insert(new_msg, new_sip, (sip_header_t *)sip_unknown_format(msg_home(new_msg), "X-Target-Uris: %s",
																			   targetUris.c_str()));
	}
	new_sip->sip_route = NULL;
	cleanAndPrependRoute(getAgent(), new_msg, new_sip, routes);

	if (context) {
		context->addBranch(new_ev, contact);
		SLOGD << "Fork to " << contact_url_string;
	} else {
		LOGD("Dispatch to %s", contact_url_string);
	}

	return true;
}

class OnContactRegisteredListener : public ContactRegisteredListener, public ContactUpdateListener, public enable_shared_from_this<OnContactRegisteredListener> {
	friend class ModuleRouter;
	ModuleRouter *mModule;
	url_t *mSipUri;
	string mUid;
	su_home_t mHome;

  public:
	OnContactRegisteredListener(ModuleRouter *module, const url_t *sipUri)
	: mModule(module), mUid("") {
		su_home_init(&mHome);
		mSipUri = url_hdup(&mHome, sipUri);
		if (url_has_param(mSipUri, "gr")) {
			LOGD("Trying to create a ContactRegistered listener using a SIP URI with a gruu, removing let's remove it");
			mSipUri->url_params = url_strip_param_string((char*)mSipUri->url_params, "gr");
		}
		LOGD("Listener created for sipUri = %s", url_as_string(&mHome, mSipUri));
	}

	~OnContactRegisteredListener() {
		su_home_deinit(&mHome);
	}

	void onContactRegistered(Record *r, const string &uid) {
		LOGD("Listener found for topic = %s, uid = %s, sipUri = %s", r->getKey().c_str(), uid.c_str(), url_as_string(&mHome, mSipUri));
		mUid = uid;
		onRecordFound(r);
	}

	void onRecordFound(Record *r) {
		if (r) {
			LOGD("Record found for uid = %s", mUid.c_str());
			mModule->onContactRegistered(mUid, r, mSipUri);
		} else {
			LOGW("No record found for uid = %s", mUid.c_str());
		}
	}
	void onError() {
	}
	void onInvalid() {
	}

	void onContactUpdated(const shared_ptr<ExtendedContact> &ec) {
	}
};

void ModuleRouter::onContactRegistered(const string &uid, Record *aor, const url_t *sipUri) {
	SofiaAutoHome home;
	sip_path_t *path = NULL;
	sip_contact_t *contact = NULL;

	if (aor == NULL) {
		SLOGE << "aor was null...";
		return;
	}

	if (!mForkCfg->mForkLate && !mMessageForkCfg->mForkLate)
		return;
	if (!sipUri)
		return; // nothing to do

	char sipUriRef[256] = {0};
	url_t urlcopy = *sipUri;

	if (mUseGlobalDomain) {
		urlcopy.url_host = "merged";
	}
	url_e(sipUriRef, sizeof(sipUriRef) - 1, &urlcopy);

	// Find all contexts
	const string key(routingKey(sipUri));
	auto range = mForks.equal_range(key.c_str());
	SLOGD << "Searching for fork context with key " << key;

	const shared_ptr<ExtendedContact> ec = aor->extractContactByUniqueId(uid);
	if (ec) {
		contact = ec->toSofiaContact(home.home(), ec->mExpireAt - 1);
		path = ec->toSofiaRoute(home.home());

		// First use sipURI
		for (auto it = range.first; it != range.second; ++it) {
			shared_ptr<ForkContext> context = it->second;
			if (context->onNewRegister(contact->m_url, uid)) {
				SLOGD << "Found a pending context for key " << key << ": " << context.get();
				lateDispatch(context->getEvent(), ec, context, "");
			} else
				LOGD("Found a pending context but not interested in this new register.");
		}
	}

	// If not found find in aliases
	const auto contacts = aor->getExtendedContacts();
	for (auto it = contacts.begin(); it != contacts.end(); ++it) {
		const shared_ptr<ExtendedContact> ec = *it;
		if (!ec || !ec->mAlias)
			continue;

		// Find all contexts
		contact = ec->toSofiaContact(home.home(), ec->mExpireAt - 1);
		path = ec->toSofiaRoute(home.home());
		auto rang = mForks.equal_range(ExtendedContact::urlToString(ec->mSipContact->m_url));
		for (auto ite = rang.first; ite != rang.second; ++ite) {
			shared_ptr<ForkContext> context = ite->second;
			if (context->onNewRegister(contact->m_url, uid)) {
				LOGD("Found a pending context for contact %s: %p", ExtendedContact::urlToString(ec->mSipContact->m_url).c_str(), context.get());
				auto stlpath = Record::route_to_stl(path);
				lateDispatch(context->getEvent(), ec, context, "");
			}
		}
	}
}

bool ModuleRouter::makeGeneratedContactRoute(shared_ptr<RequestSipEvent> &ev, Record *aor,
											 list<shared_ptr<ExtendedContact>> &ec_list) {
	if (!mGeneratedContactRoute.empty() && (!aor || mGenerateContactEvenOnFilledAor)) {
		const shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_t *sip = ms->getSip();
		const url_t *to = ms->getSip()->sip_to->a_url;
		shared_ptr<ExtendedContact> gwECt = make_shared<ExtendedContact>(to, mGeneratedContactRoute.c_str());

		// This contact is a proxy which will challenge us with a known Realm
		const char *nextProxyRealm = mExpectedRealm.empty() ? to->url_host : mExpectedRealm.c_str();
		if (ms->getSip()->sip_request->rq_method == sip_method_invite &&
			!ModuleToolbox::findAuthorizationForRealm(ms->getHome(), sip->sip_proxy_authorization, nextProxyRealm)) {
			LOGD("No authorization header %s found in request, forwarding request only to proxy", nextProxyRealm);
			if (rewriteContactUrl(ms, to, mGeneratedContactRoute.c_str())) {
				shared_ptr<OutgoingTransaction> transaction = ev->createOutgoingTransaction();
				shared_ptr<string> thisProxyRealm(make_shared<string>(to->url_host));
				transaction->setProperty("this_proxy_realm", thisProxyRealm);
				shared_ptr<RequestSipEvent> new_ev = make_shared<RequestSipEvent>(ev);
				getAgent()->injectRequestEvent(new_ev);
				return true;
			}
		} else {
			LOGD("Authorization header %s found", nextProxyRealm);
		}
		LOGD("Added generated contact to %s@%s through %s", to->url_user, to->url_host, mGeneratedContactRoute.c_str());
		ec_list.push_back(gwECt);
	}
	return false;
}

struct ForkDestination {
	ForkDestination() : mSipContact(NULL) {
	}
	ForkDestination(sip_contact_t *ct, const shared_ptr<ExtendedContact> &exContact, const string &targetUris)
		: mSipContact(ct), mExtendedContact(exContact), mTargetUris(targetUris) {
	}
	sip_contact_t *mSipContact;
	shared_ptr<ExtendedContact> mExtendedContact;
	string mTargetUris;
};

class ForkGroupSorter {
  public:
	ForkGroupSorter(const list<pair<sip_contact_t *, shared_ptr<ExtendedContact>>> &usable_contacts)
		: mAllContacts(usable_contacts) {
	}
	void makeGroups() {
		SofiaAutoHome home;
		/*first step, eliminate adjacent contacts, they cannot be factorized*/
		for (auto it = mAllContacts.begin(); it != mAllContacts.end();) {
			if ((*it).second->mPath.size() < 2) {
				/*this is a "direct" destination, nothing to do*/
				mDestinations.emplace_back(ForkDestination((*it).first, (*it).second, ""));
				it = mAllContacts.erase(it);
			} else
				++it;
		}
		/*second step, form groups with non-adjacent contacts*/
		for (auto it = mAllContacts.begin(); it != mAllContacts.end();) {
			list<pair<sip_contact_t *, shared_ptr<ExtendedContact>>>::iterator sameDestinationIt;
			ForkDestination dest;
			ostringstream targetUris;
			bool foundGroup = false;

			dest.mSipContact = (*it).first;
			dest.mExtendedContact = (*it).second;
			targetUris << "<" << *dest.mExtendedContact->toSofiaUrlClean(home.home()) << ">";
			url_t *url = url_make(home.home(), (*it).second->mPath.back().c_str());
			// remove it and now search for other contacts that have the same route.
			it = mAllContacts.erase(it);
			while ((sameDestinationIt = findDestination(url)) != mAllContacts.end()) {
				targetUris << ", <" << *(*sameDestinationIt).second->toSofiaUrlClean(home.home()) << ">";
				mAllContacts.erase(sameDestinationIt);
				foundGroup = true;
			}
			if (foundGroup) {
				// a group was formed
				LOGD("A group with targetUris %s was formed", targetUris.str().c_str());
				dest.mTargetUris = targetUris.str();
				it = mAllContacts.begin();
			}
			mDestinations.emplace_back(dest);
		}
	}
	void makeDestinations() {
		for (auto it = mAllContacts.begin(); it != mAllContacts.end(); ++it) {
			mDestinations.emplace_back(ForkDestination((*it).first, (*it).second, ""));
		}
	}
	const list<ForkDestination> &getDestinations() const {
		return mDestinations;
	}

  private:
	list<pair<sip_contact_t *, shared_ptr<ExtendedContact>>>::iterator findDestination(const url_t *url) {
		SofiaAutoHome home;
		// LOGD("findDestination(): looking for %s", url_as_string(home.home(), url));
		for (auto it = mAllContacts.begin(); it != mAllContacts.end(); ++it) {
			url_t *it_route = url_make(home.home(), (*it).second->mPath.back().c_str());
			// LOGD("findDestination(): seeing %s", url_as_string(home.home(), it_route));
			if (url_cmp(it_route, url) == 0) {
				return it;
			}
		}
		return mAllContacts.end();
	}
	list<ForkDestination> mDestinations;
	list<pair<sip_contact_t *, shared_ptr<ExtendedContact>>> mAllContacts;
};

void ModuleRouter::routeRequest(shared_ptr<RequestSipEvent> &ev, Record *aor, const url_t *sipUri) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	list<shared_ptr<ExtendedContact>> contacts;
	list<pair<sip_contact_t *, shared_ptr<ExtendedContact>>> usable_contacts;
	bool isInvite = false;

	if (!aor && mGeneratedContactRoute.empty()) {
		LOGD("This user isn't registered (no aor).");
		SLOGUE << "User " << url_as_string(ms->getHome(), sipUri) << " isn't registered (no aor)";
		sendReply(ev, SIP_404_NOT_FOUND);
		return;
	}

	// _Copy_ list of extended contacts
	if (aor)
		contacts = aor->getExtendedContacts();

	time_t now = getCurrentTime();

	// Eventually generate a fake contact for a proxy and handle it directly.
	if (makeGeneratedContactRoute(ev, aor, contacts))
		return;

	// now, create the list of usable contacts to fork to
	bool nonSipsFound = false;
	for (auto it = contacts.begin(); it != contacts.end(); ++it) {
		const shared_ptr<ExtendedContact> &ec = *it;
		sip_contact_t *ct = ec->toSofiaContact(ms->getHome(), now);
		if (!ct) {
			SLOGE << "Can't create sip_contact of " << ec->mSipContact->m_url;
			continue;
		}
		// If it's not a message, verify if it's really expired
		if (sip->sip_request->rq_method != sip_method_message && (ec->getExpireNotAtMessage() < now)) {
			LOGD("Sip_contact of %s is expired", url_as_string(ms->getHome(),ec->mSipContact->m_url));
			continue;
		}
		if (sip->sip_request->rq_url->url_type == url_sips && ct->m_url->url_type != url_sips) {
			/* https://tools.ietf.org/html/rfc5630 */
			nonSipsFound = true;
			LOGD("Not dispatching request to non-sips target.");
			continue;
		}
		if (ec->mUsedAsRoute && ModuleToolbox::viaContainsUrl(sip->sip_via, ct->m_url)) {
			LOGD("Skip destination to %s, because the message is coming from here already.",
				 url_as_string(ms->getHome(), ct->m_url));
			continue;
		}
		usable_contacts.push_back(make_pair(ct, ec));
	}

	if (usable_contacts.size() == 0) {
		if (nonSipsFound) {
			/*rfc5630 5.3*/
			SLOGUE << "Not dispatching request because SIPS not allowed for " << url_as_string(ms->getHome(), sipUri);
			sendReply(ev, SIP_480_TEMPORARILY_UNAVAILABLE, 380, "SIPS not allowed");
		} else {
			LOGD("This user isn't registered (no valid contact).");
			SLOGUE << "User " << url_as_string(ms->getHome(), sipUri) << " isn't registered (no valid contact)";
			sendReply(ev, SIP_404_NOT_FOUND);
		}
		return;
	}
	/*now we can create a fork context and dispatch the message to all branches*/

	if (!mFork) {
		mStats.mCountNonForks->incr();
	} else {
		mStats.mCountForks->incrStart();
	}

	// Init context if needed
	shared_ptr<ForkContext> context;
	if (mFork) {
		if (sip->sip_request->rq_method == sip_method_invite) {
			context = make_shared<ForkCallContext>(getAgent(), ev, mForkCfg, this);
			isInvite = true;
		} else if (
			(sip->sip_request->rq_method == sip_method_message) &&
			!(sip->sip_content_type && strcasecmp(sip->sip_content_type->c_type, "application/im-iscomposing+xml") == 0) &&
			!(sip->sip_expires && sip->sip_expires->ex_delta == 0)
		) {
			// Use the basic fork context for "im-iscomposing+xml" messages to prevent storing useless messages
			context = make_shared<ForkMessageContext>(getAgent(), ev, mMessageForkCfg, this);
		} else if (sip->sip_request->rq_method == sip_method_refer &&
				   (sip->sip_refer_to != NULL && msg_params_find(sip->sip_refer_to->r_params, "text") != NULL)) {
			// Use the message fork context only for refers that are text to prevent storing useless refers
			context = make_shared<ForkMessageContext>(getAgent(), ev, mMessageForkCfg, this);
		} else {
			context = make_shared<ForkBasicContext>(getAgent(), ev, mOtherForkCfg, this);
		}
		if (context) {
			if (context->getConfig()->mForkLate) {
				const string key(routingKey(sipUri));
				context->addKey(key);
				mForks.insert(make_pair(key, context));
				if (mForks.count(key) == 1) {
					auto listener = make_shared<OnContactRegisteredListener>(this, sipUri);
					context->setContactRegisteredListener(listener);
					RegistrarDb::get()->subscribe(key, listener);
				}
				SLOGD << "Add fork " << context.get() << " to store with key '" << key << "'";
			}
		}
	}
	// now sort usable_contacts to form groups, if grouping is allowed
	ForkGroupSorter sorter(usable_contacts);
	if (isInvite && mAllowTargetFactorization) {
		sorter.makeGroups();
	} else {
		sorter.makeDestinations();
	}
	const list<ForkDestination> &destinations = sorter.getDestinations();

	for (auto it = destinations.begin(); it != destinations.end(); ++it) {
		sip_contact_t *ct = (*it).mSipContact;
		const shared_ptr<ExtendedContact> &ec = (*it).mExtendedContact;
		const string &targetUris = (*it).mTargetUris;

		if (!ec->mAlias) {
			if (dispatch(ev, ec, context, targetUris)) {
				if (!mFork)
					break;
			}
		} else {
			if (mFork && context->getConfig()->mForkLate && isManagedDomain(ct->m_url)) {
				sip_contact_t *temp_ctt = sip_contact_create(ms->getHome(), (url_string_t*)ec->mSipContact->m_url, NULL);

				if (mUseGlobalDomain) {
					temp_ctt->m_url->url_host = "merged";
					temp_ctt->m_url->url_port = NULL;
				}
				const string key(routingKey(temp_ctt->m_url));
				context->addKey(key);
				mForks.insert(make_pair(key, context));
				if (mForks.count(key) == 1) {
					auto listener = make_shared<OnContactRegisteredListener>(this, temp_ctt->m_url);
					context->setContactRegisteredListener(listener);
					RegistrarDb::get()->subscribe(key, listener);
				}
				LOGD("Add fork %p to store with key '%s' because it is an alias", context.get(), key.c_str());
			} else {
				if (dispatch(ev, ec, context, targetUris)) {
					if (!mFork)
						break;
				}
			}
		}
	}

	context->start();
}

class PreroutingFetcher : public ContactUpdateListener,
						  public enable_shared_from_this<PreroutingFetcher>,
						  private ModuleToolbox {
	friend class ModuleRouter;
	shared_ptr<RequestSipEvent> mEv;
	shared_ptr<ContactUpdateListener> mListener;
	vector<string> mPreroutes;
	int pending;
	bool error;
	Record *m_record;

  public:
	PreroutingFetcher(ModuleRouter *module, shared_ptr<RequestSipEvent> ev,
					  const shared_ptr<ContactUpdateListener> &listener, const vector<string> &preroutes)
		: mEv(ev), mListener(listener), mPreroutes(preroutes) {
		pending = 0;
		error = false;
		m_record = new Record(NULL);
	}

	~PreroutingFetcher() {
		delete (m_record);
	}

	void fetch() {
		const char *domain = mEv->getSip()->sip_to->a_url->url_host;
		if (isNumeric(domain))
			SLOGE << "Not handled: to is ip at " << __LINE__;

		pending += mPreroutes.size();
		for (auto it = mPreroutes.cbegin(); it != mPreroutes.cend(); ++it) {
			url_t *target = url_format(mEv->getHome(), "sip:%s@%s", it->c_str(), domain);
			RegistrarDb::get()->fetch(target, this->shared_from_this(), true);
		}
	}

	void onRecordFound(Record *r) {
		--pending;
		if (r != NULL) {
			const auto &ctlist = r->getExtendedContacts();
			for (auto it = ctlist.begin(); it != ctlist.end(); ++it)
				m_record->pushContact(*it);
		}
		checkFinished();
	}
	void onError() {
		--pending;
		error = true;
		checkFinished();
	}

	void onInvalid() {
		--pending;
		error = true;
		checkFinished();
	}

	void onContactUpdated(const shared_ptr<ExtendedContact> &ec) {
	}

	void checkFinished() {
		if (pending != 0)
			return;
		if (error)
			mListener->onError();
		else
			mListener->onRecordFound(m_record);
	}
};

class TargetUriListFetcher : public ContactUpdateListener,
							 public enable_shared_from_this<TargetUriListFetcher>,
							 private ModuleToolbox {
	friend class ModuleRouter;
	shared_ptr<RequestSipEvent> mEv;
	shared_ptr<ContactUpdateListener> mListener;
	sip_route_t *mUriList; /*it is parsed as a route but is not a route*/
	int mPending;
	Record *mRecord;
	bool mError;

  public:
	TargetUriListFetcher(ModuleRouter *module, const shared_ptr<RequestSipEvent> &ev,
						 const shared_ptr<ContactUpdateListener> &listener, sip_unknown_t *target_uris)
		: mEv(ev), mListener(listener) {
		mPending = 0;
		mError = false;
		mRecord = new Record(NULL);
		if (target_uris && target_uris->un_value) {
			/*the X-target-uris header is parsed like a route, as it is a list of URIs*/
			mUriList = sip_route_make(mEv->getHome(), target_uris->un_value);
		}
	}

	~TargetUriListFetcher() {
		delete mRecord;
	}

	void fetch(bool allowDomainRegistrations, bool recursive) {
		sip_route_t *iter;
		/*compute the number of asynchronous queries we are going to make, to later know when we are done.*/
		for (iter = mUriList; iter != NULL; iter = iter->r_next) {
			mPending++;
		}
		/*start the queries for all uris of the target uri list*/
		for (iter = mUriList; iter != NULL; iter = iter->r_next) {
			RegistrarDb::get()
				->fetch(iter->r_url, this->shared_from_this(), allowDomainRegistrations, recursive);
		}
	}

	void onRecordFound(Record *r) {
		--mPending;
		if (r != NULL) {
			const auto &ctlist = r->getExtendedContacts();
			for (auto it = ctlist.begin(); it != ctlist.end(); ++it)
				mRecord->pushContact(*it);
		}
		checkFinished();
	}
	void onError() {
		--mPending;
		mError = true;
		checkFinished();
	}

	void onInvalid() {
		--mPending;
		mError = true;
		checkFinished();
	}

	void onContactUpdated(const shared_ptr<ExtendedContact> &ec) {
	}

	void checkFinished() {
		if (mPending != 0)
			return;
		if (mError){
			mListener->onError();
		}else{
			if (mRecord->count() > 0){
				/*also add aliases in the ExtendedContact list for the searched AORs, so that they are added to the ForkMap.*/
				sip_route_t *iter;
				for (iter = mUriList; iter != NULL; iter = iter->r_next) {

					shared_ptr<ExtendedContact> alias = make_shared<ExtendedContact>(iter->r_url, "");
					alias->mAlias = true;
					mRecord->pushContact(alias);
				}
			}
			mListener->onRecordFound(mRecord);
		}
	}
};

class OnFetchForRoutingListener : public ContactUpdateListener {
	friend class ModuleRouter;
	ModuleRouter *mModule;
	shared_ptr<RequestSipEvent> mEv;
	url_t *mSipUri;

  public:
	OnFetchForRoutingListener(ModuleRouter *module, shared_ptr<RequestSipEvent> ev, const url_t *sipuri)
		: mModule(module), mEv(ev) {
		if (!ev->isSuspended()) ev->suspendProcessing();
		mSipUri = url_hdup(mEv->getMsgSip()->getHome(), sipuri);
		const sip_t *sip = ev->getMsgSip()->getSip();
		if (sip->sip_request->rq_method == sip_method_invite) {
			ev->setEventLog(make_shared<CallLog>(sip));
		}
	}
	void onRecordFound(Record *r) {
		const string &fallbackRoute = mModule->getFallbackRoute();

		bool ownRecord = r == NULL;
		if (ownRecord)
			r = new Record(mSipUri);

		if (!mModule->isManagedDomain(mSipUri)) {
			shared_ptr<ExtendedContact> contact = make_shared<ExtendedContact>(mSipUri, "");
			r->pushContact(contact);

			SLOGD << "Record [" << r << "] Original request URI added because domain is not managed: " << *contact;
		}

		if (!fallbackRoute.empty()) {
			shared_ptr<ExtendedContact> fallback = make_shared<ExtendedContact>(mSipUri, fallbackRoute, 0.0);
			r->pushContact(fallback);

			SLOGD << "Record [" << r << "] Fallback route '" << fallbackRoute << "' added: " << *fallback;
		}

		if (r->count() == 0 && mModule->isFallbackToParentDomainEnabled()) {
			string host = mSipUri->url_host;
			size_t pos = host.find('.');
			size_t end = host.length();
			if (pos == string::npos) {
				SLOGE << "Host URL doesn't have any subdomain: " << host;
				mModule->routeRequest(mEv, r, mSipUri);
				return;
			} else {
				host = host.substr(pos + 1, end - (pos + 1)); // Gets the host without the first subdomain
			}

			url_t *url = url_format(mEv->getHome(), "sip:%s@%s", mSipUri->url_user, host.c_str());
			SLOGD << "Record [" << r << "] empty, trying to route to parent domain: '" << url_as_string(mEv->getHome(), url);

			auto onRoutingListener = make_shared<OnFetchForRoutingListener>(mModule, mEv, mSipUri);
			RegistrarDb::get()->fetch(url, onRoutingListener, mModule->isDomainRegistrationAllowed(), true);
		} else {
			mModule->routeRequest(mEv, r, mSipUri);
		}

		if (ownRecord)
			delete r;
	}
	void onError() {
		mModule->sendReply(mEv, SIP_500_INTERNAL_SERVER_ERROR);
	}

	void onInvalid() {
		LOGD("OnFetchForRoutingListener::onInvalid : 400 - Replayed CSeq");
		mModule->sendReply(mEv, 400, "Replayed CSeq");
	}

	void onContactUpdated(const shared_ptr<ExtendedContact> &ec) {
	}
};

static vector<string> split(const char *data, const char *delim) {
	const char *p;
	vector<string> res;
	char *s = strdup(data);
	char *saveptr = NULL;
	for (p = strtok_r(s, delim, &saveptr); p; p = strtok_r(NULL, delim, &saveptr)) {
		res.push_back(p);
	}
	free(s);
	return res;
}

void ModuleRouter::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	// Handle SipEvent associated with a Stateful transaction
	if (sip->sip_request->rq_method == sip_method_cancel) {
		ForkContext::processCancel(ev);
		return;
	}

	// Don't route registers
	if (sip->sip_request->rq_method == sip_method_register)
		return;

	if (mResolveRoutes) {
		sip_route_t *iterator = sip->sip_route;
		while (iterator != NULL) {
			sip_route_t *route = iterator;
			if (getAgent()->isUs(route->r_url)) {
				SLOGD << "Route header found " << url_as_string(ms->getHome(), route->r_url) << " and is us, continuing";
			} else {
				SLOGD << "Route header found " << url_as_string(ms->getHome(), route->r_url) << " but not us, forwarding";
				url_t *sipurl = sip->sip_request->rq_url;
				auto onRoutingListener = make_shared<OnFetchForRoutingListener>(this, ev, sipurl);
				RegistrarDb::get()->fetch(sipurl, onRoutingListener, mAllowDomainRegistrations, true);
				return;
			}
			iterator = iterator->r_next;
		}
	} else if (sip->sip_route != NULL && !getAgent()->isUs(sip->sip_route->r_url)) {
		SLOGD << "Route header found " << url_as_string(ms->getHome(), sip->sip_route->r_url)
			  << " but not us, skipping";
		return;
	}

	/*see if we can route other requests */
	/*
	 * 	ACKs shall not have their request uri rewritten:
		- they can be for us (in response to a 407 for invite)
		- they can be for the a remote peer, in which case they will have the correct contact address in the request uri
	*/
	/* When we accept * as domain we need to test ip4/ipv6 */
	if (sip->sip_request->rq_method != sip_method_ack && sip->sip_to != NULL && sip->sip_to->a_tag == NULL) {
		url_t *sipurl = sip->sip_request->rq_url;
		if (sipurl->url_host && isManagedDomain(sipurl)) {
			LOGD("Fetch for url %s.", url_as_string(ms->getHome(), sipurl));
			// Go stateful to stop retransmissions
			ev->createIncomingTransaction();
			sendReply(ev, SIP_100_TRYING);
			auto onRoutingListener = make_shared<OnFetchForRoutingListener>(this, ev, sipurl);

			if (mPreroute.empty()) {
				/*the unstandard X-Target-Uris header gives us a list of SIP uri to which the request is to be forked.*/
				sip_unknown_t *h = ModuleToolbox::getCustomHeaderByName(ev->getSip(), "X-Target-Uris");
				if (!h) {
					RegistrarDb::get()->fetch(sipurl, onRoutingListener, mAllowDomainRegistrations, true);
				} else {
					auto fetcher = make_shared<TargetUriListFetcher>(this, ev, onRoutingListener, h);
					sip_header_remove(ms->getMsg(), sip, (sip_header_t *)h);
					fetcher->fetch(mAllowDomainRegistrations, true);
				}
			} else {
				/*The preroute request uri param does more or less the same thing as the above X-Target-Uris header,
				* but was designed in more ancient times. The domain name is deduced from the request-uri.
				* It is kept for backward compatibility but the X-Target-Uris method is prefered*/
				char preroute_param[20];
				if (url_param(sipurl->url_params, "preroute", preroute_param, sizeof(preroute_param))) {
					if (strchr(preroute_param, '@')) {
						SLOGE << "Prerouting contains at symbol" << preroute_param;
						return;
					}
					SLOGD << "Prerouting to provided " << preroute_param;
					vector<string> tokens = split(preroute_param, ":");
					auto prFetcher = make_shared<PreroutingFetcher>(this, ev, onRoutingListener, tokens);
					prFetcher->fetch();
				} else {
					SLOGD << "Prerouting to " << mPreroute;
					url_t *prerouteUrl = url_format(ev->getHome(), "sip:%s@%s", mPreroute.c_str(), sipurl->url_host);
					RegistrarDb::get()->fetch(prerouteUrl, onRoutingListener, true);
				}
			}
		}
	}
}

void ModuleRouter::onResponse(shared_ptr<ResponseSipEvent> &ev) {
	ForkContext::processResponse(ev);
}

void ModuleRouter::onForkContextFinished(shared_ptr<ForkContext> ctx) {
	if (!ctx->getConfig()->mForkLate) return;

	list<string> keys = ctx->getKeys();
	for (list<string>::iterator it=keys.begin(); it != keys.end(); ++it) {
		string key = *it;
		LOGD("Looking at fork contexts with key %s", key.c_str());

		int count = 0;
		int removed = 0;
		auto range = mForks.equal_range(key.c_str());
		for (auto it = range.first; it != range.second;) {
			count++;
			if (it->second == ctx) {
				LOGD("Remove fork %s from store", it->first.c_str());
				mStats.mCountForks->incrFinish();
				auto cur_it = it;
				++it;
				// for some reason the multimap erase does not return the next iterator !
				mForks.erase(cur_it);
				removed++;
				// do not break, because a single fork context might appear several time in the map because of aliases.
			} else {
				++it;
			}
		}
		if (count == removed && count > 0) {
			RegistrarDb::get()->unsubscribe(key, ctx->getContactRegisteredListener());
		}
	}
}

ModuleInfo<ModuleRouter> ModuleRouter::sInfo(
	"Router",
	"The ModuleRouter module routes requests for domains it manages.",
	{ "ContactRouteInserter" },
	ModuleInfoBase::ModuleOid::Router
);
