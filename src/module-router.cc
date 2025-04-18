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

#include "flexisip/module-router.hh"

#include <memory>

#include "conference/chatroom-prefix.hh"
#include "domain-registrations.hh"
#include "eventlogs/events/calls/call-ended-event-log.hh"
#include "exceptions/bad-configuration.hh"
#include "flexisip/logmanager.hh"
#include "fork-context/fork-basic-context.hh"
#include "fork-context/fork-call-context.hh"
#include "fork-context/fork-message-context.hh"
#include "module-toolbox.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "router/agent-injector.hh"
#include "router/inject-context.hh"
#include "router/schedule-injector.hh"
#include "sofia-sip/sip.h"
#include "sofia-sip/sip_status.h"
#include "utils/uri-utils.hh"

#if ENABLE_SOCI
#include "fork-context/fork-message-context-db-proxy.hh"
#include "fork-context/fork-message-context-soci-repository.hh"
#endif

using namespace std;
using namespace chrono;
using namespace flexisip;
using namespace sofiasip;

ModuleRouter::ModuleRouter(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
	LOGD << "New instance [" << this << "]";
	mStats.mCountForks = mModuleConfig->getStatPairPtr("count-forks");
	mStats.mCountBasicForks = mModuleConfig->getStatPairPtr("count-basic-forks");
	mStats.mCountCallForks = mModuleConfig->getStatPairPtr("count-call-forks");
	mStats.mCountMessageForks = mModuleConfig->getStatPairPtr("count-message-forks");
	mStats.mCountMessageProxyForks = mModuleConfig->getStatPairPtr("count-message-proxy-forks");
	mStats.mCountMessageConferenceForks = mModuleConfig->getStatPairPtr("count-message-conference-forks");
}

ModuleRouter::~ModuleRouter() {
	LOGD << "Destroy instance [" << this << "]";
};

void ModuleRouter::declareConfig(GenericStruct& moduleConfig) {
	ConfigItemDescriptor configs[] = {
	    {
	        Boolean,
	        "use-global-domain",
	        "Store and retrieve contacts without using the domain.",
	        "false",
	    },
	    {
	        Boolean,
	        "fork-late",
	        "Fork INVITE requests to clients that register late.",
	        "false",
	    },
	    {
	        Boolean,
	        "fork-no-global-decline",
	        "All the devices of the target (i.e. all fork branches) have to decline in order to decline the caller "
	        "invite.",
	        "false",
	    },
	    {
	        Boolean,
	        "treat-decline-as-urgent",
	        "Treat '603 Declined' answers as urgent. Only relevant if 'fork-no-global-decline' is set to true.",
	        "false",
	    },
	    {
	        Boolean,
	        "treat-all-as-urgent",
	        "During a fork procedure, treat all failure response as urgent.",
	        "false",
	    },
	    {
	        DurationS,
	        "call-fork-timeout",
	        "Maximum time for a call fork to try to reach a callee.",
	        "90",
	    },
	    {
	        DurationS,
	        "call-fork-urgent-timeout",
	        "Maximum time before delivering urgent responses during a call fork.\n"
	        "The typical fork process requires to wait the best response from all branches before transmitting it to "
	        "the client. However some error responses are retryable immediately (like '415 unsupported media', 401, "
	        "407) thus it is painful for the client to need to wait the end of the transaction time (32 seconds) for "
	        "these error codes.",
	        "5",
	    },
	    {
	        DurationS,
	        "call-fork-current-branches-timeout",
	        "Maximum time before trying the next set of lower priority contacts.",
	        "10",
	    },
	    {
	        DurationS,
	        "call-push-response-timeout",
	        "Optional timer to detect lack of push response.",
	        "0",
	    },
	    {
	        Boolean,
	        "message-fork-late",
	        "Fork MESSAGE requests to clients that register late.",
	        "true",
	    },
	    {
	        DurationS,
	        "message-delivery-timeout",
	        "Maximum duration for delivering a MESSAGE request.\n"
	        "This property applies only if 'message-fork-late' is 'true'; otherwise, the duration cannot exceed the "
	        "normal transaction duration.",
	        "604800",
	    },
	    {
	        DurationS,
	        "message-accept-timeout",
	        "Maximum duration for accepting a MESSAGE request if no response is received from any recipients.\n"
	        "This property is meaningful when 'message-fork-late' is set to 'true'.",
	        "5",
	    },
	    {
	        Boolean,
	        "message-database-enabled",
	        "Store MESSAGE requests that are waiting for delivery in the database instead of memory.\n",
	        "false",
	    },
	    {
	        String,
	        "message-database-backend",
	        "Type of backend that Soci will use for the connection.\n"
	        "Depending on your Soci package and the modules you installed, the supported databases are: `mysql` (and "
	        "`sqlite3` soon)",
	        "mysql",
	    },
	    {
	        String,
	        "message-database-connection-string",
	        "Configuration parameters of the backend.\n"
	        "The basic format is \"key=value key2=value2\". For a mysql backend, this is a valid config: \"db=mydb "
	        "user=user password='pass' host=myhost.com\". Please refer to the Soci documentation of your backend "
	        "(http://soci.sourceforge.net/doc/master/backends/#supported-backends-and-features)",
	        "db='mydb' user='myuser' password='mypass' host='myhost.com'",
	    },
	    {
	        Integer,
	        "message-database-pool-size",
	        "Size of the connections pool that Soci will use for accessing the database.",
	        "100",
	    },
	    {
	        String,
	        "fallback-route",
	        "Default route to apply when the recipient is unreachable or when all attempted destination have "
	        "failed. It is given as a SIP URI, for example: sip:example.org;transport=tcp (without surrounding "
	        "brackets)",
	        "",
	    },
	    {
	        Boolean,
	        "allow-target-factorization",
	        "During a call fork process, allow several INVITE requests routed to the same next hop to be grouped into "
	        "a single one.\n"
	        "A proprietary custom header 'X-target-uris' is added to the INVITE request to indicate the final targets "
	        "of the request.",
	        "false",
	    },
	    {
	        Boolean,
	        "permit-self-generated-provisional-response",
	        "Whether the proxy is allowed to generate and send provisional responses during a call fork process.\n"
	        "A typical example for this is the '110 Push sent' emitted by the proxy when at least one push "
	        "notification has been sent to a target UA while routing an INVITE request. Some old versions of Linphone "
	        "(below linphone-sdk 4.2) suffer from an issue when receiving such kind of provisional responses that "
	        "do not come from a remote client. This setting is mainly intended to temporarily workaround this "
	        "situation.",
	        "true",
	    },
	    {
	        Boolean,
	        "resolve-routes",
	        "Resolve next hop in route header against registrar database.\n"
	        "This is an extension to RFC3261, and should not be used unless in some specific deployment cases. A next "
	        "hop in route header is otherwise resolved through standard DNS procedure by the Forward module.",
	        "false",
	    },
	    {
	        Boolean,
	        "parent-domain-fallback",
	        "Fallback to the parent domain if there is no fallback route set and the recipient is "
	        "unreachable.\n"
	        "For example, if routing to 'sip:bob@a.b.com' returns no result, route the request to 'b.com'. This is "
	        "also a non-standard behavior.",
	        "false",
	    },
	    {
	        BooleanExpr,
	        "fallback-route-filter",
	        "Only use the fallback route if the expression is true.",
	        "true",
	    },
	    {
	        DurationS,
	        "max-request-retention-time",
	        "Maximum duration the proxy will retain a request in order to maintain order.",
	        "30",
	    },
	    {
	        StringList,
	        "static-targets",
	        "List of sip addresses that are always added to the list of contacts fetched from the registrar database "
	        "when routing INVITE and MESSAGE requests.",
	        "",
	    },

	    // deprecated parameters
	    {
	        Boolean,
	        "stateful",
	        "Force forking and thus the creation of an outgoing transaction even when only one contact found",
	        "true",
	    },
	    {
	        Boolean,
	        "fork",
	        "Fork messages to all registered devices",
	        "true",
	    },
	    {
	        String,
	        "generated-contact-route",
	        "Generate a contact from the TO header and route it to the above destination. [sip:host:port]",
	        "",
	    },
	    {
	        String,
	        "generated-contact-expected-realm",
	        "Require presence of authorization header for specified realm. [Realm]",
	        "",
	    },
	    {
	        Boolean,
	        "generate-contact-even-on-filled-aor",
	        "Generate a contact route even on filled AOR.",
	        "false",
	    },
	    {
	        String,
	        "preroute",
	        "Rewrite username with given value.",
	        "",
	    },
	    config_item_end,
	};
	moduleConfig.addChildrenValues(configs);

	// deprecated since 2020-01-28 (2.0.0)
	{
		const char* depDate = "2020-01-28";
		const char* depVersion = "2.0.0";

		moduleConfig.get<ConfigBoolean>("stateful")
		    ->setDeprecated({
		        depDate,
		        depVersion,
		        "Stateless mode isn't supported anymore.",
		    });
		moduleConfig.get<ConfigBoolean>("fork")->setDeprecated({
		    depDate,
		    depVersion,
		    "This feature is always enabled since stateless mode is removed.",
		});

		GenericEntry::DeprecationInfo removedFeatureDepInfo(depDate, depVersion, "This feature has been removed.");
		moduleConfig.get<ConfigString>("generated-contact-route")->setDeprecated(removedFeatureDepInfo);
		moduleConfig.get<ConfigString>("generated-contact-expected-realm")->setDeprecated(removedFeatureDepInfo);
		moduleConfig.get<ConfigBoolean>("generate-contact-even-on-filled-aor")->setDeprecated(removedFeatureDepInfo);
		moduleConfig.get<ConfigString>("preroute")->setDeprecated(removedFeatureDepInfo);
	}

	moduleConfig.get<ConfigDuration<chrono::seconds>>("call-push-response-timeout")
	    ->setDeprecated({
	        "2022-02-03",
	        "2.2.0",
	        "This feature will be removed in a future version.",
	    });

	moduleConfig.createStatPair("count-forks", "Number of forks");
	moduleConfig.createStatPair("count-basic-forks", "Number of basic forks");
	moduleConfig.createStatPair("count-call-forks", "Number of call forks");
	moduleConfig.createStatPair("count-message-forks", "Number of message forks");
	moduleConfig.createStatPair("count-message-proxy-forks", "Number of proxy message forks");
	moduleConfig.createStatPair("count-message-conference-forks", "Number of conference message forks");
}

MsgSipPriority ModuleRouter::sMaxPriorityHandled = MsgSipPriority::Normal;

void OnContactRegisteredListener::onContactRegistered(const shared_ptr<Record>& r, const string& uid) {
	LOGD << "Listener invoked for topic = " << r->getKey() << ", uid = " << uid;
	if (r) mModule->onContactRegistered(shared_from_this(), uid, r);
}
void ModuleRouter::onLoad(const GenericStruct* mc) {
	const GenericStruct* cr = getAgent()->getConfigManager().getRoot();
	const GenericStruct* mReg = cr->get<GenericStruct>("module::Registrar");

	mDomains = mReg->get<ConfigStringList>("reg-domains")->read();

	// Forking configuration for INVITEs
	mCallForkCfg = make_shared<ForkContextConfig>();
	mCallForkCfg->mForkLate = mc->get<ConfigBoolean>("fork-late")->read();
	mCallForkCfg->mTreatAllErrorsAsUrgent = mc->get<ConfigBoolean>("treat-all-as-urgent")->read();
	mCallForkCfg->mForkNoGlobalDecline = mc->get<ConfigBoolean>("fork-no-global-decline")->read();
	mCallForkCfg->mUrgentTimeout = chrono::duration_cast<chrono::seconds>(
	    mc->get<ConfigDuration<chrono::seconds>>("call-fork-urgent-timeout")->read());
	mCallForkCfg->mPushResponseTimeout = chrono::duration_cast<chrono::seconds>(
	    mc->get<ConfigDuration<chrono::seconds>>("call-push-response-timeout")->read());
	mCallForkCfg->mDeliveryTimeout =
	    chrono::duration_cast<chrono::seconds>(mc->get<ConfigDuration<chrono::seconds>>("call-fork-timeout")->read())
	        .count();
	mCallForkCfg->mTreatDeclineAsUrgent = mc->get<ConfigBoolean>("treat-decline-as-urgent")->read();
	mCallForkCfg->mCurrentBranchesTimeout =
	    chrono::duration_cast<chrono::seconds>(
	        mc->get<ConfigDuration<chrono::seconds>>("call-fork-current-branches-timeout")->read())
	        .count();
	mCallForkCfg->mPermitSelfGeneratedProvisionalResponse =
	    mc->get<ConfigBoolean>("permit-self-generated-provisional-response")->read();

	// Forking configuration for MESSAGEs
	mMessageForkCfg = make_shared<ForkContextConfig>();
	mMessageForkCfg->mForkLate = mc->get<ConfigBoolean>("message-fork-late")->read();
	mMessageForkCfg->mDeliveryTimeout =
	    chrono::duration_cast<chrono::seconds>(
	        mc->get<ConfigDuration<chrono::seconds>>("message-delivery-timeout")->read())
	        .count();
	mMessageForkCfg->mUrgentTimeout = chrono::duration_cast<chrono::seconds>(
	    mc->get<ConfigDuration<chrono::seconds>>("message-accept-timeout")->read());

	// Forking configuration for other kind of requests.
	mOtherForkCfg = make_shared<ForkContextConfig>();
	mOtherForkCfg->mTreatAllErrorsAsUrgent = false;
	mOtherForkCfg->mForkLate = false;

	mUseGlobalDomain = mc->get<ConfigBoolean>("use-global-domain")->read();

	mAllowDomainRegistrations =
	    cr->get<GenericStruct>("inter-domain-connections")->get<ConfigBoolean>("accept-domain-registrations")->read();
	mAllowTargetFactorization = mc->get<ConfigBoolean>("allow-target-factorization")->read();
	mResolveRoutes = mc->get<ConfigBoolean>("resolve-routes")->read();
	mFallbackRoute = mc->get<ConfigString>("fallback-route")->read();
	mFallbackParentDomain = mc->get<ConfigBoolean>("parent-domain-fallback")->read();
	mFallbackRouteFilter = mc->get<ConfigBooleanExpression>("fallback-route-filter")->read();

	if (!mFallbackRoute.empty()) {
		mFallbackRouteParsed = ModuleToolbox::sipUrlMake(mHome.home(), mFallbackRoute.c_str());
		if (!mFallbackRouteParsed)
			throw BadConfiguration{"invalid value '" + mFallbackRoute + "' for module::Router/fallback-route"};
	}

	for (const auto& uri : mc->get<ConfigStringList>("static-targets")->read()) {
		mStaticTargets.emplace_back(uri);
	}

	if (mMessageForkCfg->mForkLate || mCallForkCfg->mForkLate) {
		mOnContactRegisteredListener = make_shared<OnContactRegisteredListener>(this);
	}

#if ENABLE_SOCI
	if (mMessageForkCfg->mForkLate && mc->get<ConfigBoolean>("message-database-enabled")->read()) {
		mMessageForkCfg->mSaveForkMessageEnabled = true;
		InjectContext::setMaxRequestRetentionTime(
		    mc->get<ConfigDuration<chrono::seconds>>("max-request-retention-time")->read());
		mInjector = make_unique<ScheduleInjector>(this);
		ForkMessageContextSociRepository::prepareConfiguration(
		    mc->get<ConfigString>("message-database-backend")->read(),
		    mc->get<ConfigString>("message-database-connection-string")->read(),
		    mc->get<ConfigInt>("message-database-pool-size")->read());

		restoreForksFromDatabase();
	}
#endif

	if (!mInjector) {
		mInjector = make_unique<AgentInjector>(this);
	}
}

#if ENABLE_SOCI
void ModuleRouter::restoreForksFromDatabase() {
	LOGI << "Fork message to database is enabled, retrieving previous messages in database...";
	auto allDbMessages = ForkMessageContextSociRepository::getInstance()->findAllForkMessage();
	LOGI << " ... " << allDbMessages.size() << " messages found in database ...";
	for (auto& dbMessage : allDbMessages) {
		mStats.mCountForks->incrStart();
		auto restoredForkMessage = ForkMessageContextDbProxy::make(shared_from_this(), dbMessage);
		for (const auto& key : dbMessage.dbKeys) {
			mForks.emplace(key, restoredForkMessage);
			mAgent->getRegistrarDb().subscribe(
			    Record::Key(key), std::weak_ptr<OnContactRegisteredListener>(mOnContactRegisteredListener));
		}
	}
	LOGI << " ... " << mForks.size() << " fork messages restored from database";
}
#endif

void ModuleRouter::sendReply(RequestSipEvent& ev, int code, const char* reason, int warn_code, const char* warning) {
	const shared_ptr<MsgSip>& ms = ev.getMsgSip();
	sip_t* sip = ms->getSip();
	sip_warning_t* warn = NULL;

	if (sip->sip_request->rq_method == sip_method_invite) {
		shared_ptr<CallLog> calllog = ev.getEventLog<CallLog>();
		if (calllog) {
			calllog->setStatusCode(code, reason);
			calllog->setCompleted();
		}
	} else if (sip->sip_request->rq_method == sip_method_message) {
		shared_ptr<MessageLog> mlog = ev.getEventLog<MessageLog>();
		if (mlog) {
			mlog->setStatusCode(code, reason);
			mlog->setCompleted();
		}
	}
	if (warn_code != 0) {
		warn = sip_warning_format(ev.getHome(), "%i %s \"%s\"", warn_code, mAgent->getPublicIp().c_str(), warning);
	}
	if (warn) {
		ev.reply(code, reason, SIPTAG_SERVER_STR(getAgent()->getServerString()), SIPTAG_WARNING(warn), TAG_END());
	} else {
		ev.reply(code, reason, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	}
}

template <>
Record::Key ModuleRouter::routingKey(const url_t* sipUri) {
	ostringstream oss;
	if (sipUri->url_user) {
		oss << sipUri->url_user << "@";
	}
	if (mUseGlobalDomain) {
		oss << "merged";
	} else {
		oss << sipUri->url_host;
	}
	return Record::Key(oss.str());
}

std::shared_ptr<BranchInfo> ModuleRouter::dispatch(const shared_ptr<ForkContext>& context,
                                                   const std::shared_ptr<ExtendedContact>& contact,
                                                   const std::string& targetUris) {

	const auto& ev = context->getEvent();
	const auto& ms = ev.getMsgSip();
	sip_contact_t* ct = contact->toSofiaContact(ms->getHome());
	url_t* dest = ct->m_url;

	/*sanity check on the contact address: might be '*' or whatever useless information*/
	if (dest->url_host == NULL || dest->url_host[0] == '\0') {
		LOGW << "Request is not routed because of incorrect address of contact";
		mInjector->removeContext(context, contact->contactId());
		return nullptr;
	}

	char* contact_url_string = url_as_string(ms->getHome(), dest);
	auto new_ev = make_unique<RequestSipEvent>(ev);
	auto new_msgsip = new_ev->getMsgSip();
	msg_t* new_msg = new_msgsip->getMsg();
	sip_t* new_sip = new_msgsip->getSip();

	// Convert path to routes
	sip_route_t* routes = contact->toSofiaRoute(new_ev->getHome());
	if (!contact->mUsedAsRoute) {
		if (targetUris.empty()) {
			/* Rewrite request-uri */
			new_sip->sip_request->rq_url[0] = *url_hdup(msg_home(new_msg), dest);
		} // else leave the request uri as it is, the X-target-uris header will give the resolved destinations.
		  // the cleaning of push notif params will be done just before forward
	} else {
		// leave the request uri as it is, but append a route for the final destination
		sip_route_t* final_route = sip_route_create(new_msgsip->getHome(), dest, NULL);
		if (!url_has_param(final_route->r_url, "lr")) {
			url_param_add(new_msgsip->getHome(), final_route->r_url, "lr");
		}
		if (routes == NULL) routes = final_route;
		else {
			sip_route_t* r = routes;
			while (r->r_next != NULL) {
				r = r->r_next;
			}
			r->r_next = final_route;
		}
	}
	if (!contact->mIsFallback) {
		/* If the original request received contained an X-Target-Uris, it shall be removed now, except
		 * in the case where we send to a fallback route, because in this case the actual resolution of the
		 * X-Target-Uris is actually not done at all. */
		sip_unknown_t* h = ModuleToolbox::getCustomHeaderByName(new_ev->getMsgSip()->getSip(), "X-Target-Uris");
		if (h) sip_header_remove(new_ev->getMsgSip()->getMsg(), new_ev->getMsgSip()->getSip(), (sip_header_t*)h);
	}

	if (!targetUris.empty()) {
		sip_header_insert(
		    new_msg, new_sip,
		    (sip_header_t*)sip_unknown_format(msg_home(new_msg), "X-Target-Uris: %s", targetUris.c_str()));
	}
	ModuleToolbox::cleanAndPrependRoute(getAgent(), new_msg, new_sip, routes);

	LOGI << "Fork to " << contact_url_string;

	return context->addBranch(std::move(new_ev), contact);
}

void ModuleRouter::onContactRegistered(const std::shared_ptr<OnContactRegisteredListener>& listener,
                                       const std::string& uid,
                                       const std::shared_ptr<Record>& record) {
	Home home;
	sip_contact_t* contact = NULL;
	bool forksFound = false;

	if (record == NULL) {
		LOGE << "Record is null";
		return;
	}

	if (!mCallForkCfg->mForkLate && !mMessageForkCfg->mForkLate) return;

	// Find all contexts
	auto range = getLateForks(record->getKey().asString());
	LOGD << "Searching for fork context with key " << record->getKey();

	if (range.size() > 0) {
		forksFound = true;
		const shared_ptr<ExtendedContact> ec = record->extractContactByUniqueId(uid);
		if (ec) {
			contact = ec->toSofiaContact(home.home());

			// First use sipURI
			mInjector->addContext(range, ec->contactId());
			for (const auto& context : range) {
				context->onNewRegister(SipUri{contact->m_url}, uid, ec);
			}
		}
	}

	const auto& contacts = record->getExtendedContacts();
	for (const auto& ec : contacts) {
		if (!ec || !ec->mAlias) continue;

		// Find all contexts
		contact = ec->toSofiaContact(home.home());
		auto rang = getLateForks(ExtendedContact::urlToString(ec->mSipContact->m_url));
		mInjector->addContext(rang, ec->contactId());
		for (const auto& context : rang) {
			forksFound = true;
			context->onNewRegister(SipUri{contact->m_url}, uid, ec);
		}
	}

	if (!forksFound) {
		/*
		 * REVISIT: late cleanup. This is really not the best option. I did this change because previous way of cleaning
		 * was not working. A better option would be to get rid of the mForks totally, and instead rely only on
		 * RegistrarDb::subscribe()/unsubscribe(). Another option would be to keep mForks, but make it a simple map of
		 * structure containing the OnContactRegisteredListener handling the topic + a list of ForkContext. When the
		 * list becomes empty, we know that we can clear the structure from mForks.
		 * --SM
		 */
		LOGD << "Router module no longer interested in contact registered notification for topic = "
		     << record->getKey();
		mAgent->getRegistrarDb().unsubscribe(record->getKey(), listener);
	}
}

struct ForkDestination {
	ForkDestination() : mSipContact(NULL) {
	}
	ForkDestination(sip_contact_t* ct, const shared_ptr<ExtendedContact>& exContact, const string& targetUris)
	    : mSipContact(ct), mExtendedContact(exContact), mTargetUris(targetUris) {
	}
	sip_contact_t* mSipContact;
	shared_ptr<ExtendedContact> mExtendedContact;
	string mTargetUris;
};

class ForkGroupSorter {
public:
	ForkGroupSorter(const list<pair<sip_contact_t*, shared_ptr<ExtendedContact>>>& usable_contacts)
	    : mAllContacts(usable_contacts) {
	}
	void makeGroups() {
		Home home;
		/*first step, eliminate adjacent contacts, they cannot be factorized*/
		for (auto it = mAllContacts.begin(); it != mAllContacts.end();) {
			if ((*it).second->mPath.size() < 2) {
				/*this is a "direct" destination, nothing to do*/
				mDestinations.emplace_back(ForkDestination((*it).first, (*it).second, ""));
				it = mAllContacts.erase(it);
			} else ++it;
		}
		/*second step, form groups with non-adjacent contacts*/
		for (auto it = mAllContacts.begin(); it != mAllContacts.end();) {
			list<pair<sip_contact_t*, shared_ptr<ExtendedContact>>>::iterator sameDestinationIt;
			ForkDestination dest;
			ostringstream targetUris;
			bool foundGroup = false;

			dest.mSipContact = (*it).first;
			dest.mExtendedContact = (*it).second;
			targetUris << "<" << *dest.mExtendedContact->toSofiaUrlClean(home.home()) << ">";
			url_t* url = url_make(home.home(), (*it).second->mPath.back().c_str());
			// remove it and now search for other contacts that have the same route.
			it = mAllContacts.erase(it);
			while ((sameDestinationIt = findDestination(url)) != mAllContacts.end()) {
				targetUris << ", <" << *(*sameDestinationIt).second->toSofiaUrlClean(home.home()) << ">";
				mAllContacts.erase(sameDestinationIt);
				foundGroup = true;
			}
			if (foundGroup) {
				// a group was formed
				LOGD << "A group with targetUris " << targetUris.str() << " was formed";
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
	const list<ForkDestination>& getDestinations() const {
		return mDestinations;
	}

private:
	static constexpr std::string_view mLogPrefix{"ForkGroupSorter"};

	list<pair<sip_contact_t*, shared_ptr<ExtendedContact>>>::iterator findDestination(const url_t* url) {
		Home home;
		for (auto it = mAllContacts.begin(); it != mAllContacts.end(); ++it) {
			url_t* it_route = url_make(home.home(), (*it).second->mPath.back().c_str());
			if (url_cmp(it_route, url) == 0) {
				return it;
			}
		}
		return mAllContacts.end();
	}

	list<ForkDestination> mDestinations;
	list<pair<sip_contact_t*, shared_ptr<ExtendedContact>>> mAllContacts;
};

void ModuleRouter::routeRequest(unique_ptr<RequestSipEvent>&& ev, const shared_ptr<Record>& aor, const url_t* sipUri) {
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	sip_t* sip = ms->getSip();
	list<pair<sip_contact_t*, shared_ptr<ExtendedContact>>> usableContacts;
	bool isInvite = false;

	if (!aor) {
		LOGD << "This user is not registered (no AOR)";
		LOGUE << "User " << url_as_string(ms->getHome(), sipUri) << " is not registered (no AOR)";
		sendReply(*ev, SIP_404_NOT_FOUND);
		return;
	}

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
		usableContacts.emplace_back(ct, ec);
	}
	if (usableContacts.empty()) {
		if (nonSipsFound) {
			/*rfc5630 5.3*/
			LOGUE << "Not dispatching request because SIPS not allowed for " << url_as_string(ms->getHome(), sipUri);
			sendReply(*ev, SIP_480_TEMPORARILY_UNAVAILABLE, 380, "SIPS not allowed");
		} else {
			LOGD << "This user is not registered (no valid contact)";
			LOGUE << "User " << url_as_string(ms->getHome(), sipUri) << " is not registered (no valid contact)";
			sendReply(*ev, SIP_404_NOT_FOUND);
		}
		return;
	}
	/*now we can create a fork context and dispatch the message to all branches*/

	mStats.mCountForks->incrStart();

	// Init context
	shared_ptr<ForkContext> context;
	const auto method = sip->sip_request->rq_method;
	const auto msgPriority = ms->getPriority() <= sMaxPriorityHandled ? ms->getPriority() : sMaxPriorityHandled;

	const auto makeForkMessageContext = [&, shared = shared_from_this()](bool isIntendedForConfServer =
	                                                                         false) -> shared_ptr<ForkContext> {
#if ENABLE_SOCI
		if (mMessageForkCfg->mSaveForkMessageEnabled)
			return ForkMessageContextDbProxy::make(shared, std::move(ev), msgPriority);
#endif
		return ForkMessageContext::make(shared, shared, std::move(ev), msgPriority, isIntendedForConfServer);
	};

	const auto imIsComposingXml =
	    sip->sip_content_type && strcasecmp(sip->sip_content_type->c_type, "application/im-iscomposing+xml") == 0;
	const auto sipExDeltaIsZero = sip->sip_expires && sip->sip_expires->ex_delta == 0;
	const auto referRequestIsText = sip->sip_refer_to && msg_params_find(sip->sip_refer_to->r_params, "text");

	if (method == sip_method_invite) {
		context = ForkCallContext::make(shared_from_this(), std::move(ev), MsgSipPriority::Urgent);
		isInvite = true;
	} else if (method == sip_method_message && !imIsComposingXml && !sipExDeltaIsZero) {
		// Use the basic fork context for "im-iscomposing+xml" messages to prevent storing useless messages.
		context = makeForkMessageContext(url_has_param(sip->sip_to->a_url, conference::CONFERENCE_ID));
	} else if (method == sip_method_refer && referRequestIsText) {
		// Use the message fork context only for REFER requests that are text to prevent storing useless REFER requests.
		context = makeForkMessageContext();
	} else {
		context = ForkBasicContext::make(shared_from_this(), std::move(ev), msgPriority);
	}

	auto key = routingKey<Record::Key>(sipUri);
	context->addKey(key.asString());
	mForks.emplace(key.asString(), context);
	LOGD << "Add fork " << context.get() << " to store with key '" << key << "'";
	if (context->getConfig()->mForkLate) {
		mAgent->getRegistrarDb().subscribe(key,
		                                   std::weak_ptr<OnContactRegisteredListener>(mOnContactRegisteredListener));
	}

	// now sort usable_contacts to form groups, if grouping is allowed
	ForkGroupSorter sorter(usableContacts);
	if (isInvite && mAllowTargetFactorization) {
		sorter.makeGroups();
	} else {
		sorter.makeDestinations();
	}
	const list<ForkDestination>& destinations = sorter.getDestinations();

	for (auto it = destinations.begin(); it != destinations.end(); ++it) {
		sip_contact_t* ct = (*it).mSipContact;
		const shared_ptr<ExtendedContact>& ec = (*it).mExtendedContact;
		const string& targetUris = (*it).mTargetUris;

		if (!ec->mAlias) {
			mInjector->addContext(context, ec->contactId());
			dispatch(context, ec, targetUris);
		} else {
			if (context->getConfig()->mForkLate && isManagedDomain(ct->m_url)) {
				sip_contact_t* temp_ctt =
				    sip_contact_create(ms->getHome(), (url_string_t*)ec->mSipContact->m_url, NULL);

				if (mUseGlobalDomain) {
					temp_ctt->m_url->url_host = "merged";
					temp_ctt->m_url->url_port = NULL;
				}
				auto aliasKey = routingKey<Record::Key>(temp_ctt->m_url);
				context->addKey(aliasKey.asString());
				mForks.emplace(aliasKey.asString(), context);
				LOGD << "Add fork " << context.get() << " to store with key '" << aliasKey
				     << "' because it is an alias";
				if (context->getConfig()->mForkLate) {
					mAgent->getRegistrarDb().subscribe(
					    std::move(aliasKey), std::weak_ptr<OnContactRegisteredListener>(mOnContactRegisteredListener));
				}
			}
		}
	}

	context->start();
}

class TargetUriListFetcher : public ContactUpdateListener, public enable_shared_from_this<TargetUriListFetcher> {
public:
	// Adding maybe_unused after the argument because of C++ compiler bug:
	// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=81429
	TargetUriListFetcher(ModuleRouter* module,
	                     RequestSipEvent& ev,
	                     const shared_ptr<ContactUpdateListener>& listener,
	                     const sip_unknown_t* target_uris)
	    : mListener(listener), mRegistrarDb(module->getAgent()->getRegistrarDb()) {
		mRecord = make_shared<Record>(SipUri(), mRegistrarDb.getRecordConfig());
		if (target_uris && target_uris->un_value) {
			// The X-target-uris header is parsed like a route, as it is a list of URIs
			const auto routes = sip_route_make(ev.getHome(), target_uris->un_value);

			for (sip_route_t* iter = routes; iter; iter = iter->r_next) {
				try {
					SipUri uri(iter->r_url);
					mUriList.push_back(std::move(uri));
				} catch (const InvalidUrlError& e) {
					vector<char> buffer(1024);
					sip_unknown_e(buffer.data(), buffer.size(), (msg_header_t*)target_uris, 0);
					LOGW << "Invalid URI in X-Target-Uris header [" << e.getUrl() << "], ignoring it, context:" << endl
					     << ev.getMsgSip()->contextAsString() << endl
					     << buffer.data() << endl;
				}
			}
		}
	}

	~TargetUriListFetcher() override = default;

	void fetch(bool allowDomainRegistrations, bool recursive) {
		// Compute the number of asynchronous queries we are going to make, to later know when we are done.
		mPending = mUriList.size();

		// Start the queries for all uris of the target uri list.
		for (const auto& uri : mUriList) {
			mRegistrarDb.fetch(uri, this->shared_from_this(), allowDomainRegistrations, recursive);
		}
	}

	void onRecordFound(const shared_ptr<Record>& r) override {
		--mPending;
		if (r != nullptr) {
			mRecord->appendContactsFrom(r);
		}
		checkFinished();
	}

	void onError(const SipStatus&) override {
		--mPending;
		mError = true;
		checkFinished();
	}

	void onInvalid(const SipStatus&) override {
		--mPending;
		mError = true;
		checkFinished();
	}

	void onContactUpdated([[maybe_unused]] const shared_ptr<ExtendedContact>& ec) override {
	}

	void checkFinished() {
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

private:
	friend class ModuleRouter;

	static constexpr std::string_view mLogPrefix{"TargetUriListFetcher"};

	int mPending = 0;
	bool mError = false;
	vector<SipUri> mUriList;
	shared_ptr<Record> mRecord;
	shared_ptr<ContactUpdateListener> mListener;
	RegistrarDb& mRegistrarDb;
};

class OnFetchForRoutingListener : public ContactUpdateListener {
public:
	OnFetchForRoutingListener(ModuleRouter* module,
	                          unique_ptr<RequestSipEvent>&& ev,
	                          const SipUri& sipuri,
	                          const vector<SipUri>& staticTargetUris = {})
	    : mSipUri(sipuri), mStaticTargets(staticTargetUris), mModule(module), mEv(std::move(ev)) {
		if (!mEv->isSuspended()) mEv->suspendProcessing();

		const sip_t* sip = mEv->getMsgSip()->getSip();
		if (sip->sip_request->rq_method == sip_method_invite) {
			mEv->setEventLog(make_shared<CallLog>(sip));
		}
	}

	void onRecordFound(const shared_ptr<Record>& arg) override {
		shared_ptr<Record> r = arg;
		const string& fallbackRoute = mModule->getFallbackRoute();
		const auto& recordConfig = mModule->getAgent()->getRegistrarDb().getRecordConfig();
		const auto& msgExpiresName = recordConfig.messageExpiresName();

		if (r == nullptr) {
			r = make_shared<Record>(mSipUri, recordConfig);
		}

		auto& contacts = r->getExtendedContacts();
		for (const auto& uri : mStaticTargets) {
			contacts.emplace(make_shared<ExtendedContact>(uri, "", msgExpiresName));
		}

		if (!mModule->isManagedDomain(mSipUri.get())) {
			const auto contact =
			    r->getExtendedContacts().emplace(make_shared<ExtendedContact>(mSipUri, "", msgExpiresName));

			LOGD << "Record [" << r << "] original request URI added because domain is not managed: " << **contact;
		}

		if (!fallbackRoute.empty() && mModule->getFallbackRouteFilter()->eval(*mEv->getMsgSip()->getSip())) {
			if (!ModuleToolbox::viaContainsUrlHost(mEv->getMsgSip()->getSip()->sip_via,
			                                       mModule->getFallbackRouteParsed())) {
				shared_ptr<ExtendedContact> fallback =
				    make_shared<ExtendedContact>(mSipUri, fallbackRoute, msgExpiresName, 0.0);
				fallback->mIsFallback = true;
				r->getExtendedContacts().emplace(fallback);
				LOGD << "Record [" << r << "] fallback route '" << fallbackRoute << "' added: " << *fallback;
			} else {
				LOGD << "Not adding fallback route '" << fallbackRoute
				     << "' to avoid loop because request is coming from there already";
			}
		}

		if (r->count() == 0 && mModule->isFallbackToParentDomainEnabled()) {
			string host = mSipUri.getHost();
			size_t pos = host.find('.');
			size_t end = host.length();
			if (pos == string::npos) {
				LOGE << "Host URL does not have any subdomain: " << host;
				mModule->routeRequest(std::move(mEv), r, mSipUri.get());
				return;
			} else {
				host = host.substr(pos + 1, end - (pos + 1)); // Gets the host without the first subdomain
			}

			auto urlStr = "sip:" + mSipUri.getUser() + "@" + host;
			SipUri url(urlStr);
			LOGD << "Record [" << r << "] empty, trying to route to parent domain: '" << urlStr << "'";

			auto onRoutingListener = make_shared<OnFetchForRoutingListener>(mModule, std::move(mEv), mSipUri);
			mModule->getAgent()->getRegistrarDb().fetch(url, onRoutingListener, mModule->isDomainRegistrationAllowed(),
			                                            true);
		} else {
			mModule->routeRequest(std::move(mEv), r, mSipUri.get());
		}
	}

	void onError(const SipStatus& response) override {
		mModule->sendReply(*mEv, response.getCode(), response.getReason());
	}

	void onInvalid(const SipStatus& response) override {
		LOGD << response.getReason();
		mModule->sendReply(*mEv, response.getCode(), response.getReason());
	}

	void onContactUpdated([[maybe_unused]] const shared_ptr<ExtendedContact>& ec) override {
	}

	RequestSipEvent& getEvent() {
		return *mEv;
	}

private:
	friend class ModuleRouter;

	static constexpr std::string_view mLogPrefix{"OnFetchForRoutingListener"};

	SipUri mSipUri;
	vector<SipUri> mStaticTargets;
	ModuleRouter* mModule = nullptr;
	unique_ptr<RequestSipEvent> mEv;
};

vector<string> ModuleRouter::split(const char* data, const char* delim) {
	const char* p;
	vector<string> res;
	char* s = strdup(data);
	char* saveptr = NULL;
	for (p = strtok_r(s, delim, &saveptr); p; p = strtok_r(NULL, delim, &saveptr)) {
		res.push_back(p);
	}
	free(s);
	return res;
}

ModuleRouter::ForkRefList ModuleRouter::getLateForks(const std::string& key) const noexcept {
	ForkRefList lateForks{};
	lateForks.reserve(mForks.count(key));
	auto range = mForks.equal_range(key);
	for (auto it = range.first; it != range.second; ++it) {
		const auto& forkCtx = it->second;
		if (forkCtx->getConfig()->mForkLate) lateForks.emplace_back(it->second);
	}
	return lateForks;
}

unique_ptr<RequestSipEvent> ModuleRouter::onRequest(unique_ptr<RequestSipEvent>&& ev) {
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	sip_t* sip = ms->getSip();
	const url_t* next_hop = nullptr;
	bool isRoute = false;

	const bool iAmTheEdgeProxy = !sip->sip_via || !sip->sip_via->v_next;
	if (sip->sip_request->rq_method == sip_method_bye && iAmTheEdgeProxy) {
		ev->writeLog(make_shared<CallEndedEventLog>(*sip));
	}

	if ((next_hop = ModuleToolbox::getNextHop(getAgent(), sip, &isRoute)) != NULL && isRoute) {
		LOGD << "Route header found [" << url_as_string(ms->getHome(), next_hop) << "] but not us, skipping";
		return std::move(ev);
	}

	if (mResolveRoutes) {
		sip_route_t* iterator = sip->sip_route;
		while (iterator != NULL) {
			sip_route_t* route = iterator;
			if (getAgent()->isUs(route->r_url)) {
				LOGD << "Route header found " << url_as_string(ms->getHome(), route->r_url) << " and is us, continuing";
			} else {
				try {
					LOGD << "Route header found " << url_as_string(ms->getHome(), route->r_url)
					     << " but not us, forwarding";
					SipUri sipurl(sip->sip_request->rq_url);
					auto onRoutingListener = make_shared<OnFetchForRoutingListener>(this, std::move(ev), sipurl);
					mAgent->getRegistrarDb().fetch(sipurl, onRoutingListener, mAllowDomainRegistrations, true);
					return {};
				} catch (const InvalidUrlError& e) {
					LOGD << e.what();
					ev->reply(400, "Bad request", TAG_END());
					return {};
				}
			}
			iterator = iterator->r_next;
		}
	} else if (sip->sip_route != NULL && !getAgent()->isUs(sip->sip_route->r_url)) {
		LOGD << "Route header found " << url_as_string(ms->getHome(), sip->sip_route->r_url) << " but not us, skipping";
		return std::move(ev);
	}

	try {
		SipUri requestUri(sip->sip_request->rq_url);

		if (!isManagedDomain(requestUri.get())) return std::move(ev);

		if (sip->sip_request->rq_method == sip_method_cancel) {
			// Handle SipEvent associated with a Stateful transaction
			ForkContext::processCancel(*ev);
			if (!ev->isTerminated()) sendReply(*ev, SIP_481_NO_TRANSACTION);
			return std::move(ev);
		}

		/*unless in a specific case, REGISTER don't go into the router logic*/
		if (sip->sip_request->rq_method == sip_method_register) {
			if (sip->sip_from->a_url->url_user == NULL ||
			    !getAgent()->getDRM()->haveToRelayRegToDomain(sip->sip_request->rq_url->url_host)) {
				return std::move(ev);
			}
			LOGD << "Router: routing REGISTER to domain controller";
		}

		/*see if we can route other requests */
		/*
		 * 	ACKs shall not have their request uri rewritten:
		    - these can be for us (in response to a 407 for invite)
		    - these can be for a remote peer, in which case they will have the correct contact address in the
		 request uri
		*/
		/* When we accept * as domain we need to test ip4/ipv6 */
		if (sip->sip_request->rq_method == sip_method_ack || sip->sip_to == NULL || sip->sip_to->a_tag != NULL)
			return std::move(ev);

		LOGD << "Fetch for url " << requestUri.str();

		// Go stateful to stop retransmissions
		ev->createIncomingTransaction();
		sendReply(*ev, SIP_100_TRYING);

		// The non-standard "X-Target-Uris" header gives us a list of SIP uri. The request has to be forked to
		// all of them.
		const auto* targetUrisHeader = ModuleToolbox::getCustomHeaderByName(ev->getSip(), "X-Target-Uris");
		const auto listener = make_shared<OnFetchForRoutingListener>(this, std::move(ev), requestUri, mStaticTargets);

		if (!targetUrisHeader) {
			mAgent->getRegistrarDb().fetch(requestUri, listener, mAllowDomainRegistrations, true);
		} else {
			const auto fetcher =
			    make_shared<TargetUriListFetcher>(this, listener->getEvent(), listener, targetUrisHeader);
			fetcher->fetch(mAllowDomainRegistrations, true);
		}
	} catch (const InvalidUrlError& e) {
		LOGD << "The request URI [" << e.getUrl()
		     << "] is not valid (skipping fetching from registrar database): " << e.getReason();
	}
	return std::move(ev);
}

unique_ptr<ResponseSipEvent> ModuleRouter::onResponse(unique_ptr<ResponseSipEvent>&& ev) {
	ForkContext::processResponse(*ev);
	return std::move(ev);
}

void ModuleRouter::onForkContextFinished(const shared_ptr<ForkContext>& ctx) {
	const auto& keys = ctx->getKeys();
	for (const auto& key : keys) {
		LOGD << "Looking at fork contexts with key " << key;

		auto range = mForks.equal_range(key);
		for (auto it = range.first; it != range.second;) {
			if (it->second == ctx) {
				LOGD << "Remove fork " << it->first << " from store";
				mStats.mCountForks->incrFinish();
				auto cur_it = it;
				++it;
				// for some reason the multimap erase does not return the next iterator !
				mForks.erase(cur_it);
				// do not break, because a single fork context might appear several time in the map because of aliases.
			} else {
				++it;
			}
		}
	}
}

shared_ptr<BranchInfo> ModuleRouter::onDispatchNeeded(const shared_ptr<ForkContext>& ctx,
                                                      const shared_ptr<ExtendedContact>& newContact) {
	return dispatch(ctx, newContact);
}

void ModuleRouter::onUselessRegisterNotification(const std::shared_ptr<ForkContext>& ctx,
                                                 const std::shared_ptr<ExtendedContact>& newContact,
                                                 [[maybe_unused]] const SipUri& dest,
                                                 [[maybe_unused]] const std::string& uid,
                                                 [[maybe_unused]] const DispatchStatus reason) {
	mInjector->removeContext(ctx, newContact->contactId());
}

bool ModuleRouter::isManagedDomain(const url_t* url) const {
	return ModuleToolbox::isManagedDomain(getAgent(), mDomains, url);
}

void ModuleRouter::sendToInjector(unique_ptr<RequestSipEvent>&& ev,
                                  const shared_ptr<ForkContext>& context,
                                  const string& contactId) {
	mInjector->injectRequestEvent(std::move(ev), context, contactId);
}

ModuleInfo<ModuleRouter> ModuleRouter::sInfo(
    "Router",
    "The Router module routes requests for domains it manages.\n"
    "The routing algorithm is as follows: \n"
    " - first skip route headers that directly point to this proxy.\n"
    " - if a route header is found that doesn't point to this proxy, then the request is not processed by the Router "
    "module, and will be"
    " handled by the Forward module at the end of the processing chain.\n"
    " - examine the request-uri: if it is part of the domains managed by this proxy (according to Registrar module "
    "'reg-domains' definition,"
    " then attempt to resolve the request-uri from the Registrar database.\n"
    " - the results from the registrar database, in the form of contact headers, are sorted by priority (q parameter), "
    "if any.\n"
    " - for each set of contact with equal priorities, the request is forked, and sent to their corresponding sip URI. "
    "After a timeout defined by property 'call-fork-current-branches-timeout', a next set of contact header is "
    "determined.\n"
    " - responses are received from all attempted branches, and sent back to the request originator, according to the "
    "procedure of RFC3261 16.7"
    " Response processing.\n"
    "The router module offers different variations of the routing logic, depending on whether it is an INVITE, a "
    "MESSAGE, or another type of request. "
    "The processing of MESSAGE request essentially differs from others because it allows to keep the MESSAGE for a "
    "later delivery, in which "
    "case the incoming transaction will be terminated with a 202 Accepted response.",
    {"ContactRouteInserter"},
    ModuleInfoBase::ModuleOid::Router,
    declareConfig);