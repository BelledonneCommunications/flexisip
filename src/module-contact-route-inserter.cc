/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/module.hh"

#include "agent.hh"
#include "contact-masquerader.hh"

using namespace std;
using namespace flexisip;

class ContactRouteInserter : public Module {
	friend std::shared_ptr<Module> ModuleInfo<ContactRouteInserter>::create(Agent*);

public:
	void onLoad(const GenericStruct* mc) {
		mCtRtParamName = string("CtRt") + getAgent()->getUniqueId();
		mMasqueradeInvites = mc->get<ConfigBoolean>("masquerade-contacts-for-invites")->read();
		mMasqueradeRegisters = mc->get<ConfigBoolean>("masquerade-contacts-on-registers")->read();
		mInsertDomain = mc->get<ConfigBoolean>("insert-domain")->read();
		mContactMasquerader = unique_ptr<ContactMasquerader>(new ContactMasquerader(mAgent, mCtRtParamName));
	}

	void onRequest(shared_ptr<RequestSipEvent>& ev) {
		const shared_ptr<MsgSip>& ms = ev->getMsgSip();
		sip_t* sip = ms->getSip();
		const sip_method_t rq_method = sip->sip_request->rq_method;

		if (mMasqueradeRegisters && rq_method == sip_method_register) {
			LOGD("Masquerading contact");
			mContactMasquerader->masquerade(ev, mInsertDomain);
		} else if (mMasqueradeInvites && rq_method == sip_method_invite) {
			LOGD("Masquerading contact");
			mContactMasquerader->masquerade(ev);
		}

		if (rq_method != sip_method_register) {
			// check if request-uri contains a contact-route parameter,
			// so that we can route back to the client
			char ctrt[512];
			url_t* dest = sip->sip_request->rq_url;
			// now need to check if request uri has special param inserted
			// by contact-route-inserter module
			if (url_param(dest->url_params, mCtRtParamName.c_str(), ctrt, sizeof(ctrt))) {
				LOGD("Found a contact route parameter");
				mContactMasquerader->restore(ms->getHome(), dest, ctrt, "doroute");
			} else {
				LOGD("No countact route parameter found");
			}
		}
	}

	virtual void onResponse(shared_ptr<ResponseSipEvent>& ev) {
		const shared_ptr<MsgSip>& ms = ev->getMsgSip();
		sip_t* sip = ms->getSip();
		if (mMasqueradeInvites &&
		    (sip->sip_cseq->cs_method == sip_method_invite || sip->sip_cseq->cs_method == sip_method_subscribe)) {
			mContactMasquerader->masquerade(ev);
		}
	}

	unique_ptr<ContactMasquerader> mContactMasquerader;
	string mCtRtParamName;
	bool mMasqueradeRegisters, mMasqueradeInvites;
	bool mInsertDomain;

private:
	ContactRouteInserter(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo), mContactMasquerader() {
	}

	static ModuleInfo<ContactRouteInserter> sInfo;
};

ModuleInfo<ContactRouteInserter> ContactRouteInserter::sInfo(
    "ContactRouteInserter",
    "The purpose of the ContactRouteInserter module is to masquerade the contact header of "
    "incoming registers that are not handled locally "
    "(think about flexisip used as a SBC gateway) in such a way that it is then possible "
    "to route back outgoing invites to the original address. "
    "It is a kind of similar mechanism as Record-Route, but for REGISTER.",
    {"StatisticsCollector"},
    ModuleInfoBase::ModuleOid::ContactRouteInserter,

    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor items[] = {
	        {Boolean, "masquerade-contacts-on-registers", "Masquerade register contacts with proxy address.", "true"},
	        {Boolean, "masquerade-contacts-for-invites", "Masquerade invite-related messages with proxy address.",
	         "false"},
	        {Boolean, "insert-domain", "Masquerade register with from domain.", "false"},
	        config_item_end};
	    moduleConfig.addChildrenValues(items);
    },
    ModuleClass::Experimental);
