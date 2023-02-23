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

#include <flexisip/module.hh>
#include <flexisip/agent.hh>

using namespace std;
using namespace flexisip;

class ModuleSanityChecker : public Module, protected ModuleToolbox {
public:
	ModuleSanityChecker(Agent *ag) : Module(ag) {
	}

	~ModuleSanityChecker() {
	}

	virtual void onRequest(shared_ptr<RequestSipEvent> &ev) {
		sip_t *sip = ev->getMsgSip()->getSip();

		const char *error = checkHeaders(sip);
		if (error) {
			LOGW("Rejecting request because of %s", error);
			ev->reply(400, error, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		}
		if (sip->sip_request == NULL || sip->sip_request->rq_url->url_host == NULL) {
			ev->reply(400, "Bad request URI", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		}
	}

	virtual void onResponse([[maybe_unused]] shared_ptr<ResponseSipEvent> &ev) {
		// don't check our responses ;)
	}

	void onDeclare([[maybe_unused]] GenericStruct *mc) {
	}

private:
	const char *checkHeaders(sip_t *sip) {
		if (sip->sip_via == NULL)
			return "No via";
		if (sip->sip_from == NULL || sip->sip_from->a_url->url_host == NULL || sip->sip_from->a_tag == NULL)
			return "Invalid from header";
		if (sip->sip_to == NULL || sip->sip_to->a_url->url_host == NULL)
			return "Invalid to header";
		if (sip->sip_contact) {
			if (sip->sip_contact->m_url->url_scheme == NULL)
				return "Invalid scheme in contact header";
			if (sip->sip_contact->m_url->url_scheme[0] != '*' && sip->sip_contact->m_url->url_host == NULL)
				return "Invalid contact header";
		}
		return NULL;
	}
	static ModuleInfo<ModuleSanityChecker> sInfo;
};

ModuleInfo<ModuleSanityChecker> ModuleSanityChecker::sInfo(
	"SanityChecker",
	"The SanitChecker module checks that required fields of a SIP message are present to avoid unecessary checking while "
	"processing message further.\n"
	"If the message doesn't meet these sanity check criterias, then it is stopped and bad request response is sent.",
	{ "DoSProtection" },
	ModuleInfoBase::ModuleOid::SanityChecker
);
