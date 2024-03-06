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

#include <sstream>

#include <sofia-sip/sip_status.h>
#include <sofia-sip/su_md5.h>
#include <sofia-sip/tport.h>

#include "flexisip/module.hh"

#include "agent.hh"
#include "eventlogs/events/eventlogs.hh"
#include "eventlogs/writers/event-log-writer.hh"

using namespace std;
using namespace flexisip;

class StatisticsCollector : public Module {
	friend std::shared_ptr<Module> ModuleInfo<StatisticsCollector>::create(Agent*);

public:
	~StatisticsCollector();
	virtual void onLoad(const GenericStruct* root);
	virtual void onRequest(shared_ptr<RequestSipEvent>& ev);
	virtual void onResponse(shared_ptr<ResponseSipEvent>& ev);

private:
	StatisticsCollector(Agent* ag, const ModuleInfoBase* moduleInfo);
	int managePublishContent(const shared_ptr<RequestSipEvent> ev);
	bool containsMandatoryFields(char* data, usize_t len);

	static ModuleInfo<StatisticsCollector> sInfo;
	url_t* mCollectorAddress;
	su_home_t mHome;
};

StatisticsCollector::StatisticsCollector(Agent* ag, const ModuleInfoBase* moduleInfo)
    : Module(ag, moduleInfo), mCollectorAddress(NULL) {
	su_home_init(&mHome);
}

StatisticsCollector::~StatisticsCollector() {
	su_home_deinit(&mHome);
}

void StatisticsCollector::onLoad(const GenericStruct* mc) {
	string value = mc->get<ConfigString>("collector-address")->read();
	if (value.size() > 0) {
		mCollectorAddress = url_make(&mHome, value.c_str());
		if (mCollectorAddress == NULL ||
		    (mCollectorAddress->url_type != url_sip && mCollectorAddress->url_type != url_sips)) {
			LOGF("StatisticsCollector: Invalid collector address '%s'", value.c_str());
		}
		mCollectorAddress->url_type =
		    url_sip; /*we don't want to distinguish between sip and sips for the collector url*/
	} else {
		mCollectorAddress = NULL;
	}
	LOGI("StatisticsCollector: setup with collector address '%s'", value.c_str());
}

void StatisticsCollector::onRequest(shared_ptr<RequestSipEvent>& ev) {
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	sip_t* sip = ms->getSip();
	url_t url = *sip->sip_request->rq_url;
	// verify collector address AND content type
	url.url_type = url_sip; /*workaround the fact that we could receive the publish as sips .*/
	if (mCollectorAddress && (url_cmp(mCollectorAddress, &url) == 0)) {
		if (sip->sip_content_type && (strcmp("application/vq-rtcpxr", sip->sip_content_type->c_type) == 0) &&
		    (strcmp("vq-rtcpxr", sip->sip_content_type->c_subtype) == 0)) {
			// some treatment
			int err = managePublishContent(ev);
			ev->reply(err, sip_status_phrase(err), SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		} else {
			LOGI("StatisticsCollector: received PUBLISH with invalid type, ignoring");
		}
	}
}

void StatisticsCollector::onResponse([[maybe_unused]] shared_ptr<ResponseSipEvent>& ev) {
}

/*avoid crash if x is NULL on libc versions <4.5.26 */
#define __strstr(x, y) ((x == NULL) ? NULL : strstr(x, y))

bool StatisticsCollector::containsMandatoryFields(char* body, [[maybe_unused]] usize_t len) {
	char* remote_metrics_start = __strstr(body, "RemoteMetrics:");

	if (__strstr(body, "VQIntervalReport\r\n") != body && __strstr(body, "VQSessionReport\r\n") != body &&
	    __strstr(body, "VQSessionReport: CallTerm\r\n") != body)
		return false;

	if (!(body = __strstr(body, "CallID:"))) return false;
	if (!(body = __strstr(body, "LocalID:"))) return false;
	if (!(body = __strstr(body, "RemoteID:"))) return false;
	if (!(body = __strstr(body, "OrigID:"))) return false;
	if (!(body = __strstr(body, "LocalGroup:"))) return false;
	if (!(body = __strstr(body, "RemoteGroup:"))) return false;
	if (!(body = __strstr(body, "LocalAddr:"))) return false;
	if (!(body = __strstr(body, "IP="))) return false;
	if (!(body = __strstr(body, "PORT="))) return false;
	if (!(body = __strstr(body, "SSRC="))) return false;
	if (!(body = __strstr(body, "RemoteAddr:"))) return false;
	if (!(body = __strstr(body, "IP="))) return false;
	if (!(body = __strstr(body, "PORT="))) return false;
	if (!(body = __strstr(body, "SSRC="))) return false;
	if (!(body = __strstr(body, "LocalMetrics:"))) return false;
	if (!(body = __strstr(body, "Timestamps:"))) return false;
	if (!(body = __strstr(body, "START="))) return false;
	if (!(body = __strstr(body, "STOP="))) return false;

	/* We should have not reached RemoteMetrics section yet */
	if (remote_metrics_start && body >= remote_metrics_start) return false;

	return true;
}

int StatisticsCollector::managePublishContent(const shared_ptr<RequestSipEvent> ev) {
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	const sip_t* sip = ms->getSip();
	int err = 200;
	std::string statusPhrase = "OK";

	if (!sip) {
		err = 400;
		statusPhrase = "Invalid SIP";
	}

	// verify that packet contains data
	if (!sip->sip_payload || sip->sip_payload->pl_len == 0 || !sip->sip_payload->pl_data) {
		err = 606;
		statusPhrase = "No data in packet payload";
		// verify that packet contains mandatory fields
	} else if (!containsMandatoryFields(sip->sip_payload->pl_data, sip->sip_payload->pl_len)) {
		err = 606;
		statusPhrase = "One or several mandatory fields missing";
	}

	auto log = make_shared<CallQualityStatisticsLog>(sip);
	log->setStatusCode(err, statusPhrase.c_str());
	log->setCompleted();
	ev->setEventLog(log);

	return err;
}

ModuleInfo<StatisticsCollector> StatisticsCollector::sInfo(
    "StatisticsCollector",
    "The purpose of the StatisticsCollector module is to "
    "collect call statistics (RFC 6035) and store them on the server.",
    {"Registrar"},
    ModuleInfoBase::ModuleOid::StatisticsCollector,

    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor items[] = {{String, "collector-address",
	                                     "SIP URI of the statistics collector. "
	                                     "Note that application/vq-rtcpxr messages for this address will be deleted by "
	                                     "this module and thus not be delivered.",
	                                     ""},

	                                    config_item_end};
	    moduleConfig.addChildrenValues(items);

	    /* modify the default value for "enabled" */
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
	    moduleConfig.get<ConfigBooleanExpression>("filter")->setDefault(
	        "is_request && request.method-name == 'PUBLISH'");
    });
