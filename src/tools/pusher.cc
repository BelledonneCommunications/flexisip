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

#include "common.hh"
#include "pushnotification/applepush.hh"
#include "pushnotification/googlepush.hh"
#include "pushnotification/microsoftpush.hh"
#include "pushnotification/pushnotificationservice.hh"

#include <unistd.h>
#include <string>

#include <ortp/ortp.h>
#include <sofia-sip/url.h>

static const int MAX_QUEUE_SIZE = 100;
// static const int PRINT_STATS_TIMEOUT = 3000;	/* In milliseconds. */

class ErrorCb : public PushNotificationRequestCallback {
	virtual void onError(const string &msg) {
		cout << "ErrorCb: " << msg << endl;
	}
};

struct PusherArgs {
	string prefix;
	string pntype;
	bool debug;
	string appid;
	vector<string> pntok;
	string apikey;

	void usage(const char *app) {
		cout << app
			 << " --pntype error|google|wp|apple --appid id --pntok id1 id2 id3 --gkey googleapikey --prefix dir --debug "
			 << endl;
	}

	const char *parseUrlParams(const char *params) {
		char tmp[64];
		if (url_param(params, "pn-type", tmp, sizeof(tmp)) == 0) {
			return "no pn-type";
		} else
			pntype = tmp;

		if (url_param(params, "app-id", tmp, sizeof(tmp)) == 0) {
			return "no app-id";
		} else
			appid = tmp;

		if (url_param(params, "pn-tok", tmp, sizeof(tmp)) == 0) {
			return "no pn-tok";
		} else
			pntok.push_back(tmp);

		return NULL;
	}

	void parse(int argc, char *argv[]) {
		prefix = "/etc/flexisip";
		pntype = "error";
#define EQ0(i, name) (strcmp(name, argv[i]) == 0)
#define EQ1(i, name) (strcmp(name, argv[i]) == 0 && argc > i)
		for (int i = 1; i < argc; ++i) {
			if (EQ1(i, "--prefix")) {
				prefix = argv[++i];
			} else if (EQ1(i, "--pntype")) {
				pntype = argv[++i];
			} else if (EQ1(i, "--appid")) {
				appid = argv[++i];
			} else if (EQ0(i, "--debug")) {
				debug = true;
			} else if (EQ1(i, "--pntok")) {
				i++;
				while (i < argc && strncmp(argv[i], "--", 2) != 0) {
					pntok.push_back(argv[i]);
					i++;
				}
			} else if (EQ1(i, "--gkey")) {
				apikey = argv[++i];
			} else if (EQ1(i, "--raw")) {
				const char *res = parseUrlParams(argv[++i]);
				if (res) {
					cerr << "? raw " << res << endl;
					exit(-1);
				}
			} else if (EQ0(i, "--help") || EQ0(i, "-h")) {
				usage(*argv);
				exit(0);
			} else {
				cerr << "? arg" << i << " " << argv[i] << endl;
				usage(*argv);
				exit(-1);
			}
		}
	}
};

static vector<shared_ptr<PushNotificationRequest>> createRequestFromArgs(const PusherArgs &args) {
	vector<shared_ptr<PushNotificationRequest>> result;
	for (string pntok : args.pntok) {
		PushInfo pinfo;
		pinfo.mType = args.pntype;
		pinfo.mFromName = "Pusher";
		pinfo.mFromUri = "sip:toto@sip.linphone.org";
		if (args.pntype == "error") {
			result.push_back(make_shared<ErrorPushNotificationRequest>());
		} else if (args.pntype == "google") {
			pinfo.mCallId = "fb14b5fe-a9ab-1231-9485-7d582244ba3d";
			pinfo.mFromName = "+33681741738";
			pinfo.mDeviceToken = pntok;
			pinfo.mAppId = args.appid;
			pinfo.mApiKey = args.apikey;
			result.push_back(make_shared<GooglePushNotificationRequest>(pinfo));
		} else if (args.pntype == "wp") {
			pinfo.mAppId = args.appid;
			pinfo.mDeviceToken = pntok;
			pinfo.mEvent = PushInfo::Message;
			pinfo.mText = "Hi here!";
			result.push_back(make_shared<WindowsPhonePushNotificationRequest>(pinfo));
		} else if (args.pntype == "apple") {
			pinfo.mAlertMsgId = "IM_MSG";
			pinfo.mAlertSound = "msg.caf";
			pinfo.mAppId = args.appid;
			pinfo.mDeviceToken = pntok;
			result.push_back(make_shared<ApplePushNotificationRequest>(pinfo));
		} else {
			cerr << "? push pntype " << args.pntype << endl;
			exit(-1);
		}
	}
	return result;
}

int main(int argc, char *argv[]) {
	PusherArgs args;
	args.parse(argc, argv);

	flexisip::log::preinit(sUseSyslog, args.debug);
	flexisip::log::initLogs(sUseSyslog, args.debug);
	flexisip::log::updateFilter("%Severity% >= debug");

	PushNotificationService service(MAX_QUEUE_SIZE);

	if (args.pntype == "apple") {
		service.setupiOSClient(args.prefix + "/apn", "");
	} else if (args.pntype == "google") {
		map<string, string> googleKey;
		googleKey.insert(make_pair(args.appid, args.apikey));
		service.setupAndroidClient(googleKey);
	}

	service.start();
	auto pn = createRequestFromArgs(args);
	auto cb = make_shared<ErrorCb>();
	int ret = 0;
	for (auto push : pn) {
		push->setCallBack(cb);
		ret += service.sendRequest(push);
	}
	sleep(1);
	if (ret == 0) {
		service.waitEnd();
	} else {
		cerr << "fail to send request, aborting" << endl;
	}
	return ret;
}
