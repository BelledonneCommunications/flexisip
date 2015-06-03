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
#include "pushnotification/pushnotification.hh"
#include "pushnotification/pushnotificationservice.hh"

#include <unistd.h>
#include <string>

#include <ortp/ortp.h>
#include <sofia-sip/url.h>

using namespace ::std;

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
	string pntok;
	string apikey;

	void usage(const char* app) {
		cout << app << " --pntype error|google|wp|apple --appid id --pntok theid --gkey googleapikey --prefix dir --debug " << endl;
	}

	const char *parseUrlParams(const char *params) {
		char tmp[64];
		if (url_param(params, "pn-type", tmp, sizeof(tmp)) == 0) {
			return "no pn-type";
		} else pntype = tmp;

		if (url_param(params, "app-id", tmp, sizeof(tmp)) == 0) {
			return "no app-id";
		} else appid = tmp;

		if (url_param(params, "pn-tok", tmp, sizeof(tmp)) == 0) {
			return "no pn-tok";
		} else pntok = tmp;

		return NULL;
	}

	void parse(int argc, char *argv[]) {
		prefix = "/etc/flexisip";
		pntype = "error";
		#define EQ0(i, name) (strcmp(name, argv[ i ]) == 0)
		#define EQ1(i, name) (strcmp(name, argv[ i ]) == 0 && argc > i)
		for (int i = 1; i < argc; ++i) {
			if (EQ1(i, "--prefix")) {
				prefix = argv[++i];
			} else if (EQ1(i, "--pntok")) {
				pntok = argv[++i];
			} else if (EQ1(i, "--pntype")) {
				pntype = argv[++i];
			} else if (EQ1(i, "--appid")) {
				appid = argv[++i];
			} else if (EQ0(i, "--debug")) {
				debug = true;
			}  else if (EQ1(i, "--pntok")) {
				pntok = argv[++i];
			}  else if (EQ1(i, "--gkey")) {
				apikey = argv[++i];
			}  else if (EQ1(i, "--raw")) {
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

static shared_ptr<PushNotificationRequest> createRequestFromArgs(const PusherArgs &args) {
	PushInfo pinfo;
	pinfo.mType=args.pntype;
	pinfo.mFromName="Pusher";
	pinfo.mFromUri="sip:toto@sip.linphone.org";
	if (args.pntype == "error") {
		return make_shared<ErrorPushNotificationRequest>();
	} else if (args.pntype == "google") {
		pinfo.mCallId="fb14b5fe-a9ab-1231-9485-7d582244ba3d";
		pinfo.mFromName="+33681741738";
		pinfo.mDeviceToken=args.pntok;
		pinfo.mApiKey=args.apikey;
		return make_shared<GooglePushNotificationRequest>(pinfo);
	} else if (args.pntype == "wp") {
		pinfo.mAppId=args.appid;
		pinfo.mDeviceToken=args.pntok;
		pinfo.mEvent=PushInfo::Message;
		pinfo.mText="Hi here!";
		return make_shared<WindowsPhonePushNotificationRequest>(pinfo);
	} else if (args.pntype == "apple") {
		pinfo.mAlertMsgId="IM_MSG";
		pinfo.mAlertSound="msg.caf";
		pinfo.mAppId=args.appid;
		pinfo.mDeviceToken=args.pntok;
		return make_shared<ApplePushNotificationRequest>(pinfo);
	}
	cerr << "? push pntype " << args.pntype << endl;
	exit(-1);
}

int main(int argc, char *argv[])
{
	PusherArgs args;
	args.parse(argc, argv);

	flexisip::log::preinit(sUseSyslog, args.debug);
	flexisip::log::initLogs(sUseSyslog, args.debug);
	flexisip::log::updateFilter("%Severity% >= debug");

	auto pn = createRequestFromArgs(args);
	auto cb = make_shared<ErrorCb>();
	pn->setCallBack(cb);

	PushNotificationService service(args.prefix+"/apn", "", MAX_QUEUE_SIZE);
	service.start();
	int ret = service.sendRequest(pn);
	sleep(1);
	service.waitEnd();
	return ret;
}
