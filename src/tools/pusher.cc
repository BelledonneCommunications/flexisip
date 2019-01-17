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

#include <flexisip/common.hh>
#include "pushnotification/applepush.hh"
#include "pushnotification/googlepush.hh"
#include "pushnotification/microsoftpush.hh"
#include "pushnotification/firebasepush.hh"
#include "pushnotification/pushnotificationservice.hh"

#include <unistd.h>
#include <string>

#include <ortp/ortp.h>
#include <sofia-sip/url.h>
#include <sofia-sip/base64.h>

using namespace std;
using namespace flexisip;

static const int MAX_QUEUE_SIZE = 3000;
// static const int PRINT_STATS_TIMEOUT = 3000;	/* In milliseconds. */

struct PusherArgs {
	PusherArgs() : debug(false), isSilent(false){
	}
	string prefix;
	string pntype;
	bool debug;
	bool isSilent;
	string appid;
	vector<string> pntok;
	string apikey;
	string packageSID;
	void usage(const char *app) {
		cout << app
			 << " --pntype google|firebase|wp|w10|apple --appid id --key apikey(secretkey) --sid ms-app://value --prefix dir --silent --debug --pntok id1 (id2 id3 ...)"
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
		pntype = "";
#define EQ0(i, name) (strcmp(name, argv[i]) == 0)
#define EQ1(i, name) (strcmp(name, argv[i]) == 0 && argc > i)
		for (int i = 1; i < argc; ++i) {
			if (EQ1(i, "--prefix")) {
				prefix = argv[++i];
			} else if (EQ1(i, "--pntype")) {
				pntype = argv[++i];
			} else if (EQ1(i, "--appid")) {
				appid = argv[++i];
			} else if (EQ1(i, "--sid")) {
				packageSID = argv[++i];
			} else if (EQ0(i, "--debug")) {
				debug = true;
			}else if (EQ0(i, "--silent")) {
				isSilent = true;
			} else if (EQ1(i, "--pntok")) {
				while (i+1 < argc && strncmp(argv[i+1], "--", 2) != 0) {
					i++;
					pntok.push_back(argv[i]);
				}
			} else if (EQ1(i, "--key")) {
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
	for (auto it = args.pntok.begin(); it != args.pntok.end(); it++) {
		auto pntok = *it;
		PushInfo pinfo;
		pinfo.mType = args.pntype;
		pinfo.mFromName = "Pusher";
		pinfo.mFromUri = "sip:toto@sip.linphone.org";
		if (args.pntype == "google") {
			pinfo.mCallId = "fb14b5fe-a9ab-1231-9485-7d582244ba3d";
			pinfo.mFromName = "+33681741738";
			pinfo.mDeviceToken = pntok;
			pinfo.mAppId = args.appid;
			pinfo.mApiKey = args.apikey;
			result.push_back(make_shared<GooglePushNotificationRequest>(pinfo));
		} else if (args.pntype == "firebase") {
			pinfo.mCallId = "fb14b5fe-a9ab-1231-9485-7d582244ba3d";
			pinfo.mFromName = "+33681741738";
			pinfo.mDeviceToken = pntok;
			pinfo.mAppId = args.appid;
			pinfo.mApiKey = args.apikey;
			result.push_back(make_shared<FirebasePushNotificationRequest>(pinfo));
		} else if (args.pntype == "wp") {
			pinfo.mAppId = args.appid;
			pinfo.mDeviceToken = pntok;
			pinfo.mEvent = PushInfo::Message;
			pinfo.mText = "Hi here!";
			result.push_back(make_shared<WindowsPhonePushNotificationRequest>(pinfo));
		} else if (args.pntype == "w10") {
			pinfo.mAppId = args.appid;
			pinfo.mEvent = PushInfo::Message;
			pinfo.mDeviceToken = pntok;
			pinfo.mText = "Hi here!";
			result.push_back(make_shared<WindowsPhonePushNotificationRequest>(pinfo));
		} else if (args.pntype == "apple") {
			pinfo.mAlertMsgId = "IM_MSG";
			pinfo.mAlertSound = "msg.caf";
			pinfo.mAppId = args.appid;
			pinfo.mDeviceToken = pntok;
			pinfo.mTtl = 2592000;
			pinfo.mSilent = args.isSilent;
			//pinfo.mTtl = 60;
			result.push_back(make_shared<ApplePushNotificationRequest>(pinfo));
		} else {
			cerr << "? push pntype " << args.pntype << endl;
			exit(-1);
		}
	}
	return result;
}

int main(int argc, char *argv[]) {
	int ret = 0;
	PusherArgs args;
	args.parse(argc, argv);

	flexisip::log::preinit(flexisip_sUseSyslog, args.debug, 0, "pusher");
	flexisip::log::initLogs(flexisip_sUseSyslog, args.debug ? "debug" : "error", "error", false, true);
	flexisip::log::updateFilter("%Severity% >= debug");

	{
		PushNotificationService service(MAX_QUEUE_SIZE);

		if (args.pntype == "apple") {
			service.setupiOSClient(args.prefix + "/apn", "");
		} else if (args.pntype == "google") {
			map<string, string> googleKey;
			googleKey.insert(make_pair(args.appid, args.apikey));
			service.setupAndroidClient(googleKey);
		} else if (args.pntype == "firebase") {
			map<string, string> firebaseKey;
			firebaseKey.insert(make_pair(args.appid, args.apikey));
			service.setupFirebaseClient(firebaseKey);
		} else if (args.pntype == "wp" || args.pntype == "w10") {
			service.setupWindowsPhoneClient(args.packageSID, args.apikey);
		}

		auto pn = createRequestFromArgs(args);
		for (auto it = pn.begin(); it != pn.end(); it++) {
			auto push = *it;
			ret += service.sendPush(push);
		}
		
		while (!service.isIdle()) {
			sleep(1);
		}
		
		int failed = 0;
		int success = 0;
		int inprogress = 0;
		int notsubmitted = 0;
		int total = 0;
		
		for(auto it = pn.begin(); it != pn.end(); it++){
			switch((*it)->getState()){
				case PushNotificationRequest::NotSubmitted:
					notsubmitted++;
				break;
				case PushNotificationRequest::InProgress:
					inprogress++;
				break;
				case PushNotificationRequest::Failed:
					failed++;
				break;
				case PushNotificationRequest::Successful:
					success++;
				break;
			}
			total++;
		}
		cout << total << " push notification(s) sent, " << success << " successfully and " << failed << " failed." << endl;  
		if (failed > 0 ){
			cout << "There are failed requests, relaunch with --debug to consult exact error cause." << endl;
		}
		if (notsubmitted > 0 || inprogress > 0){
			cerr << "There were unsubmitted or uncompleted requests, this is a bug." << endl;
		}
	}
	cout << "job is done, thanks for using " << argv[0] << ". Bye!" << endl;
	return ret;
}
