/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include <string>

#include <flexisip/common.hh>
#include <flexisip/utils/timer.hh>

#include "pushnotification/service.hh"

using namespace std;
using namespace flexisip;
using namespace flexisip::pushnotification;


static constexpr int MAX_QUEUE_SIZE = 3000;

struct PusherArgs {
	string prefix{};
	string pntype{};
	bool debug{false};
	string appid{};
	vector<string> pntok{};
	string apikey{};
	string packageSID{};
	string customPayload;
	ApplePushType applePushType{ApplePushType::Pushkit};
	bool legacyPush{false};

	// Standard params
	string pnProvider{};
	string pnParam{};
	vector<string> pnPrids{};

	void usage(const char *app) {
		cout << "Standard push notifications usage:" << endl << "    "
			<< app << " [options] --pn-provider provider --pn-param params --pn-prid prid1 [prid2 prid3 ...]" << endl
			<< endl
			<< "Legacy push notifications usage:" << endl << "    "
			<< app << " [options] --pntype {google|firebase|wp|w10|apple} --appid id --key --pntok id1 [id2 id3 ...] apikey(secretkey) --sid ms-app://value --prefix dir" << endl
			<< endl
			<< "Generic options:" << endl
			<< "    --customPayload json" << endl
			<< "    --apple-push-type {RemoteBasic|RemoteWithMutableContent|Background|PushKit}, PushKit by default" << endl
			<< "    --prefix dir" << endl
			<< "    --debug" << endl;
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

		auto showUsageAndExit = [=]() {
			usage(*argv);
			exit(-1);
		};
		bool found_RFC_8599_Params = false;
		bool found_Legacy_Params = false;

#define EQ0(i, name) (strcmp(name, argv[i]) == 0)
#define EQ1(i, name) (strcmp(name, argv[i]) == 0 && argc > i)
		for (int i = 1; i < argc; ++i) {
			if (EQ1(i, "--prefix")) {
				prefix = argv[++i];
			} else if (EQ1(i, "--pntype")) {
				found_Legacy_Params = true;
				pntype = argv[++i];
			} else if (EQ1(i, "--appid")) {
				found_Legacy_Params = true;
				appid = argv[++i];
			} else if (EQ1(i, "--sid")) {
				packageSID = argv[++i];
			} else if (EQ0(i, "--debug")) {
				debug = true;
			}else if (EQ0(i, "--silent")) {
				cout << "WARNING: --silent has no more effect (deprecated)" << endl;
			} else if (EQ1(i, "--apple-push-type")) {
				const char *aspt = argv[++i];
				if (string(aspt) == "PushKit") {
					applePushType = ApplePushType::Pushkit;
				} else if (string(aspt) == "RemoteBasic") {
					applePushType = ApplePushType::RemoteBasic;
				} else if (string(aspt) == "RemoteWithMutableContent") {
					applePushType = ApplePushType::RemoteWithMutableContent;
				} else if (string(aspt) == "Background") {
					applePushType = ApplePushType::Background;
				} else {
					usage(*argv);
					exit(-1);
				}
			} else if (EQ1(i, "--pntok")) {
				found_Legacy_Params = true;
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
					showUsageAndExit();
				}
			} else if (EQ1(i, "--pn-provider")) {
				found_RFC_8599_Params = true;
				pnProvider = argv[++i];
			} else if (EQ1(i, "--pn-prid")) {
				found_RFC_8599_Params = true;
				while (i+1 < argc && strncmp(argv[i+1], "--", 2) != 0) {
					i++;
					pnPrids.push_back(argv[i]);
				}
			} else if (EQ1(i, "--pn-param")) {
				found_RFC_8599_Params = true;
				pnParam = argv[++i];
			} else if (EQ0(i, "--help") || EQ0(i, "-h")) {
				usage(*argv);
				exit(0);
			} else if (EQ1(i, "--customPayload")) {
				customPayload = argv[++i];
			} else {
				cerr << "? arg" << i << " " << argv[i] << endl;
				showUsageAndExit();
			}
		}

		if (found_Legacy_Params && found_RFC_8599_Params) {
			cerr << "Found both legacy and standard parameters, choose one way or the other !" << endl;
			showUsageAndExit();
		}

		legacyPush = found_Legacy_Params;

		if (legacyPush && pntok.empty()) {
			cerr << "Trying to use legacy push but couldn't find any pntok" << endl;
			showUsageAndExit();
		} else if (!legacyPush && pnPrids.empty()) {
			cerr << "Trying to use standard push but couldn't find any pn-prid" << endl;
			showUsageAndExit();
		}
	}
};

static vector<PushInfo> createPushInfosFromArgs(const PusherArgs &args) {
	vector<PushInfo> pushInfos;
	// Parameters in common between Legacy and Standard push
	auto createAndInitializePushInfo = [](const PusherArgs &args) -> PushInfo {
		PushInfo pinfo;
		pinfo.mFromName = "Pusher";
		pinfo.mFromUri = "sip:toto@sip.linphone.org";
		return pinfo;
	};

	// Parameters in common between Legacy and Standard push, specifically for apple push notification
	auto fillAppleGenericParams = [&args](PushInfo &pinfo) {
		pinfo.mAlertMsgId = "IM_MSG";
		pinfo.mAlertSound = "msg.caf";
		pinfo.mTtl = 2592000;
		pinfo.mCustomPayload = args.customPayload;
		pinfo.mApplePushType = args.applePushType;
	};

	if (args.legacyPush) { // Legacy push
		for (const auto &pntok : args.pntok) {
			PushInfo pinfo = createAndInitializePushInfo(args);
			pinfo.mType = args.pntype;
			if (args.pntype == "firebase") {
				pinfo.mCallId = "fb14b5fe-a9ab-1231-9485-7d582244ba3d";
				pinfo.mFromName = "+33681741738";
				pinfo.mDeviceToken = pntok;
				pinfo.mAppId = args.appid;
				pinfo.mApiKey = args.apikey;
			} else if (args.pntype == "wp") {
				pinfo.mAppId = args.appid;
				pinfo.mDeviceToken = pntok;
				pinfo.mEvent = PushInfo::Event::Message;
				pinfo.mText = "Hi here!";
			} else if (args.pntype == "w10") {
				pinfo.mAppId = args.appid;
				pinfo.mEvent = PushInfo::Event::Message;
				pinfo.mDeviceToken = pntok;
				pinfo.mText = "Hi here!";
			} else if (args.pntype == "apple") {
				fillAppleGenericParams(pinfo);
				pinfo.mAppId = args.appid;
				pinfo.mDeviceToken = pntok;
			}
			pushInfos.push_back(pinfo);
		}
	} else { // StandardPush
		RFC8599PushParams standardParams;
		standardParams.pnProvider = args.pnProvider;
		standardParams.pnParam = args.pnParam;
		for (const auto &pnPrid : args.pnPrids) {
			standardParams.pnPrid = pnPrid;
			PushInfo pinfo = createAndInitializePushInfo(args);
			pinfo.readRFC8599PushParams(standardParams);
			if (pinfo.mType == "apple") {
				fillAppleGenericParams(pinfo);
				// apple-push-type is still required in order to be able to know if the notification is a remote or background.
				// Background notification aren't specified in the standard push params, but rather in the content of the push notification
				pinfo.mApplePushType = args.applePushType;
			}
			pinfo.mApiKey = args.apikey;
			pushInfos.push_back(pinfo);
		}
	}
	return pushInfos;
}

int main(int argc, char *argv[]) {
	int ret = 0;
	PusherArgs args;
	args.parse(argc, argv);

	LogManager::Parameters logParams;

	logParams.logDirectory = "/var/opt/belledonne-communications/log/flexisip"; //Sorry but ConfigManager is not accessible in this tool.
	logParams.logFilename = "flexisip-pusher.log";
	logParams.level = args.debug ? BCTBX_LOG_DEBUG : BCTBX_LOG_ERROR;
	logParams.enableSyslog = false;
	logParams.enableStdout = true;
	LogManager::get().initialize(logParams);

	{
		auto root = su_root_create(nullptr);
		Service service{*root, MAX_QUEUE_SIZE};
		auto pushInfos = createPushInfosFromArgs(args);

		// Cannot be empty, or the program would have exited while parsing parameters. All pushInfos have the same mType, so we just take the front one.
		string pnType = pushInfos.front().mType;
		if (pnType == "apple") {
			service.setupiOSClient(args.prefix + "/apn", "");
		} else if (pnType == "firebase") {
			map<string, string> firebaseKey;
			firebaseKey.emplace(pushInfos.front().mAppId, pushInfos.front().mApiKey);
			service.setupFirebaseClient(firebaseKey);
		} else if (pnType == "wp" || pnType == "w10") {
			service.setupWindowsPhoneClient(args.packageSID, args.apikey);
		}

		vector<shared_ptr<Request>> pushRequests;

		for (const PushInfo &pinfo : pushInfos) {
			try {
				pushRequests.push_back(Service::makePushRequest(pinfo));
			} catch (const invalid_argument &msg) {
				cerr << msg.what() << endl;
				exit(-1);
			}
		}
		for (const auto &push : pushRequests) {
			ret += service.sendPush(push);
		}

		sofiasip::Timer timer{root, 1000};
		timer.run(
			[root, &service] () {
				if (service.isIdle()) su_root_break(root);
			}
		);
		su_root_run(root);

		int failed = 0;
		int success = 0;
		int inprogress = 0;
		int notsubmitted = 0;
		int total = 0;

		for(const auto &request : pushRequests){
			switch(request->getState()){
				case Request::State::NotSubmitted:
					notsubmitted++;
				break;
				case Request::State::InProgress:
					inprogress++;
				break;
				case Request::State::Failed:
					failed++;
				break;
				case Request::State::Successful:
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
