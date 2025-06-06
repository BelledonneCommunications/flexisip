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

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <string>

#include "flexisip/common.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/sofia-wrapper/timer.hh"

#include "exceptions/exit.hh"
#include "pushnotification/apple/apple-request.hh"
#include "pushnotification/service.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace flexisip;
using namespace flexisip::pushnotification;

static constexpr int MAX_QUEUE_SIZE = 3000;
static constexpr auto* PUSHER_DEFAULT_LOG_DIR = "/var/opt/belledonne-communications/log/flexisip";

/**
 * Command line arguments parser and documentation.
 */
struct PusherArgs {
	/* Standard and mandatory parameters */
	string pnProvider{};
	string pnParam{};
	vector<string> pnPrids{};

	/* General options */
	bool debug{false};
	string customPayload{};
	string callID{};

	/* Android specific options */
	string apikey{};

	/* iOS specific options */
	string prefix{};
	PushType applePushType{PushType::Background};

	/* Pusher internal parameters */
	string pntype{};
	string appid{};
	vector<string> pntok{};
	string packageSID{};
	bool legacyPush{false};

	/*
	 * Print push usage documentation in the standard output.
	 * @param app path to executable
	 */
	void usage(const char* app) {
		cout << "usage: " << app
		     << " "
		        R"doc([options] --pn-provider {apns,apns.dev,fcm} --pn-param <param> --pn-prid <prid> [<prid> ...]

A tool to send push notifications to Android and iOS applications, based on parameters defined by RFC8599.

Mandatory parameters:
---------------------
  --pn-provider {apns,apns.dev,fcm}  The service in charge to send the push notification.
                                       * 'apns'     for iOS production applications;
                                       * 'apns.dev' for iOS development applications;
                                       * 'fcm'      for Android applications.

  --pn-param <param>                 Provider specific ID of the application.
                                       * Android:   Firebase Project ID.
                                       * iOS:       <TeamID>.<BundleID>[.voip], where '.voip' is only added
                                                    for VoIP push notification.


  --pn-prid <prid>                   Provider specific ID of the targeted application instance.
                                       * Android:   Registration token.
                                       * iOS:       Device token.


General options:
----------------
  -h, --help                         Show this help message and exit.
  --debug                            Print all debug messages on the standard output.

  --customPayload <payload>          Add custom parameters in the PN request body. <payload> must be a JSON structure
								     and will be placed in the top-level JSON attribute.

  --call-id <callID>                 Call-ID to use in the push notification payload.


Android specific options:
-------------------------
  --key <SecretKey>                  Specify the secret key to put in the HTTP/2 headers to be authenticated
                                     by Firebase push notification service.


iOS specific options:
---------------------
  --prefix <path>                    Path to the directory where the APNS certificates are stored. The certificates
                                     must actually be placed in a subdirectory named 'apns' just like a standard
                                     Flexisip configuration directory.

  --apple-push-type {Background,RemoteWithMutableContent,PushKit}
                                     The kind of push notification to send to the iOS device. Default: PushKit.
                                       * Background: only wake the application up without displaying anything to
                                         the user;
                                       * RemoteWithMutableContent: a message is displayed to the user;
                                       * PushKit: require the application to use CallKit API to display the incoming
                                         call view.

Examples:
---------
* Send a data push notification to an Android application:

    ./flexisip_pusher --key '<SecretKey>' --pn-provider 'fcm' --pn-param '<ProjectID>' --pn-prid '<token>'


* Send a data push notification to an Android application using FirebaseV1 API:

    ./flexisip_pusher --key '<FirebaseServiceAccountFile>' --pn-provider 'fcm' --pn-param '<ProjectID>' --pn-prid '<token>'


* Send a remote message push notification to an iOS production application:

    ./flexisip_pusher --prefix /etc/flexisip --pn-provider 'apns' --pn-param '<TeamID>.<BundleID>'
                      --pn-prid '<token>' --apple-push-type RemoteWithMutableContent


* Send a remote message push notification to an iOS development application:

    ./flexisip_pusher --prefix /etc/flexisip --pn-provider 'apns.dev' --pn-param '<TeamID>.<BundleID>'
                      --pn-prid '<token>' --apple-push-type RemoteWithMutableContent


* Send a VoIP push notification to an iOS production application:

    ./flexisip_pusher --prefix /etc/flexisip --pn-provider 'apns' --pn-param '<TeamID>.<BundleID>.voip'
                      --pn-prid '<token>' --apple-push-type PushKit


* Send a background push notification (remote PN without alert section) to an iOS production application:

    ./flexisip_pusher --prefix /etc/flexisip --pn-provider 'apns' --pn-param '<TeamID>.<BundleID>'
                      --pn-prid '<token>' --apple-push-type Background


Environment Variables:
----------------------
  FS_LOG_DIR    The directory to write logs into. Defaults to )doc"
		     << PUSHER_DEFAULT_LOG_DIR << '\n';
	}

	const char* parseUrlParams(const char* params) {
		char tmp[64];
		if (url_param(params, "pn-type", tmp, sizeof(tmp)) == 0) {
			return "no pn-type";
		} else pntype = tmp;

		if (url_param(params, "app-id", tmp, sizeof(tmp)) == 0) {
			return "no app-id";
		} else appid = tmp;

		if (url_param(params, "pn-tok", tmp, sizeof(tmp)) == 0) {
			return "no pn-tok";
		} else pntok.emplace_back(tmp);

		return nullptr;
	}

	void parse(int argc, const char* argv[]) {
		prefix = "/etc/flexisip";
		pntype = "";

		bool found_RFC_8599_Params = false;
		bool found_Legacy_Params = false;

#define EQ0(i, name) (strcmp(name, argv[i]) == 0)
#define EQ1(i, name) (i + 1 < argc && strcmp(name, argv[i]) == 0)
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
			} else if (EQ0(i, "--silent")) {
				cout << "WARNING: --silent has no more effect (deprecated)" << endl;
			} else if (EQ1(i, "--apple-push-type")) {
				const char* aspt = argv[++i];
				if (string(aspt) == "PushKit") {
					applePushType = PushType::VoIP;
				} else if (string(aspt) == "RemoteWithMutableContent") {
					applePushType = PushType::Message;
				} else if (string(aspt) == "Background") {
					applePushType = PushType::Background;
				} else {
					usage(*argv);
					throw ExitFailure{-1};
				}
			} else if (EQ1(i, "--pntok")) {
				found_Legacy_Params = true;
				while (i + 1 < argc && strncmp(argv[i + 1], "--", 2) != 0) {
					i++;
					pntok.emplace_back(argv[i]);
				}
			} else if (EQ1(i, "--key")) {
				apikey = argv[++i];
			} else if (EQ1(i, "--raw")) {
				const char* res = parseUrlParams(argv[++i]);
				if (res) {
					cerr << "? raw " << res << endl;
					usage(*argv);
					throw ExitFailure{-1};
				}
			} else if (EQ1(i, "--pn-provider")) {
				found_RFC_8599_Params = true;
				pnProvider = argv[++i];
			} else if (EQ1(i, "--pn-prid")) {
				found_RFC_8599_Params = true;
				while (i + 1 < argc && strncmp(argv[i + 1], "--", 2) != 0) {
					i++;
					pnPrids.emplace_back(argv[i]);
				}
			} else if (EQ1(i, "--pn-param")) {
				found_RFC_8599_Params = true;
				pnParam = argv[++i];
			} else if (EQ0(i, "--help") || EQ0(i, "-h")) {
				usage(*argv);
				throw ExitSuccess{};
			} else if (EQ1(i, "--customPayload")) {
				customPayload = argv[++i];
			} else if (EQ1(i, "--call-id")) {
				callID = argv[++i];
			} else {
				cerr << "? arg" << i << " " << argv[i] << endl;
				usage(*argv);
				throw ExitFailure{-1};
			}
		}

		if (found_Legacy_Params && found_RFC_8599_Params) {
			cerr << "Error: found both legacy and standard parameters, choose one way or the other!" << endl;
			usage(*argv);
			throw ExitFailure{-1};
		}

		legacyPush = found_Legacy_Params;

		if (legacyPush && pntok.empty()) {
			cerr << "Error: trying to use legacy push notifications but couldn't find any pntok" << endl;
			usage(*argv);
			throw ExitFailure{-1};
		} else if (!legacyPush && pnPrids.empty()) {
			cerr << "Error: trying to use standard push notifications but couldn't find any pn-prid" << endl;
			usage(*argv);
			throw ExitFailure{-1};
		}
	}
};

struct Stats {
	int failed{0};
	int success{0};
	int inprogress{0};
	int notsubmitted{0};

	int total() const noexcept {
		return failed + success + inprogress + notsubmitted;
	}
};

static vector<std::unique_ptr<PushInfo>> createPushInfosFromArgs(const PusherArgs& args) {
	vector<unique_ptr<PushInfo>> pushInfos{};
	// Parameters in common between legacy and standard push notifications.
	const auto fillCommonPushParams = [&args](PushInfo& info) {
		info.mFromName = "";
		info.mFromUri = "";
		info.mCallId = args.callID;
		if (args.applePushType == PushType::VoIP) {
			info.mAlertMsgId = "IC_MSG";
			info.mTtl = 90s; // Default proxy value
		} else {
			info.mAlertMsgId = "IM_MSG";
			info.mTtl = 30 * 24h;
		}
		info.mAlertSound = "empty"; // Not used by the app anyway
		info.mCustomPayload = args.customPayload;
	};

	if (args.legacyPush) { // Legacy push notifications.
		for (const auto& pntok : args.pntok) {
			auto pinfo = make_unique<PushInfo>();
			auto dest = make_shared<RFC8599PushParams>();
			dest->setFromLegacyParams(args.pntype, args.appid, pntok);
			pinfo->addDestination(dest);
			fillCommonPushParams(*pinfo);
			pushInfos.emplace_back(std::move(pinfo));
		}
	} else { // Standard push notifications.
		for (const auto& pnPrid : args.pnPrids) {
			auto destinations = RFC8599PushParams::parsePushParams(args.pnProvider, args.pnParam, pnPrid);
			auto pinfo = make_unique<PushInfo>();
			for (const auto& kv : destinations) {
				pinfo->addDestination(kv.second);
			}
			fillCommonPushParams(*pinfo);
			pushInfos.emplace_back(std::move(pinfo));
		}
	}

	return pushInfos;
}

int _main(int argc, const char* argv[]) {
	PusherArgs args{};
	args.parse(argc, argv);

	// Note: sorry but ConfigManager is not accessible in this tool.
	LogManager::Parameters logParams{};
	logParams.logDirectory = [] {
		const auto* logDir = std::getenv("FS_LOG_DIR");
		return logDir ? logDir : PUSHER_DEFAULT_LOG_DIR;
	}();
	logParams.logFilename = "flexisip-pusher.log";
	logParams.level = args.debug ? BCTBX_LOG_DEBUG : BCTBX_LOG_MESSAGE;
	logParams.enableSyslog = false;
	logParams.enableStdout = true;
	LogManager::get().initialize(logParams);

	const auto root = make_shared<sofiasip::SuRoot>();
	Service service{root, MAX_QUEUE_SIZE};
	auto pushInfos = createPushInfosFromArgs(args);

	// Cannot be empty, or the program would have exited while parsing parameters.
	// All pushInfos have the same mType, so we just take the front one.
	const auto& pushParams = pushInfos.front()->mDestinations.cbegin()->second;
	const auto& provider = pushParams->getProvider();
	if (provider == "apns" || provider == "apns.dev") {
		service.setupiOSClient(args.prefix + "/apn", "");
	} else if (provider == "fcm") {
		const auto& apiKey = args.apikey;
		if (apiKey.empty()) throw ExitFailure{"missing Firebase service account file, use '--key'"};

		if (filesystem::exists(apiKey)) {
			service.addFirebaseV1Client(pushParams->getParam(), FIREBASE_GET_ACCESS_TOKEN_SCRIPT_PATH, apiKey, 1min,
			                            5min);
		}
	}

	vector<shared_ptr<Request>> pushRequests{};
	for (auto& pinfo : pushInfos) {
		pushRequests.emplace_back(service.makeRequest(args.applePushType, std::move(pinfo)));
	}

	Stats stats{};
	for (const auto& push : pushRequests) {
		try {
			service.sendPush(push);
		} catch (const exception& e) {
			SLOGE << e.what();
			stats.failed++;
		}
	}

	while (!service.isIdle()) {
		root->step(100ms);
	}

	for (const auto& request : pushRequests) {
		switch (request->getState()) {
			case Request::State::NotSubmitted:
				stats.notsubmitted++;
				break;
			case Request::State::InProgress:
				stats.inprogress++;
				break;
			case Request::State::Failed:
				stats.failed++;
				break;
			case Request::State::Successful:
				stats.success++;
				break;
		}
	}

	SLOGI << "Summary: " << stats.total() << " push notification(s) sent [successful = " << stats.success
	      << ", failed = " << stats.failed << "]";

	if (stats.failed > 0) {
		SLOGI << "Some push notification requests failed, execute again with --debug to debug";
	}
	if (stats.notsubmitted > 0 || stats.inprogress > 0) {
		SLOGI << "There were unsubmitted or uncompleted requests, execute again with --debug to debug";
	}

	return stats.failed;
}

int main(int argc, const char* argv[]) {
	try {
		return _main(argc, argv);
	} catch (const ExitSuccess& exception) {
		if (exception.what() != nullptr && exception.what()[0] != '\0') {
			cout << "Exit success: " << exception.what();
		}
		return EXIT_SUCCESS;
	} catch (const Exit& exception) {
		if (exception.what() != nullptr && exception.what()[0] != '\0') {
			cerr << "Error: " << exception.what() << endl;
		}
		return exception.code();
	} catch (const exception& exception) {
		cerr << "Error, caught an unexpected exception: " << exception.what() << endl;
		return EXIT_FAILURE;
	} catch (...) {
		cerr << "Error, caught an unknown exception" << endl;
		return EXIT_FAILURE;
	}
}