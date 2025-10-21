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

#include "fork-context-factory.hh"

#include "exceptions/bad-configuration.hh"

using namespace std;

namespace flexisip {

namespace {

// List of supported status codes to consider for forwarding calls to the voicemail server.
constexpr std::array<int, 3> kStatusCodes{408, 486, 603};

} // namespace

ForkContextFactory::ForkContextFactory(Agent* agent,
                                       const std::weak_ptr<ForkStats>& forkStats,
                                       const std::weak_ptr<InjectorListener>& injectorListener,
                                       const std::weak_ptr<ForkContextListener>& forkContextListener,
                                       const GenericStruct* moduleRouterConfig)
    : mAgent(agent), mForkStats(forkStats), mInjectorListener(injectorListener),
      mForkContextListener(forkContextListener) {
	mCallForkCfg = make_shared<ForkCallContextConfig>();
	mCallForkCfg->mForkLate = moduleRouterConfig->get<ConfigBoolean>("fork-late")->read();
	mCallForkCfg->mTreatAllErrorsAsUrgent = moduleRouterConfig->get<ConfigBoolean>("treat-all-as-urgent")->read();
	mCallForkCfg->mForkNoGlobalDecline = moduleRouterConfig->get<ConfigBoolean>("fork-no-global-decline")->read();
	mCallForkCfg->mUrgentTimeout =
	    moduleRouterConfig->get<ConfigDuration<chrono::seconds>>("call-fork-urgent-timeout")->readAndCast();
	mCallForkCfg->mDeliveryTimeout =
	    moduleRouterConfig->get<ConfigDuration<chrono::seconds>>("call-fork-timeout")->readAndCast();
	mCallForkCfg->mTreatDeclineAsUrgent = moduleRouterConfig->get<ConfigBoolean>("treat-decline-as-urgent")->read();
	mCallForkCfg->mCurrentBranchesTimeout =
	    moduleRouterConfig->get<ConfigDuration<chrono::seconds>>("call-fork-current-branches-timeout")->readAndCast();
	mCallForkCfg->mPermitSelfGeneratedProvisionalResponse =
	    moduleRouterConfig->get<ConfigBoolean>("permit-self-generated-provisional-response")->read();

	setVoicemailConfiguration(moduleRouterConfig);

	mMessageForkCfg = make_shared<ForkContextConfig>();
	mMessageForkCfg->mForkLate = moduleRouterConfig->get<ConfigBoolean>("message-fork-late")->read();
	mMessageForkCfg->mDeliveryTimeout =
	    moduleRouterConfig->get<ConfigDuration<chrono::seconds>>("message-delivery-timeout")->readAndCast();
	mMessageForkCfg->mUrgentTimeout =
	    moduleRouterConfig->get<ConfigDuration<chrono::seconds>>("message-accept-timeout")->readAndCast();
#if ENABLE_SOCI
	if (mMessageForkCfg->mForkLate && moduleRouterConfig->get<ConfigBoolean>("message-database-enabled")->read())
		mMessageForkCfg->mSaveForkMessageEnabled = true;
#endif

	mOtherForkCfg = make_shared<ForkContextConfig>();
	mOtherForkCfg->mTreatAllErrorsAsUrgent = false;
	mOtherForkCfg->mForkLate = false;
}

#if ENABLE_SOCI
void ForkContextFactory::setForkMessageDatabase(const std::weak_ptr<ForkMessageContextSociRepository>& database) {
	mForkMessageDatabase = database;
}

shared_ptr<ForkMessageContextSociRepository> ForkContextFactory::getForkMessageDatabase() const {
	return mForkMessageDatabase.lock();
}
#endif

bool ForkContextFactory::callForkLateEnabled() const {
	return mCallForkCfg->mForkLate;
}

bool ForkContextFactory::messageForkLateEnabled() const {
	return mMessageForkCfg->mForkLate;
}

bool ForkContextFactory::messageStorageInDbEnabled() const {
	return mMessageForkCfg->mSaveForkMessageEnabled;
}

void ForkContextFactory::setVoicemailConfiguration(const GenericStruct* config) {
	const auto* voicemailUriParameter = config->get<ConfigString>("voicemail-server");
	try {
		mCallForkCfg->mVoicemailServerUri = SipUri{voicemailUriParameter->read()};
	} catch (const exception&) {
		throw BadConfigurationValue{voicemailUriParameter, "invalid voicemail server URI"};
	}

	if (!mCallForkCfg->mVoicemailServerUri.empty()) {
		LOGI << "Voicemail server is [" << mCallForkCfg->mVoicemailServerUri.str() << "]";

		const auto* statusCodesParameter = config->get<ConfigStringList>("forwarding-status-codes");
		for (const auto& value : statusCodesParameter->read()) {
			try {
				const auto status = stoi(value);
				const auto predicate = [&status](const auto& code) { return code == status; };
				if (find_if(kStatusCodes.cbegin(), kStatusCodes.cend(), predicate) == kStatusCodes.cend())
					throw BadConfigurationValue{statusCodesParameter,
					                            "unsupported forwarding status code '" + value + "'"};

				mCallForkCfg->mStatusCodes.push_back(status);
			} catch (const exception& exception) {
				throw BadConfigurationValue{statusCodesParameter, "unsupported forwarding status code '" + value +
				                                                      "' (error: " + exception.what() + ")"};
			}
		}

		LOGI << "Call forwarding enabled to the voicemail server for status codes: "
		     << string_utils::join(statusCodesParameter->read(), 0, ", ");
	}
}

} // namespace flexisip