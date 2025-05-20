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

using namespace std;

namespace flexisip {

ForkContextFactory::ForkContextFactory(Agent* agent,
                                       const std::weak_ptr<ForkStats>& forkStats,
                                       const std::weak_ptr<InjectorListener>& injectorListener,
                                       const std::weak_ptr<ForkContextListener>& forkContextListener,
                                       const GenericStruct* moduleRouterConfig)
    : mAgent(agent), mForkStats(forkStats), mInjectorListener(injectorListener),
      mForkContextListener(forkContextListener) {
	mCallForkCfg = make_shared<ForkContextConfig>();
	mCallForkCfg->mForkLate = moduleRouterConfig->get<ConfigBoolean>("fork-late")->read();
	mCallForkCfg->mTreatAllErrorsAsUrgent = moduleRouterConfig->get<ConfigBoolean>("treat-all-as-urgent")->read();
	mCallForkCfg->mForkNoGlobalDecline = moduleRouterConfig->get<ConfigBoolean>("fork-no-global-decline")->read();
	mCallForkCfg->mUrgentTimeout =
	    moduleRouterConfig->get<ConfigDuration<chrono::seconds>>("call-fork-urgent-timeout")->readAndCast();
	mCallForkCfg->mPushResponseTimeout =
	    moduleRouterConfig->get<ConfigDuration<chrono::seconds>>("call-push-response-timeout")->readAndCast();
	mCallForkCfg->mDeliveryTimeout =
	    moduleRouterConfig->get<ConfigDuration<chrono::seconds>>("call-fork-timeout")->readAndCast().count();
	mCallForkCfg->mTreatDeclineAsUrgent = moduleRouterConfig->get<ConfigBoolean>("treat-decline-as-urgent")->read();
	mCallForkCfg->mCurrentBranchesTimeout =
	    moduleRouterConfig->get<ConfigDuration<chrono::seconds>>("call-fork-current-branches-timeout")
	        ->readAndCast()
	        .count();
	mCallForkCfg->mPermitSelfGeneratedProvisionalResponse =
	    moduleRouterConfig->get<ConfigBoolean>("permit-self-generated-provisional-response")->read();

	mMessageForkCfg = make_shared<ForkContextConfig>();
	mMessageForkCfg->mForkLate = moduleRouterConfig->get<ConfigBoolean>("message-fork-late")->read();
	mMessageForkCfg->mDeliveryTimeout =
	    moduleRouterConfig->get<ConfigDuration<chrono::seconds>>("message-delivery-timeout")->readAndCast().count();
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

bool ForkContextFactory::callForkLateEnabled() const {
	return mCallForkCfg->mForkLate;
}

bool ForkContextFactory::messageForkLateEnabled() const {
	return mMessageForkCfg->mForkLate;
}

bool ForkContextFactory::messageStorageInDbEnabled() const {
	return mMessageForkCfg->mSaveForkMessageEnabled;
}

} // namespace flexisip