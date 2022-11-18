/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <list>

#include "agent.hh"

namespace flexisip {

class CallContextBase {
public:
	CallContextBase(sip_t* sip);
	bool match(Agent* ag, sip_t* sip, bool match_call_id_only = false, bool match_established = false);
	void establishDialogWith200Ok(Agent* ag, sip_t* sip);
	bool isDialogEstablished() const;
	bool isNewInvite(sip_t* sip);
	void storeNewInvite(msg_t* orig);
	void updateActivity();
	msg_t* getLastForwardedInvite() const;
	virtual void dump();
	virtual time_t getLastActivity() {
		return mLastSIPActivity;
	}
	virtual void terminate() {
	}
	virtual ~CallContextBase();
	const std::string& getCallerTag() const {
		return mCallerTag;
	}
	const std::string& getCalleeTag() const {
		return mCalleeTag;
	}
	uint32_t getViaCount() const {
		return mViaCount;
	}

private:
	su_home_t mHome;
	sip_from_t* mFrom;
	msg_t* mInvite;
	uint32_t mCallHash;
	uint32_t mInvCseq;
	uint32_t mResCseq;
	std::string mCallerTag;
	std::string mCalleeTag;
	std::string mBranch; /*of the via of the first Invite request*/
	uint32_t mViaCount;
	time_t mLastSIPActivity;
};

class CallStore {
public:
	CallStore();
	~CallStore();
	void store(const std::shared_ptr<CallContextBase>& ctx);
	std::shared_ptr<CallContextBase> find(Agent* ag, sip_t* sip, bool match_call_id_only = false);
	std::shared_ptr<CallContextBase> findEstablishedDialog(Agent* ag, sip_t* sip);
	void findAndRemoveExcept(Agent* ag,
	                         sip_t* sip,
	                         const std::shared_ptr<CallContextBase>& ctx,
	                         bool match_call_id_only = false);
	void remove(const std::shared_ptr<CallContextBase>& ctx);
	void removeAndDeleteInactives(time_t inactivityPeriod);
	void setCallStatCounters(StatCounter64* invCount, StatCounter64* invFinishedCount) {
		mCountCalls = invCount;
		mCountCallsFinished = invFinishedCount;
	}
	void dump();
	const std::list<std::shared_ptr<CallContextBase>>& getList() const {
		return mCalls;
	}
	/// Returns the number of calls registered in the CallStore.
	int size();

private:
	std::list<std::shared_ptr<CallContextBase>> mCalls;
	StatCounter64* mCountCalls;
	StatCounter64* mCountCallsFinished;
};

} // namespace flexisip