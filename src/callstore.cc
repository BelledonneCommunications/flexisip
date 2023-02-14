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

#include <algorithm>
#include <functional>

#include "callstore.hh"

using namespace std;
using namespace flexisip;

CallContextBase::CallContextBase(sip_t *sip) {
	su_home_init(&mHome);
	mFrom = sip_from_dup(&mHome, sip->sip_from);
	mCallHash = sip->sip_call_id->i_hash;
	mInvCseq = sip->sip_cseq->cs_seq;
	mResCseq = (uint32_t)-1;
	mInvite = NULL;
	mCallerTag = sip->sip_from->a_tag;
	mViaCount = 0;
	sip_via_t *via;
	for (via = sip->sip_via; via != NULL; via = via->v_next)
		++mViaCount;
	via = sip->sip_via;
	if (via && via->v_branch) {
		mBranch = via->v_branch;
	}
	updateActivity();
	LOGD("CallContext %p created", this);
}


void CallContextBase::updateActivity() {
	mLastSIPActivity = getCurrentTime();
}

void CallContextBase::establishDialogWith200Ok([[maybe_unused]] Agent *ag, sip_t *sip) {
	if (sip->sip_status->st_status >= 200 && sip->sip_status->st_status < 300 && mCalleeTag.empty()) {
		LOGD("Dialog is established");
		if (sip->sip_to->a_tag)
			mCalleeTag = sip->sip_to->a_tag;
	}
}

bool CallContextBase::isDialogEstablished() const {
	return mCalleeTag.size() > 0;
}

bool CallContextBase::match(Agent *ag, sip_t *sip, bool match_call_id_only, bool match_established) {
	if (sip->sip_call_id == NULL)
		return false;
	if (sip->sip_from->a_tag == NULL)
		return false;

	if (sip->sip_call_id->i_hash == mCallHash) {
		if (sip->sip_request == NULL && (sip->sip_status->st_status > 100 && sip->sip_status->st_status < 300)) {
			if (!match_established && mCalleeTag.empty() && strcmp(mCallerTag.c_str(), sip->sip_from->a_tag) == 0) {
				/*not yet established dialog*/
				// check the via branch to know if that response can correspond to the original INVITE
				// and possibly establish the dialog.
				sip_via_t *respvia = ag->getNextVia(sip);
				if (respvia && respvia->v_branch) {
					if (strcmp(respvia->v_branch, mBranch.c_str()) == 0) {
						LOGD("Found CallContext matching response");
						establishDialogWith200Ok(ag, sip);
						return true;
					}
				}
			}
		}
		/*otherwise the to tag must be set (dialog established)*/
		if (sip->sip_to && sip->sip_to->a_tag) {
			// note: in case of re-INVITE, from and to tags might be inverted with mCallerTag and mCalleeTag
			if ((strcmp(mCallerTag.c_str(), sip->sip_from->a_tag) == 0 &&
				 strcmp(mCalleeTag.c_str(), sip->sip_to->a_tag) == 0) ||
				(strcmp(mCallerTag.c_str(), sip->sip_to->a_tag) == 0 &&
				 strcmp(mCalleeTag.c_str(), sip->sip_from->a_tag) == 0)) {
				LOGD("Found exact dialog");
				return true;
			}
		}
		if (match_call_id_only)
			return true;
	}
	return false;
}

bool CallContextBase::isNewInvite(sip_t *invite) {
	return invite->sip_cseq->cs_seq != mInvCseq;
}

void CallContextBase::storeNewInvite(msg_t *msg) {
	sip_t *sip = (sip_t *)msg_object(msg);
	// serialize the message before copying it otherwise we might miss some content
	msg_serialize(msg, (msg_pub_t *)sip);
	mInvCseq = sip->sip_cseq->cs_seq;
	if (mInvite != NULL) {
		msg_destroy(mInvite);
	}
	mInvite = msg_copy(msg);
	updateActivity();
}

msg_t *CallContextBase::getLastForwardedInvite() const {
	return mInvite;
}

void CallContextBase::dump() {
	LOGD("Call id %u", mCallHash);
}

CallContextBase::~CallContextBase() {
	su_home_deinit(&mHome);
	LOGD("CallContext %p with id %u destroyed.", this, mCallHash);
	if (mInvite != NULL) {
		msg_destroy(mInvite);
	}
}

CallStore::CallStore() : mCountCalls(NULL), mCountCallsFinished(NULL) {
}

CallStore::~CallStore() {
}

void CallStore::store(const shared_ptr<CallContextBase> &ctx) {
	if (mCountCalls)
		++(*mCountCalls);
	mCalls.push_back(ctx);
}

shared_ptr<CallContextBase> CallStore::find(Agent *ag, sip_t *sip, bool match_call_id_only) {
	for (auto it = mCalls.begin(); it != mCalls.end(); ++it) {
		if ((*it)->match(ag, sip, match_call_id_only))
			return *it;
	}
	return shared_ptr<CallContextBase>();
}

shared_ptr<CallContextBase> CallStore::findEstablishedDialog(Agent *ag, sip_t *sip) {
	for (auto it = mCalls.begin(); it != mCalls.end(); ++it) {
		if ((*it)->match(ag, sip, false, true))
			return *it;
	}
	return shared_ptr<CallContextBase>();
}

void CallStore::findAndRemoveExcept(Agent *ag, sip_t *sip, const shared_ptr<CallContextBase> &ctx, bool stateful) {
	int removed = 0;
	for (auto it = mCalls.begin(); it != mCalls.end();) {
		if (*it != ctx && (*it)->match(ag, sip, stateful)) {
			if (mCountCallsFinished)
				++(*mCountCallsFinished);
			LOGD("CallStore::findAndRemoveExcept() removing CallContext %p", ctx.get());
			it = mCalls.erase(it);
			++removed;
		} else
			++it;
	}
	LOGD("Removed %d maching call contexts from store", removed);
}

void CallStore::remove(const shared_ptr<CallContextBase> &ctx) {
	auto it = std::find(mCalls.begin(), mCalls.end(), ctx);
	if (it != mCalls.end()) {
		LOGD("CallStore::remove() removing CallContext %p", ctx.get());
		if (mCountCallsFinished)
			++(*mCountCallsFinished);
		(*it)->terminate();
		mCalls.erase(it);
	}
}

void CallStore::removeAndDeleteInactives(time_t inactivityPeriod) {
	time_t cur = getCurrentTime();
	for (auto it = mCalls.begin(); it != mCalls.end();) {
		if ((*it)->getLastActivity() + inactivityPeriod < cur) {
			LOGD("CallStore::removeAndDeleteInactives() removing CallContext %p", (*it).get());
			if (mCountCallsFinished)
				++(*mCountCallsFinished);
			(*it)->terminate();
			it = mCalls.erase(it);
		} else
			++it;
	}
}

void CallStore::dump() {
	for_each(mCalls.begin(), mCalls.end(), bind(&CallContextBase::dump, placeholders::_1));
}

int CallStore::size() {
	return mCalls.size();
}
