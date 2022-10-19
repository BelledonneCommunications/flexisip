/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/module-router.hh"

#include "schedule-injector.hh"

using namespace std;
using namespace flexisip;
using namespace sofiasip;

void ScheduleInjector::injectRequestEvent(const std::shared_ptr<RequestSipEvent>& ev,
                                          const shared_ptr<ForkContext>& fork,
                                          const std::string& contactId) {
	auto currentWorkingPriority = fork->getMsgPriority();
	auto& injectMap = getMapFromPriority(currentWorkingPriority);
	const auto& contactMapEntry = injectMap.find(contactId);

	if (contactMapEntry == injectMap.end()) {
		// This should not happen, but we prefer to send in wrong order than not at all.
		SLOGE << "ForkContext[ " << fork.get() << "], CallID [" << ev->getMsgSip()->getCallID() << "], "
		      << "was not found in ScheduleInjector maps and is injected out of order to " << contactId;
		mModule->injectRequestEvent(ev);
		return;
	}

	auto& contactInjectContexts = contactMapEntry->second;
	for (auto it = contactInjectContexts.begin(); it != contactInjectContexts.end(); ++it) {
		if (*it == fork) {
			it->waitForInject = ev;
			if (it == contactInjectContexts.begin() &&
			    areAllHigherPriorityMapEmpty(currentWorkingPriority, contactId)) {
				startInject(currentWorkingPriority, contactInjectContexts, contactId);
			}
			return;
		}
	}
}

void ScheduleInjector::startInject(sofiasip::MsgSipPriority currentWorkingPriority,
                                   InjectListType& contactInjectContexts,
                                   const string& contactId) {
	auto it = contactInjectContexts.begin();
	while (it != contactInjectContexts.end() && it->waitForInject) {
		mModule->injectRequestEvent(it->waitForInject);
		it = contactInjectContexts.erase(it);
	}

	if (it == contactInjectContexts.end()) {
		getMapFromPriority(currentWorkingPriority).erase(contactId);
		if (currentWorkingPriority != MsgSipPriority::NonUrgent) {
			continueInjectIfNeeded(MsgSip::getPreviousPriority(currentWorkingPriority), contactId);
		}
	}
}

void ScheduleInjector::continueInjectIfNeeded(sofiasip::MsgSipPriority currentWorkingPriority,
                                              const string& contactId) {
	auto& injectMap = getMapFromPriority(currentWorkingPriority);
	const auto& contactMapEntry = injectMap.find(contactId);

	if (contactMapEntry != injectMap.end()) {
		startInject(currentWorkingPriority, contactMapEntry->second, contactId);
	} else if (currentWorkingPriority != MsgSipPriority::NonUrgent) {
		continueInjectIfNeeded(MsgSip::getPreviousPriority(currentWorkingPriority), contactId);
	}
}

void ScheduleInjector::addContext(const shared_ptr<ForkContext>& fork, const string& contactId) {
	getMapFromPriority(fork->getMsgPriority())[contactId].emplace_back(fork);
}

void ScheduleInjector::removeContext(const shared_ptr<ForkContext>& fork, const string& contactId) {
	const auto currentPriority = fork->getMsgPriority();
	auto& injectMap = getMapFromPriority(currentPriority);

	const auto& contactMapEntry = injectMap.find(contactId);
	if (contactMapEntry == injectMap.end()) {
		return;
	}

	auto& contactInjectContexts = contactMapEntry->second;
	// Reverse search and erase
	const auto& reverseIt = find_if(contactInjectContexts.rbegin(), contactInjectContexts.rend(),
	                                [&fork](const auto& i) { return i == fork; });
	if (reverseIt != contactInjectContexts.rend()) {
		contactInjectContexts.erase(std::next(reverseIt).base()); // trick to erase from a reverse_iterator
		if (areAllHigherPriorityMapEmpty(currentPriority, contactId)) {
			startInject(currentPriority, contactInjectContexts, contactId);
		} else if (contactInjectContexts.empty()) {
			injectMap.erase(contactId);
		}
	}
}

ScheduleInjector::InjectContextMap& ScheduleInjector::getMapFromPriority(sofiasip::MsgSipPriority msgSipPriority) {
	switch (msgSipPriority) {
		case MsgSipPriority::NonUrgent:
			return mNonUrgentInjectContexts;
		case MsgSipPriority::Normal:
			return mNormalInjectContexts;
		case MsgSipPriority::Urgent:
			return mUrgentInjectContexts;
		case MsgSipPriority::Emergency:
			return mEmergencyInjectContexts;
		default:
			throw invalid_argument(
			    "ScheduleInjector::getMapFromPriority - sofiasip::MsgSipPriority value is not valid ["s +
			    to_string(static_cast<int>(msgSipPriority)) + "]");
	}
}

bool ScheduleInjector::areAllHigherPriorityMapEmpty(sofiasip::MsgSipPriority msgSipPriority,
                                                    const string& contactId) const {
	if (msgSipPriority == MsgSipPriority::Emergency) {
		return true;
	}

	auto result = mEmergencyInjectContexts.find(contactId) == mEmergencyInjectContexts.end();
	if (msgSipPriority == MsgSipPriority::Urgent) {
		return result;
	}

	result = result && mUrgentInjectContexts.find(contactId) == mUrgentInjectContexts.end();
	if (msgSipPriority == MsgSipPriority::Normal) {
		return result;
	}

	// MsgSipPriority::NonUrgent
	return result && mNormalInjectContexts.find(contactId) == mNormalInjectContexts.end();
}
