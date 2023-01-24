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

#include "schedule-injector.hh"

#include "inject-context.hh"

using namespace std;
using namespace flexisip;
using namespace sofiasip;

void ScheduleInjector::injectRequestEvent(const std::shared_ptr<RequestSipEvent>& ev,
                                          const shared_ptr<ForkContext>& fork,
                                          const std::string& contactId) {
	SLOGT << "ScheduleInjector::injectRequestEvent. ForkContext[" << fork->getPtrForEquality() << "]";

	auto currentWorkingPriority = fork->getMsgPriority();
	auto& injectMap = getMapFromPriority(currentWorkingPriority);
	const auto& contactMapEntry = injectMap.find(contactId);

	if (contactMapEntry == injectMap.end()) {
		// This should not happen, but we prefer to send in wrong order than not at all.
		SLOGE << "ScheduleInjector::injectRequestEvent. ForkContext[" << fork->getPtrForEquality() << "], CallID ["
		      << ev->getMsgSip()->getCallID() << "]. No map found. Injected out of order to " << contactId;
		mModule->injectRequestEvent(ev);
		return;
	}

	auto& contactInjectContexts = contactMapEntry->second;

	const auto& it = find_if(contactInjectContexts.begin(), contactInjectContexts.end(),
	                         [&fork](const auto& i) { return i.isEqual(fork); });
	if (it != contactInjectContexts.end()) {
		it->waitForInject = ev;
	} else {
		// This should not happen, but we prefer to send in wrong order than not at all.
		SLOGE << "ScheduleInjector::injectRequestEvent. ForkContext[" << fork->getPtrForEquality() << "], CallID ["
		      << ev->getMsgSip()->getCallID() << "], was not found in and is injected out of order to " << contactId;
		mModule->injectRequestEvent(ev);
	}

	startInject(contactId);
}

void ScheduleInjector::startInject(const std::string& contactId) {
	for (auto priority : MsgSip::getOrderedPrioritiesList()) {
		auto& injectMap = getMapFromPriority(priority);

		const auto& contactMapEntry = injectMap.find(contactId);
		if (contactMapEntry == injectMap.end()) {
			continue;
		}

		auto& contactInjectContexts = contactMapEntry->second;
		auto it = contactInjectContexts.begin();
		while (it != contactInjectContexts.end()) {
			if (it->waitForInject) {
				mModule->injectRequestEvent(it->waitForInject);
				it = contactInjectContexts.erase(it);
			} else if (it->isExpired()) {
				SLOGE << "ScheduleInjector::startInject. ForkContext[" << it->mFork->getPtrForEquality()
				      << "], is expired and is not waiting for inject, removing.";
				it = contactInjectContexts.erase(it);
			} else {
				break;
			}
		}
		if (it != contactInjectContexts.end()) {
			break;
		}
	}
}

void ScheduleInjector::addContext(const shared_ptr<ForkContext>& fork, const string& contactId) {
	SLOGT << "ScheduleInjector::addContext. ForkContext[" << fork->getPtrForEquality() << "]";
	startInject(contactId);
	getMapFromPriority(fork->getMsgPriority())[contactId].emplace_back(fork);
}

void ScheduleInjector::addContext(const vector<shared_ptr<ForkContext>>& forks, const string& contactId) {
	startInject(contactId);
	for (const auto& fork : forks) {
		SLOGT << "ScheduleInjector::addContext. ForkContext[" << fork->getPtrForEquality() << "]";
		getMapFromPriority(fork->getMsgPriority())[contactId].emplace_back(fork);
	}
}

void ScheduleInjector::removeContext(const shared_ptr<ForkContext>& fork, const string& contactId) {
	SLOGT << "ScheduleInjector::removeContext. ForkContext[" << fork->getPtrForEquality() << "]";
	const auto currentPriority = fork->getMsgPriority();
	auto& injectMap = getMapFromPriority(currentPriority);

	const auto& contactMapEntry = injectMap.find(contactId);
	if (contactMapEntry != injectMap.end()) {
		auto& contactInjectContexts = contactMapEntry->second;
		const auto& it = find_if(contactInjectContexts.begin(), contactInjectContexts.end(),
		                         [&fork](const auto& i) { return i.isEqual(fork); });
		if (it != contactInjectContexts.end()) {
			contactInjectContexts.erase(it);
		}
	}

	startInject(contactId);
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
