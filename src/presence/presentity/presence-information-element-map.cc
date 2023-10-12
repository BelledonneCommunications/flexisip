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

#include "presence-information-element-map.hh"

#include "presence/presence-server.hh"
#include "presentity-presence-information.hh"

using namespace std;
namespace flexisip {

std::shared_ptr<PresenceInformationElementMap>
PresenceInformationElementMap::make(belle_sip_main_loop_t* belleSipMainloop,
                                    const std::weak_ptr<PresentityPresenceInformation>& initialParent) {
	return std::shared_ptr<PresenceInformationElementMap>(
	    new PresenceInformationElementMap(belleSipMainloop, initialParent));
}

PresenceInformationElementMap::PresenceInformationElementMap(
    belle_sip_main_loop_t* belleSipMainloop, const weak_ptr<PresentityPresenceInformation>& initialParent)
    : mBelleSipMainloop(belleSipMainloop) {
	mParents.push_back(initialParent);
	mListeners.push_back(initialParent);
};

void PresenceInformationElementMap::removeByEtag(const std::string& eTag, bool notifyOther) {
	auto it = mInformationElements.find(eTag);
	if (it != mInformationElements.end()) {
		mInformationElements.erase(it);
		setupLastActivity();
		if (notifyOther) {
			notifyListeners();
		}
	} else SLOGD << "No tuples found for etag [" << eTag << "]";
}

void PresenceInformationElementMap::setupLastActivity() {
	mLastActivity = std::chrono::system_clock::now();
	mLastActivityTimer = belle_sip_main_loop_create_cpp_timeout(
	    mBelleSipMainloop,
	    [weakThis = weak_from_this()](unsigned int) {
		    if (auto sharedThis = weakThis.lock()) {
			    sharedThis->mLastActivity = nullopt;
		    }
		    return BELLE_SIP_STOP;
	    },
	    PresenceServer::sLastActivityRetentionMs, "Last activity retention timer");
}

void PresenceInformationElementMap::emplace(const std::string& eTag,
                                            std::unique_ptr<PresenceInformationElement>&& element) {
	if (mInformationElements.try_emplace(eTag, std::move(element)).second) {
		notifyListeners();
	}
}

bool PresenceInformationElementMap::isEtagPresent(const std::string& eTag) {
	return mInformationElements.find(eTag) != mInformationElements.end();
}

void PresenceInformationElementMap::mergeInto(const std::shared_ptr<PresenceInformationElementMap>& otherMap,
                                              bool notifyOther) {
	otherMap->mInformationElements.merge(mInformationElements);
	otherMap->mListeners.insert(end(otherMap->mListeners), begin(mListeners), end(mListeners));
	otherMap->mParents.insert(end(otherMap->mParents), begin(mParents), end(mParents));

	if (notifyOther) {
		otherMap->notifyListeners();
	}
}

void PresenceInformationElementMap::notifyListeners() {
	for (auto it = mListeners.begin(); it != mListeners.end();) {
		if (auto sharedListener = (*it).lock()) {
			sharedListener->onMapUpdate();
			++it;
		} else {
			it = mListeners.erase(it);
		}
	}
}

shared_ptr<PresentityPresenceInformationListener>
PresenceInformationElementMap::findPresenceInfoListener(const shared_ptr<PresentityPresenceInformation>& info) {
	for (auto it = mParents.begin(); it != mParents.end();) {
		auto parent = it->lock();
		if (!parent) {
			it = mParents.erase(it);
			continue;
		}
		const auto& listener = parent->findPresenceInfoListener(info, true);
		if (listener) {
			return listener;
		}
		it++;
	}

	return nullptr;
}

size_t PresenceInformationElementMap::getNumberOfListeners() {
	size_t numberOfListeners = 0;
	for (auto it = mParents.begin(); it != mParents.end();) {
		auto parent = it->lock();
		if (parent == nullptr) {
			it = mParents.erase(it);
			continue;
		}
		numberOfListeners += parent->getNumberOfListeners();
		it++;
	}

	return numberOfListeners;
}

} /* namespace flexisip */
