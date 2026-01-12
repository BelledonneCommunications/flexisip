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

#include "presentity-manager.hh"

#include <belle-sip/belle-sip.h>

#include "flexisip/logmanager.hh"

#include "exceptions/presence-server.hh"
#include "presence/bellesip-signaling-exception.hh"
#include "presence/observers/presence-info-observer.hh"
#include "presentity-presence-information-listener.hh"
#include "presentity-presence-information.hh"
#include "xml/pidf+xml.hh"

namespace flexisip {
using namespace std;

void PresentityManager::addPresenceInfo(const shared_ptr<PresentityPresenceInformation>& presenceInfo) {
	if (getPresenceInfo(presenceInfo->getEntity())) {
		stringstream message{};
		message << "presence information element already exists for " << presenceInfo;
		throw PresenceServerException{message.str()};
	}

	mPresenceInformations[presenceInfo->getEntity()] = presenceInfo;
}

shared_ptr<PresentityPresenceInformation> PresentityManager::getPresenceInfo(const belle_sip_uri_t* identity) const {
	auto presenceEntityInformationIt = mPresenceInformations.find(identity);
	return (presenceEntityInformationIt == mPresenceInformations.end()) ? nullptr : presenceEntityInformationIt->second;
}

shared_ptr<PresentityPresenceInformation> PresentityManager::getPresenceInfo(const std::string& eTag) const {
	auto presenceInformationsByEtagIt = mPresenceInformationsByEtag.find(eTag);
	return (presenceInformationsByEtagIt == mPresenceInformationsByEtag.end()) ? nullptr
	                                                                           : presenceInformationsByEtagIt->second;
}

void PresentityManager::invalidateETag(const string& eTag) {
	auto presenceInformationsByEtagIt = mPresenceInformationsByEtag.find(eTag);
	if (presenceInformationsByEtagIt != mPresenceInformationsByEtag.end()) {
		if (const shared_ptr<PresentityPresenceInformation> presenceInfo = presenceInformationsByEtagIt->second;
		    presenceInfo->canBeSafelyDeleted()) {
			LOGD << "Presentity [" << *presenceInfo << "] no longer referenced by any SUBSCRIBE nor PUBLISH, removing";
			mPresenceInformations.erase(presenceInfo->getEntity());
		}
		mPresenceInformationsByEtag.erase(presenceInformationsByEtagIt);
		LOGD << "Etag manager size [" << mPresenceInformationsByEtag.size() << "]";
	}
}
void PresentityManager::modifyEtag(const string& oldEtag, const string& newEtag) {
	auto presenceInformationsByEtagIt = mPresenceInformationsByEtag.find(oldEtag);
	if (presenceInformationsByEtagIt == mPresenceInformationsByEtag.end())
		throw PresenceServerException{"unknown Etag [" + oldEtag + "]"};
	mPresenceInformationsByEtag[newEtag] = presenceInformationsByEtagIt->second;
	mPresenceInformationsByEtag.erase(oldEtag);
}

void PresentityManager::addEtag(const shared_ptr<PresentityPresenceInformation>& info, const string& etag) {
	auto presenceInformationsByEtagIt = mPresenceInformationsByEtag.find(etag);
	if (presenceInformationsByEtagIt != mPresenceInformationsByEtag.end()) {
		throw PresenceServerException{"already existing ETag [" + etag + "] (use modifyEtag() instead)"};
	}
	mPresenceInformationsByEtag[etag] = info;
	LOGD << "ETag manager size [" << mPresenceInformationsByEtag.size() << "]";
}

void PresentityManager::addOrUpdateListener(shared_ptr<PresentityPresenceInformationListener>& listener, int expires) {
	auto presenceInfo = getPresenceInfo(listener->getPresentityUri());

	if (!presenceInfo) {
		/*no information available yet, but creating entry to be able to register subscribers*/
		presenceInfo = PresentityPresenceInformation::make(listener->getPresentityUri(), *this,
		                                                   belle_sip_stack_get_main_loop(getStack()), mPresenceStats,
		                                                   mMaxElementsByEntity);
		LOGD << "New Presentity [" << *presenceInfo << "] created from SUBSCRIBE";
		addPresenceInfo(presenceInfo);
	}

	// notify observers that a listener is added or updated
	for (const auto& observer : mPresenceInfoObservers) {
		observer->onListenerEvent(presenceInfo);
	}

	presenceInfo->addListenerIfNecessary(listener);
	enableExtendedNotifyIfPossible(listener, presenceInfo);

	if (expires > 0) presenceInfo->addOrUpdateListener(listener, expires);
	else presenceInfo->addOrUpdateListener(listener);
}

void PresentityManager::enableExtendedNotifyIfPossible(
    const std::shared_ptr<PresentityPresenceInformationListener>& listener,
    const std::shared_ptr<PresentityPresenceInformation>& presenceInfo) const {
	if (!listener->extendedNotifyEnabled()) {
		auto toPresenceInfo = getPresenceInfo(listener->getTo());
		if (toPresenceInfo) {
			auto toListener = toPresenceInfo->findPresenceInfoListener(presenceInfo);
			if (toListener != nullptr) {
				LOGD << "Listener [" << toListener.get() << "] on [" << *toPresenceInfo
				     << "] already exists, enabling extended notification";
				// both listener->getPresentityUri() and listener->getTo() are subscribed each other
				listener->enableExtendedNotify(true);   // allow listener to received extended notification
				toListener->enableExtendedNotify(true); // but also toListener
				toListener->onInformationChanged(*toPresenceInfo, true); // to triger notify
			}
		}
	} else LOGI << "Extended presence information forbidden or not available for listener [" << listener << "]";
}

void PresentityManager::addOrUpdateListeners(list<shared_ptr<PresentityPresenceInformationListener>>& listeners,
                                             int expires) {
	list<shared_ptr<PresentityPresenceInformation>> presenceInfos{};
	for (auto& listener : listeners) {
		auto presenceInfo = getPresenceInfo(listener->getPresentityUri());
		if (!presenceInfo) {
			/*no information available yet, but creating entry to be able to register subscribers*/
			presenceInfo = PresentityPresenceInformation::make(listener->getPresentityUri(), *this,
			                                                   belle_sip_stack_get_main_loop(getStack()),
			                                                   mPresenceStats, mMaxElementsByEntity);
			LOGD << "New Presentity [" << *presenceInfo << "] created from SUBSCRIBE";
			addPresenceInfo(presenceInfo);
		}

		presenceInfo->addListenerIfNecessary(listener);
		if (!listener->extendedNotifyEnabled()) {
			auto toPresenceInfo = getPresenceInfo(listener->getTo());
			if (toPresenceInfo) {
				auto toListener = toPresenceInfo->findPresenceInfoListener(presenceInfo);
				if (toListener != nullptr) {
					// both listener->getPresentityUri() and listener->getTo() are subscribed each other
					LOGD << "Listener [" << toListener.get() << "] on [" << *toPresenceInfo
					     << "] already exists, enabling extended notification";
					listener->enableExtendedNotify(true);   // allow listener to received extended notification
					toListener->enableExtendedNotify(true); // but also toListener
					toListener->onInformationChanged(*toPresenceInfo, true); // to triger notify
				}
			}
		} else LOGI << "Extended presence information forbidden or not available for listener [" << listener << "]";
		if (expires > 0) presenceInfo->addOrUpdateListener(listener, expires);
		else presenceInfo->addOrUpdateListener(listener);

		presenceInfos.push_back(presenceInfo);
	}

	// notify observers that a listener is added or updated
	for (auto& listener : mPresenceInfoObservers) {
		listener->onListenerEvents(presenceInfos);
	}
}
void PresentityManager::removeListener(const shared_ptr<PresentityPresenceInformationListener>& listener) {
	const shared_ptr<PresentityPresenceInformation> presenceInfo = getPresenceInfo(listener->getPresentityUri());
	if (presenceInfo) {
		presenceInfo->removeListener(listener);
		if (presenceInfo->canBeSafelyDeleted()) {
			LOGD << "Presentity [" << *presenceInfo << "] no longer referenced by any SUBSCRIBE nor PUBLISH, removing";
			mPresenceInformations.erase(presenceInfo->getEntity());
		}
	} else
		LOGI << "No presence info for this entity [" << listener->getPresentityUri() << "]/[" << hex << (long)&listener
		     << "]";
}

void PresentityManager::addPresenceInfoObserver(const shared_ptr<PresenceInfoObserver>& observer) {
	mPresenceInfoObservers.push_back(observer);
}

void PresentityManager::removePresenceInfoObserver(const shared_ptr<PresenceInfoObserver>& listener) {
	auto it = find(mPresenceInfoObservers.begin(), mPresenceInfoObservers.end(), listener);
	if (it != mPresenceInfoObservers.end()) {
		mPresenceInfoObservers.erase(it);
	} else {
		LOGI << "No such listener " << listener << " registered, ignoring";
	}
}

string PresentityManager::handlePublishFor(const belle_sip_uri_t* entityUri,
                                           const std::string& eTag,
                                           const std::unique_ptr<Xsd::Pidf::Presence>&& presence,
                                           int expires) {
	shared_ptr<PresentityPresenceInformation> presenceInfo;
	if (!(presenceInfo = getPresenceInfo(entityUri))) {
		presenceInfo = PresentityPresenceInformation::make(entityUri, *this, belle_sip_stack_get_main_loop(getStack()),
		                                                   mPresenceStats, mMaxElementsByEntity);
		LOGD << "New Presentity [" << *presenceInfo << "] created from PUBLISH";
		addPresenceInfo(presenceInfo);
	} else {
		LOGD << "Presentity [" << *presenceInfo << "] found";
	}
	auto person = presence->getPerson().present() ? &presence->getPerson().get() : nullptr;
	return eTag.empty() ? presenceInfo->putTuples(presence->getTuple(), person, expires)
	                    : presenceInfo->updateTuples(presence->getTuple(), person, eTag, expires);
}

std::string PresentityManager::handlePublishRefreshedFor(const string& eTag, int expires) {
	const auto& presenceInfo = getPresenceInfo(eTag);
	if (expires == 0) {
		if (presenceInfo) {
			presenceInfo->removeTuplesForEtag(eTag);
		} /*else already expired*/
		invalidateETag(eTag);
		return eTag;
	} else {
		if (presenceInfo) {
			return presenceInfo->refreshTuplesForEtag(eTag, expires);
		} else {
			throw BelleSipSignalingException{400, belle_sip_header_create("Warning", "Unknown ETag")};
		}
	}
}

void PresentityManager::handleLongtermPresence(const belle_sip_uri_t* entityUri,
                                               const std::shared_ptr<PresentityPresenceInformation>& originalEntity) {
	shared_ptr<PresentityPresenceInformation> presenceInfo;
	if (!(presenceInfo = getPresenceInfo(entityUri))) {
		presenceInfo = PresentityPresenceInformation::make(entityUri, *this, belle_sip_stack_get_main_loop(getStack()),
		                                                   mPresenceStats, mMaxElementsByEntity);
		LOGD << "New Presentity [" << *presenceInfo << "] created from LongTerm Presence, linking with "
		     << *originalEntity;
		addPresenceInfo(presenceInfo);
		presenceInfo->linkTo(originalEntity);
	} else {
		LOGD << "Presentity [" << *presenceInfo << "] found, linking with " << originalEntity;
		originalEntity->linkTo(presenceInfo);
	}
}

} // namespace flexisip