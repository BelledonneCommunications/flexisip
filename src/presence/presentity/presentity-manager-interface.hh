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

#pragma once

#include <memory>
#include <string>

#include "presence/observers/presence-info-observer.hh"
#include "presence/presentity/presentity-presence-information.hh"

namespace flexisip {

namespace Xsd::Pidf {
class Presence;
}

class PresentityManagerInterface {
public:
	explicit PresentityManagerInterface(belle_sip_stack_t* stack) : mStack(stack){};
	virtual ~PresentityManagerInterface() = default;

	virtual std::string handlePublishFor(const belle_sip_uri_t* entityUri,
	                                     const std::string& eTag,
	                                     const std::unique_ptr<Xsd::Pidf::Presence>&& presence,
	                                     int expires) = 0;

	virtual std::string handlePublishRefreshedFor(const std::string& eTag, int expires) = 0;

	virtual void handleLongtermPresence(const belle_sip_uri_t* entityUri,
	                                    const std::shared_ptr<PresentityPresenceInformation>& originalEntity) = 0;

	virtual void
	enableExtendedNotifyIfPossible(const std::shared_ptr<PresentityPresenceInformationListener>& listener,
	                               const std::shared_ptr<PresentityPresenceInformation>& presenceInfo) const = 0;
	//////// Presentities by uris
	virtual std::shared_ptr<PresentityPresenceInformation> getPresenceInfo(const belle_sip_uri_t* identity) const = 0;
	/**
	 * @throw in case an entry already exist for this entity;
	 */
	virtual void addPresenceInfo(const std::shared_ptr<PresentityPresenceInformation>&) = 0;

	//////// Presentities by etag
	virtual std::shared_ptr<PresentityPresenceInformation> getPresenceInfo(const std::string& eTag) const = 0;
	virtual void invalidateETag(const std::string& eTag) = 0;
	virtual void modifyEtag(const std::string& oldEtag, const std::string& newEtag) = 0;
	virtual void addEtag(const std::shared_ptr<PresentityPresenceInformation>& info, const std::string& etag) = 0;

	//////// Presentities listeners
	// fixme splitting into function add and function update will avoid to iterate on subscriber list
	virtual void addOrUpdateListener(std::shared_ptr<PresentityPresenceInformationListener>& listener, int expires) = 0;
	virtual void addOrUpdateListener(std::shared_ptr<PresentityPresenceInformationListener>& listener) {
		addOrUpdateListener(listener, -1);
	}

	virtual void addOrUpdateListeners(std::list<std::shared_ptr<PresentityPresenceInformationListener>>& listerner,
	                                  int expires) = 0;
	virtual void addOrUpdateListeners(std::list<std::shared_ptr<PresentityPresenceInformationListener>>& listener) {
		addOrUpdateListeners(listener, -1);
	};

	virtual void removeListener(const std::shared_ptr<PresentityPresenceInformationListener>& listener) = 0;

	//////// Observer
	virtual void addPresenceInfoObserver(const std::shared_ptr<PresenceInfoObserver>& observer) = 0;
	virtual void removePresenceInfoObserver(const std::shared_ptr<PresenceInfoObserver>& observer) = 0;

protected:
	belle_sip_stack_t* getStack() {
		return mStack;
	}

private:
	belle_sip_stack_t* mStack;
};

} // namespace flexisip
