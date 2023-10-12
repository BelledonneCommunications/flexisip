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

#pragma once

#include <list>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "presence/belle-sip-using.hh"
#include "presence/presentity/presentity-manager.hh"

namespace flexisip {

namespace Xsd::Pidf {
class Presence;
}

class MapPresentityManager : public PresentityManager {
public:
	using PresentityManager::PresentityManager;

	std::string handlePublishFor(const belle_sip_uri_t* entityUri,
	                             const std::string& eTag,
	                             const std::unique_ptr<Xsd::Pidf::Presence>&& presence,
	                             int expires) override;

	std::string handlePublishRefreshedFor(const std::string& eTag, int expires) override;

	void handleLongtermPresence(const belle_sip_uri_t* entityUri,
	                            const std::shared_ptr<PresentityPresenceInformation>& originalEntity) override;

	void
	enableExtendedNotifyIfPossible(const std::shared_ptr<PresentityPresenceInformationListener>& listener,
	                               const std::shared_ptr<PresentityPresenceInformation>& presenceInfo) const override;

	std::shared_ptr<PresentityPresenceInformation> getPresenceInfo(const belle_sip_uri_t* identity) const override;
	void addPresenceInfo(const std::shared_ptr<PresentityPresenceInformation>&) override;

	std::shared_ptr<PresentityPresenceInformation> getPresenceInfo(const std::string& eTag) const override;
	void invalidateETag(const std::string& eTag) override;
	void modifyEtag(const std::string& oldEtag, const std::string& newEtag) override;
	void addEtag(const std::shared_ptr<PresentityPresenceInformation>& info, const std::string& etag) override;

	void addOrUpdateListener(std::shared_ptr<PresentityPresenceInformationListener>& listener, int expires) override;
	void addOrUpdateListeners(std::list<std::shared_ptr<PresentityPresenceInformationListener>>& listener,
	                          int expires) override;
	void removeListener(const std::shared_ptr<PresentityPresenceInformationListener>& listener) override;

	void addPresenceInfoObserver(const std::shared_ptr<PresenceInfoObserver>& observer) override;
	void removePresenceInfoObserver(const std::shared_ptr<PresenceInfoObserver>& observer) override;

private:
	std::unordered_map<std::string, std::shared_ptr<PresentityPresenceInformation>> mPresenceInformationsByEtag;
	std::unordered_map<const belle_sip_uri_t*, std::shared_ptr<PresentityPresenceInformation>> mPresenceInformations;
	std::vector<std::shared_ptr<PresenceInfoObserver>> mPresenceInfoObservers;
};

} // namespace flexisip
