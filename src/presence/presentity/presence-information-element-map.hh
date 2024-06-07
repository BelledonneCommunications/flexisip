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

#include <memory>
#include <string>

#include "presence/presentity/presence-information-element.hh"
#include "presence/presentity/presentity-presence-information-listener.hh"
#include "utils/limited-unordered-map.hh"

namespace flexisip {
class ElementMapListener {
public:
	virtual ~ElementMapListener() = default;

	virtual void onMapUpdate() = 0;
};

class PresenceInformationElementMap : public std::enable_shared_from_this<PresenceInformationElementMap> {
public:
	using ElementMapType = LimitedUnorderedMap<std::string /*Etag*/, std::unique_ptr<PresenceInformationElement>>;

	template <typename... Args>
	static std::shared_ptr<PresenceInformationElementMap> make(Args&&... args) {
		return std::shared_ptr<PresenceInformationElementMap>(
		    new PresenceInformationElementMap(std::forward<Args>(args)...));
	}

	virtual ~PresenceInformationElementMap();

	void emplace(const std::string& eTag, std::unique_ptr<PresenceInformationElement>&& element);
	bool isEtagPresent(const std::string& eTag);
	void removeByEtag(const std::string& eTag, bool notifyOther = true);

	template <typename T>
	void refreshElement(const std::string& oldEtag, const std::string& newEtag, T&& timer) {
		if (auto it = mInformationElements.find(oldEtag); it != mInformationElements.end()) {
			auto elementToRefresh = std::move(it->second);
			mInformationElements.erase(it);
			elementToRefresh->setEtag(newEtag);
			elementToRefresh->setExpiresTimer(std::move(timer));
			emplace(newEtag, std::move(elementToRefresh));
			setupLastActivity();
		} else {
			throw FLEXISIP_EXCEPTION << "Unknown eTag [" << oldEtag << "] in map.";
		}
	}

	std::shared_ptr<PresentityPresenceInformationListener>
	findPresenceInfoListener(const std::shared_ptr<PresentityPresenceInformation>& info);

	/**
	 * WARNING : modify and emptied calling map
	 */
	void mergeInto(const std::shared_ptr<PresenceInformationElementMap>& otherMap, bool notifyOther);

	void notifyListeners();

	size_t getNumberOfListeners();

	const ElementMapType& getElements() const {
		return mInformationElements;
	};

	size_t getSize() const {
		return mInformationElements.size();
	};

	bool isEmpty() const {
		return mInformationElements.empty();
	};

	const std::optional<std::chrono::system_clock::time_point>& getLastActivity() const {
		return mLastActivity;
	};

private:
	explicit PresenceInformationElementMap(belle_sip_main_loop_t* belleSipMainloop,
	                                       const std::weak_ptr<PresentityPresenceInformation>& initialParent,
	                                       const std::weak_ptr<StatPair>& countPresenceElementMap,
	                                       size_t maximumElementsNumber);

	void setupLastActivity();

	belle_sip_main_loop_t* mBelleSipMainloop;
	ElementMapType mInformationElements;
	std::vector<std::weak_ptr<ElementMapListener>> mListeners{};
	std::optional<std::chrono::system_clock::time_point> mLastActivity = std::nullopt;
	BelleSipSourcePtr mLastActivityTimer = nullptr;

	mutable std::list<std::weak_ptr<PresentityPresenceInformation>> mParents;
	const std::weak_ptr<StatPair> mCountPresenceElementMap;
};

} /* namespace flexisip */
