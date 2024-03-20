/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include <chrono>
#include <memory>
#include <string>

#include "push-notification-exceptions.hh"
#include "push-type.hh"
#include "registrar/extended-contact.hh"
#include "rfc8599-push-params.hh"

namespace sofiasip {
class MsgSip;
};

namespace flexisip {
namespace pushnotification {

struct PushInfo {
	// Generic attributes

	/**
	 * The list of supported destinations supported by the device to notify. That especially allows the constructor
	 * of PushNotificationContext to know which kind of push notifications the device supports and then to
	 * instantiate the right pushnotification::Strategy.
	 */
	RFC8599PushParams::ParsingResult mDestinations{};
	std::string mAlertMsgId{}; /**< ID of message to show to user */
	/**
	 * Message to use as title when a PN is sent to notify a canceled call.
	 */
	std::string mMissingCallMsg{"Missing call"};
	/**
	 * Message to use as title when a PN is sent to notify
	 * that the call has been declined by another device of
	 * the callee.
	 */
	std::string mDeclinedElsewhereMsg{"Declined elsewhere"};
	/**
	 * Message to use as title when a PN is sent to notify
	 * that the call has been picked up by another device of
	 * the callee.
	 */
	std::string mAcceptedElsewhereMsg{"Accepted elsewhere"};
	std::string mCollapseId{}; /**< ID that allows to group alert notifications between each others. */
	std::string mFromName{};   /**< From's display name */
	std::string mFromUri{};    /**< From's SIP uri */
	std::string mFromTag{};    /**< From tag */
	std::string mToUri{};      /**< To SIP uri */
	std::string mCallId{};     /**< CallID */
	std::string mText{};       /**< Text of the chat message. */
	std::string mUid{};        /**< The unique id as used in the ExtendedContact, if available. */
	/**
	 * In case of a chat room invite, the sip addr of
	 * the chat room is needed. (ios specific).
	 */
	std::string mChatRoomAddr{};
	std::chrono::seconds mTtl{0}; /**< Time to live of the push notification. Zero means asap. */

	// Specific to APNS (iOS)
	bool mNoBadge{false};      /**< Whether to display a badge on the application (ios specific). */
	std::string mAlertSound{}; /**< sound to play */
	std::string mCustomPayload{};

	// Specific to Generic Push Notifications
	/**
	 * A string that indicate the kind of event that have triggered the push notification, classically
	 * 'message' or 'call'. It is a free label that will replace the occurrences of '$event' in the
	 * HTTP request sent to the server in charge of sending the push notification.
	 */
	std::string mEvent{};

public:
	// Public ctors
	PushInfo() = default;
	/**
	 * Fill the PushInfo structure by parsing the information from a SIP message.
	 * @throw MissingPushParameters when neither RFC8599, nor legacy push parameters are present in
	 * the Request-URI of the SIP message. Attribute 'mDestinations' would be empty then.
	 * @throw InvalidPushParameters for other parsing errors.
	 */
	PushInfo(const sofiasip::MsgSip& msg);
	PushInfo(const ExtendedContact& contact);
	virtual ~PushInfo() = default;

	void addDestination(const std::shared_ptr<const RFC8599PushParams>& dest) noexcept;
	const std::string& getPNProvider() const;

	bool isApple() const {
		return mDestinations.empty() ? false : mDestinations.cbegin()->second->isApns();
	}

	const RFC8599PushParams& getDestination(PushType pType) const;

private:
	// Private methods
	void parseAppleSpecifics(const sofiasip::MsgSip& msg);
	void setDestinations(const url_t* url);
};

} // namespace pushnotification
} // namespace flexisip
