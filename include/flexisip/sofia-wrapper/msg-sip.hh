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

#pragma once

#include <algorithm>
#include <array>
#include <string>
#include <string_view>

#include "bctoolbox/ownership.hh"

#include "sofia-sip/msg_addr.h"
#include "sofia-sip/sip_protos.h"

#include "flexisip/sip-boolean-expressions.hh"
#include "sip-header.hh"

using namespace ownership;

namespace flexisip {
class SocketAddress;
}

namespace sofiasip {

/**
 * Remember to update MsgSip::getPreviousPriority and MsgSip::getOrderedPrioritiesList if you update this enum.
 */
enum class MsgSipPriority { NonUrgent = 0, Normal = 1, Urgent = 2, Emergency = 3 };

class MsgSip {
public:
	MsgSip() : mMsg{msg_create(sip_default_mclass(), 0)} {}
	MsgSip(Owned<msg_t>&& msg) : mMsg(std::move(msg)) {}
	MsgSip(BorrowedMut<msg_t> msg) : mMsg(msg_ref_create(msg)) {}
	MsgSip(MsgSip&& other) noexcept : mMsg(std::move(other.mMsg)) {}
	/**
	 * @warning Invoking the copy constructor of MsgSip implies the deep copy of the underlying msg_t
	 */
	MsgSip(const MsgSip& other);
	/**
	 * Construct a MsgSip parsing the string_view parameter.
	 *
	 * @throw std::runtime_error if a parsing error occurred.
	 */
	MsgSip(int flags, std::string_view msg);

	~MsgSip() noexcept {
		msg_destroy(mMsg.take());
	}
	MsgSip& operator=(MsgSip&& other) noexcept {
		std::swap(mMsg, other.mMsg);
		return *this;
	}

	static std::array<MsgSipPriority, 4> getOrderedPrioritiesList() {
		return {MsgSipPriority::Emergency, MsgSipPriority::Urgent, MsgSipPriority::Normal, MsgSipPriority::NonUrgent};
	}
	/**
	 * Return the priority just before the one in the parameter;
	 * @throw logic_error if current == MsgSipPriority::NonUrgent
	 */
	static MsgSipPriority getPreviousPriority(MsgSipPriority current);

	static std::shared_ptr<flexisip::SipBooleanExpression>& getShowBodyForFilter();
	/**
	 * Change the sip filter used by Flexisip to show or not request's body in logs.
	 *
	 * @param filterString string containing the name of the method.
	 * @throw invalid_argument if filterString is not valid, or empty.
	 */
	static void setShowBodyFor(const std::string& filterString);

	static std::string toString(msg_t& msg);

	void serialize();

	msg_header_t* findHeader(const std::string& name, bool searchUnknowns = false);
	const msg_header_t* findHeader(const std::string& name, bool searchUnknowns = false) const;

	std::string msgAsString() const;
	std::string contextAsString() const;

	bool isGroupChatInvite() const noexcept;
	bool isChatService() noexcept;
	/**
	 * @return 'true' if the SIP request contained in this instance is in-dialog, according to RFC3261.
	 */
	bool isInDialog() const noexcept;

	/**
	 * Insert or add a SIP header in the SIP message.
	 * If the header already exists in the message and is to be unique, then the new header replaces the old one.
	 * If the header already exists in the message and isn't to be unique, then the new header is inserted after
	 * or before the current headers according to the kind of the header.
	 */
	void insertHeader(SipHeader&& header);

	/**
	 * Create and insert a header in a SIP message.
	 * @tparam HeaderT The header type.
	 * @param args The arguments to give to the header constructor.
	 */
	template <typename HeaderT, typename... ArgsT>
	void makeAndInsert(ArgsT&&... args) {
		insertHeader(HeaderT{std::forward<ArgsT>(args)...});
	}

	Borrowed<msg_t> getMsg() const {
		return {mMsg};
	}
	BorrowedMut<msg_t> getMsg() {
		return mMsg.borrow();
	}
	const sip_t* getSip() const;
	sip_t* getSip();
	su_home_t* getHome();
	sockaddr* getSockAddr();
	sip_method_t getSipMethod() const;
	std::string getCallID() const;
	MsgSipPriority getPriority() const;
	/**
	 * @return a copy of the socket address associated with the message or nullptr if it failed to make the
	 * SocketAddress.
	 */
	std::shared_ptr<flexisip::SocketAddress> getAddress();

private:
	static std::shared_ptr<flexisip::SipBooleanExpression> sShowBodyFor;

	Owned<msg_t> mMsg{nullptr};
	std::string mLogPrefix{};
};

std::ostream& operator<<(std::ostream& strm, const MsgSip& obj) noexcept;

}; // namespace sofiasip