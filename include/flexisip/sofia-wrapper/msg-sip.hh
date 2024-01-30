/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL.

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

#include <algorithm>
#include <ostream>
#include <set>
#include <string>
#include <string_view>

#include <sofia-sip/msg_addr.h>
#include <sofia-sip/msg_types.h>
#include <sofia-sip/sip_protos.h>
#include <sofia-sip/su_alloc.h>

#include <bctoolbox/ownership.hh>

#include "flexisip/sip-boolean-expressions.hh"

#include "sip-header.hh"

using namespace ownership;

namespace sofiasip {

/**
 * Don't forget to update MsgSip::getPreviousPriority and MsgSip::getOrderedPrioritiesList if you update this enum.
 */
enum class MsgSipPriority { NonUrgent = 0, Normal = 1, Urgent = 2, Emergency = 3 };

class MsgSip {
public:
	MsgSip() : mMsg{msg_create(sip_default_mclass(), 0)} {
	}
	MsgSip(Owned<msg_t>&& msg) : mMsg(std::move(msg)) {
	}
	MsgSip(BorrowedMut<msg_t> msg) : mMsg(msg_ref_create(msg)) {
	}
	MsgSip(MsgSip&& other) : mMsg(std::move(other.mMsg)) {
	}
	MsgSip(const MsgSip& other);
	/**
	 * Construct a MsgSip parsing the string_view parameter.
	 *
	 * @throw Throw std::runtime_error if a parsing error occurred.
	 */
	MsgSip(int flags, std::string_view msg);

	~MsgSip() noexcept {
		msg_destroy(mMsg.take());
	}

	MsgSip& operator=(MsgSip&& other) {
		mMsg = std::move(other.mMsg);
		return *this;
	}

	Borrowed<msg_t> getMsg() const {
		return {mMsg};
	}
	BorrowedMut<msg_t> getMsg() {
		return mMsg.borrow();
	}
	sip_t* getSip() const {
		return (sip_t*)msg_object(mMsg);
	}
	su_home_t* getHome() {
		return msg_home(static_cast<msg_t*>(mMsg.borrow()));
	}
	sockaddr* getSockAddr() {
		return msg_addrinfo(mMsg.borrow())->ai_addr;
	}

	msg_header_t* findHeader(const std::string& name, bool searchUnknowns = false);
	const msg_header_t* findHeader(const std::string& name, bool searchUnknowns = false) const {
		return const_cast<MsgSip*>(this)->findHeader(name, searchUnknowns);
	}

	sip_method_t getSipMethod() const {
		const auto rq = getSip()->sip_request;
		return rq != nullptr ? rq->rq_method : sip_method_unknown;
	}

	std::string getCallID() const;

	MsgSipPriority getPriority() const;

	void serialize() {
		msg_serialize(mMsg.borrow(), (msg_pub_t*)getSip());
	}
	const char* print();
	std::string printString();
	std::string printContext() const;

	bool isGroupChatInvite() const noexcept;
	bool isChatService() noexcept;

	/**
	 * Change the sip filter used by Flexisip to show or not request's body in logs.
	 *
	 * @param filterString string containing the name of the method.
	 * @throw invalid_argument if filterString is not valid, or empty.
	 */
	static void setShowBodyFor(const std::string& filterString);

	static std::shared_ptr<flexisip::SipBooleanExpression>& getShowBodyForFilter() {
		if (!sShowBodyFor) {
			sShowBodyFor = flexisip::SipBooleanExpressionBuilder::get().parse("content-type == 'application/sdp'");
		}
		return sShowBodyFor;
	}

	/**
	 * Return the priority just before the one in parameter;
	 * @throw logic_error if current == MsgSipPriority::NonUrgent
	 */
	static MsgSipPriority getPreviousPriority(MsgSipPriority current);

	static std::array<MsgSipPriority, 4> getOrderedPrioritiesList() {
		return {MsgSipPriority::Emergency, MsgSipPriority::Urgent, MsgSipPriority::Normal, MsgSipPriority::NonUrgent};
	};
	/**
	 * Insert or add a SIP header in the SIP message.
	 * If the header already exists in the message and is to be unique, then the new header replace the old one.
	 * If the header already exists in the message and isn't to be unique, then the new header is inserted after
	 * or before the current headers according the kind of the header.
	 */
	void insertHeader(SipHeader&& header) {
		su_home_move(getHome(), header.mHome.home());
		msg_header_insert(mMsg.borrow(), nullptr, header.mNativePtr);
		header.mNativePtr = nullptr;
	}
	/**
	 * Create and insert a header in a SIP message.
	 * @param HeaderT The header type.
	 * @param args The arguments to give to the header constructor.
	 */
	template <typename HeaderT, typename... ArgsT>
	void makeAndInsert(ArgsT&&... args) {
		insertHeader(HeaderT{std::forward<ArgsT>(args)...});
	}

private:
	// Private methods
	std::pair<char*, size_t> asString();

	// Private attributes
	Owned<msg_t> mMsg{nullptr};

	static std::shared_ptr<flexisip::SipBooleanExpression> sShowBodyFor;
};

std::ostream& operator<<(std::ostream& strm, const sofiasip::MsgSip& obj) noexcept;

}; // namespace sofiasip
