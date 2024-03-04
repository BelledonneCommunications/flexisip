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

#include <optional>
#include <string>

#include "flexisip/sofia-wrapper/home.hh"
#include <sofia-sip/sip_protos.h>

#include "eventlogs/events/calls/invite-kind.hh"
#include "eventlogs/events/event-id.hh"
#include "eventlogs/events/event-log-write-dispatcher.hh"
#include "eventlogs/events/identified.hh"
#include "eventlogs/events/sip-event-log.hh"
#include "fork-context/fork-status.hh"
#include "registrar/extended-contact.hh"

namespace flexisip {

class EventLogWriter;

class EventLog : public EventLogWriteDispatcher, public SipEventLog {
public:
	EventLog(const sip_t* sip);
	EventLog(const EventLog&) = delete;
	EventLog(EventLog&&) = default;
	virtual ~EventLog() = default;

	sip_user_agent_t* getUserAgent() const {
		return mUA;
	}
	const std::string& getCallId() const {
		return mCallId;
	}
	const time_t& getDate() const {
		return mDate;
	}
	const std::string& getReason() const {
		return mReason;
	}

	bool isCompleted() const {
		return mCompleted;
	}
	void setCompleted() {
		mCompleted = true;
	}

	const int& getStatusCode() const {
		return mStatusCode;
	}
	template <typename T>
	void setStatusCode(int sip_status, T&& reason) {
		mStatusCode = sip_status;
		mReason = std::forward<T>(reason);
	}

	const std::string& getPriority() const {
		return mPriority;
	}
	template <typename T>
	void setPriority(T&& priority) {
		mPriority = std::forward<T>(priority);
	}

protected:
	sip_user_agent_t* mUA{nullptr};
	time_t mDate{0};
	int mStatusCode{0};
	std::string mReason{};
	bool mCompleted{false};
	std::string mCallId{};
	std::string mPriority{"normal"};
};

class RegistrationLog : public EventLog {
public:
	// Explicit values are necessary for soci. Do not change this.
	enum class Type { Register = 0, Unregister = 1, Expired = 2 };

	RegistrationLog(const sip_t* sip, const sip_contact_t* contacts);

	Type getType() const {
		return mType;
	}
	sip_contact_t* getContacts() const {
		return mContacts;
	}

	void write(EventLogWriter& writer) const override;

private:
	Type mType{Type::Register};
	sip_contact_t* mContacts{nullptr};
};

class CallLog : public EventLog, public Identified, public WithInviteKind {
public:
	CallLog(const sip_t* sip) : EventLog(sip), Identified(*sip), WithInviteKind(sip->sip_content_type) {
	}

	bool isCancelled() const {
		return mCancelled;
	}
	void setCancelled() {
		mCancelled = true;
	}

	void write(EventLogWriter& writer) const override;

	ForkStatus getForkStatus() const {
		return mForkStatus;
	}
	void setForkStatus(ForkStatus value) {
		mForkStatus = value;
	}
	const std::optional<ExtendedContact>& getDevice() const {
		return mDevice;
	}
	void setDevice(const ExtendedContact& value) {
		mDevice.emplace(value);
	}

private:
	ForkStatus mForkStatus = ForkStatus::Standard;
	std::optional<ExtendedContact> mDevice = std::nullopt;
	bool mCancelled{false};
};

class MessageLog : public EventLog {
public:
	// Explicit values is necessary for soci. Do not change this.
	enum class ReportType { ResponseToSender = 0, ResponseFromRecipient = 1 };

	MessageLog(const sip_t& sip) : EventLog(&sip) {
	}
	virtual ~MessageLog() = default;

	virtual ReportType getReportType() const {
		return ReportType::ResponseToSender;
	}
	const url_t* getUri() const {
		return mUri;
	}

	void setDestination(const url_t* dest) {
		mUri = url_hdup(mHome.home(), dest);
	}

	void write(EventLogWriter& writer) const override;

private:
	url_t* mUri{nullptr}; // destination uri of message
};

class AuthLog : public EventLog {
public:
	AuthLog(const sip_t* sip, bool userExists);

	const url_t* getOrigin() const {
		return mOrigin;
	}
	const std::string& getMethod() const {
		return mMethod;
	}

	bool userExists() const {
		return mUserExists;
	}

	void write(EventLogWriter& writer) const override;

private:
	void setOrigin(const sip_via_t* via);

	url_t* mOrigin{nullptr};
	std::string mMethod{};
	bool mUserExists{false};
};

class CallQualityStatisticsLog : public EventLog {
public:
	CallQualityStatisticsLog(const sip_t* sip);

	const std::string& getReport() const {
		return mReport;
	}

	void write(EventLogWriter& writer) const override;

private:
	// Note on `soci`: The `char *` support is dead since 2008...
	// See: https://github.com/SOCI/soci/commit/25c704ac4cb7bb0135dabc2421a1281fb868a511
	// It's necessary to create a hard copy with a `string`.
	std::string mReport{};
};

} // namespace flexisip
