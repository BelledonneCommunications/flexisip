/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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
#include <string_view>

#include "flexisip/event.hh"
#include "flexisip/module-router.hh"
#include "flexisip/registrar/registar-listeners.hh"
#include "flexisip/utils/sip-uri.hh"
#include "flexisip/utils/stl-backports.hh"
#include "fork-context/fork-context.hh"
#include "registrar/registrar-db.hh"

namespace flexisip {

class TargetUriListFetcher : public ContactUpdateListener, public std::enable_shared_from_this<TargetUriListFetcher> {
public:
	TargetUriListFetcher(Agent* agent,
	                     RequestSipEvent& ev,
	                     const std::shared_ptr<ContactUpdateListener>& listener,
	                     const sip_unknown_t* target_uris);

	~TargetUriListFetcher() override = default;

	void fetch(bool allowDomainRegistrations, bool recursive);

	void onRecordFound(const std::shared_ptr<Record>& r) override;
	void onError(const SipStatus&) override;
	void onInvalid(const SipStatus&) override;

	void onContactUpdated(const std::shared_ptr<ExtendedContact>&) override {}

	void checkFinished();

private:
	static constexpr std::string_view mLogPrefix{"TargetUriListFetcher"};

	int mPending = 0;
	bool mError = false;
	std::vector<SipUri> mUriList;
	std::shared_ptr<Record> mRecord;
	std::shared_ptr<ContactUpdateListener> mListener;
	RegistrarDb& mRegistrarDb;
};

class ForkFetchRoutingListener : public ContactUpdateListener {
public:
	ForkFetchRoutingListener(const std::shared_ptr<ForkManager>& forkManager,
	                         const std::shared_ptr<ForkContext>& forkContext,
	                         const SipUri& sipuri,
	                         bool isInviteRequest,
	                         stl_backports::move_only_function<void(bool)>&& onEmptyContacts);

	void onRecordFound(const std::shared_ptr<Record>& arg) override;
	void onError(const SipStatus& response) override;
	void onInvalid(const SipStatus& response) override;
	void onContactUpdated(const std::shared_ptr<ExtendedContact>&) override {}

private:
	static constexpr std::string_view mLogPrefix{"ForkFetchRoutingListener"};

	void routeRequest(const std::shared_ptr<Record>& aor);

	std::shared_ptr<ForkManager> mForkManager{};
	std::shared_ptr<ForkContext> mForkContext{};
	SipUri mSipUri{};
	bool mIsInviteRequest{};
	stl_backports::move_only_function<void(bool)> mEmptyContactsCb;
};

} // namespace flexisip
