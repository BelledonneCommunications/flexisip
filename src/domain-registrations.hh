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
#include <regex>

#include <sofia-sip/msg.h>
#include <sofia-sip/nta.h>
#include <sofia-sip/su_wait.h>
#include <sofia-sip/tport.h>

#include "flexisip/common.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/registrar/registar-listeners.hh"
#include "flexisip/utils/sip-uri.hh"

#include "registrar/registrar-db.hh"

namespace flexisip {

class Agent;
class DomainRegistrationManager;
class LocalRegExpireListener;

class DomainRegistration {
public:
	DomainRegistration(DomainRegistrationManager& mgr,
	                   const std::string& localDomain,
	                   const sofiasip::Url& parentProxy,
	                   const std::string& password,
	                   const sofiasip::TlsConfigInfo& clientCertConf,
	                   const std::string& passphrase,
	                   int lineIndex);
	~DomainRegistration();

	void start();
	void stop();

	bool isUs(const url_t* url);
	bool hasTport(const tport_t* tport) const;

	const url_t* getPublicUri() const;
	const url_t* getProxy() const {
		return mProxy;
	}
	tport_t* getTport() const {
		return mCurrentTport;
	}
	StatCounter64* getRegistrationStatus() const noexcept {
		return mRegistrationStatus;
	}

private:
	// Private types
	struct uuid_t {
		unsigned int time_low;
		unsigned short time_mid;
		unsigned short time_hi_and_version;
		unsigned char clock_seq_hi_and_reserved;
		unsigned char clock_seq_low;
		unsigned char node[6];
	};

	// Private methods
	void setContact(msg_t* msg);
	std::chrono::seconds getExpires(nta_outgoing_t* orq, const sip_t* response);
	static void sOnConnectionBroken(tp_stack_t* stack, tp_client_t* client, tport_t* tport, msg_t* msg, int error);
	static int sLegCallback(nta_leg_magic_t* ctx, nta_leg_t* leg, nta_incoming_t* incoming, const sip_t* request);
	static int sResponseCallback(nta_outgoing_magic_t* ctx, nta_outgoing_t* orq, const sip_t* resp);
	void responseCallback(nta_outgoing_t* orq, const sip_t* resp);
	void onConnectionBroken(tport_t* tport, msg_t* msg, int error);
	void setCurrentTport(tport_t* tport);
	void cleanCurrentTport();
	void sendRequest();
	int generateUuid(const std::string& uniqueId);

	// Private attributes
	DomainRegistrationManager& mManager;
	StatCounter64* mRegistrationStatus{
	    nullptr}; // This contains the latest SIP response code of the REGISTER transaction.
	sofiasip::Home mHome{};
	nta_leg_t* mLeg{nullptr};
	tport_t* mPrimaryTport{nullptr}; // the tport that has the configuration
	tport_t* mCurrentTport{nullptr}; // the secondary tport that has the active connection.
	int mPendId{0};
	std::unique_ptr<sofiasip::Timer> mTimer{};
	url_t* mFrom{nullptr};
	std::string mPassword{};
	url_t* mProxy{nullptr};
	sip_contact_t* mExternalContact{nullptr};
	std::string mUuid{};
	nta_outgoing_t* mOutgoing{nullptr};
	std::chrono::seconds mExpires{600};
	bool mLastResponseWas401{false};
	bool mPongsExpected{false};
};

class DomainRegistrationManager : public LocalRegExpireListener,
                                  public std::enable_shared_from_this<DomainRegistrationManager> {
	friend class DomainRegistration;

public:
	explicit DomainRegistrationManager(Agent* agent);
	~DomainRegistrationManager() override;

	int load(const std::string& passphrase);

	template <typename DomainRegistrationPtr>
	void addDomainRegistration(DomainRegistrationPtr&& dr) noexcept {
		mRegistrations.emplace_back(std::forward<DomainRegistrationPtr>(dr));
	}

	auto getReconnectionDelay() const noexcept {
		return mReconnectionDelay;
	}

	auto getRegistrationCount() const noexcept {
		return mNbRegistration;
	}

	/**
	 * check is url is a local contact of any existing domain registration.
	 */
	bool isUs(const url_t* url) const;
	/**
	 * If this tport was created as result of domain registration, returns the known public ip/port.
	 * This is useful for setting correct Record-Routes for request arriving through these connections.
	 **/
	const url_t* getPublicUri(const tport_t* tport) const;

	void onLocalRegExpireUpdated(unsigned int count) override;

	/**
	 * Search for a DomainRegistration whose remote proxy matches destUrl, and return the tport_t it uses.
	 */
	tport_t* lookupTport(const url_t* destUrl);

	/**
	 * Check if a we have to relay registration requests to its domain controller for a given domain.
	 * If url_host is an empty string, then the global relay registration to domain cfg status is returned.
	 */
	bool haveToRelayRegToDomain(const std::string& url_host);

private:
	Agent* mAgent{nullptr};
	std::list<std::shared_ptr<DomainRegistration>> mRegistrations{};
	int mNbRegistration{0};
	std::unique_ptr<sofiasip::Timer> mTimer{};
	std::list<std::string> mRegistrationList{};
	GenericStruct* mDomainRegistrationArea{nullptr}; /*this is used to place statistics values*/
	std::chrono::seconds mKeepaliveInterval{0};
	std::chrono::seconds mPingPongTimeoutDelay{0};
	std::chrono::seconds mReconnectionDelay{0};
	bool mVerifyServerCerts{false};
	bool mRegisterWhenNeeded{false};
	bool mDomainRegistrationsStarted{false};
	bool mRelayRegsToDomains{false};
	std::regex mRelayRegsToDomainsRegex{};
};

} // namespace flexisip
