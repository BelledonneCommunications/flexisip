/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <sofia-sip/sip.h>

#include "registrar/registrar-db.hh"

namespace flexisip {

class RegistrarDbInternal : public RegistrarDb {
public:
	RegistrarDbInternal(Agent* ag);
	void clearAll();

	void fetchExpiringContacts(time_t startTimestamp,
	                           float threshold,
	                           std::function<void(std::vector<ExtendedContact>&&)>&& callback) const override;

private:
	void doBind(const sofiasip::MsgSip& msg,
	            const BindingParameters& parameters,
	            const std::shared_ptr<ContactUpdateListener>& listener) override;
	void doClear(const sofiasip::MsgSip& msg, const std::shared_ptr<ContactUpdateListener>& listener) override;
	void doFetch(const SipUri& url, const std::shared_ptr<ContactUpdateListener>& listener) override;
	void doFetchInstance(const SipUri& url,
	                     const std::string& uniqueId,
	                     const std::shared_ptr<ContactUpdateListener>& listener) override;
	void doMigration() override;
	void publish(const std::string& topic, const std::string& uid) override;

	std::map<std::string, std::shared_ptr<Record>> mRecords;
};

} // namespace flexisip
