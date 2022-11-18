/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <bctoolbox/ownership.hh>

#include "flexisip/registrar/registar-listeners.hh"

#include "agent-test.hh"
#include "registrar/binding-parameters.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "utils/redis-server.hh"

using namespace std;

namespace flexisip {
namespace tester {

namespace DbImplementation {

class Internal {
public:
	void amendConfiguration(GenericManager& cfg) {
		auto* registrarConf = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		registrarConf->get<ConfigValue>("db-implementation")->set("internal");
	}

	std::map<std::string, std::string> configAsMap() {
		return {
		    {"module::Registrar/db-implementation", "internal"},
		};
	}
};

class Redis {
	RedisServer mRedisServer{};

public:
	int mPort = -1;

	void amendConfiguration(GenericManager& cfg) {
		mPort = mRedisServer.start();

		auto* registrarConf = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		registrarConf->get<ConfigValue>("db-implementation")->set("redis");
		registrarConf->get<ConfigValue>("redis-server-domain")->set("localhost");
		registrarConf->get<ConfigValue>("redis-server-port")->set(to_string(mPort));
	}

	std::map<std::string, std::string> configAsMap() {
		return {{"module::Registrar/db-implementation", "redis"},
		        {"module::Registrar/redis-server-domain", "localhost"},
		        {"module::Registrar/redis-server-port", std::to_string(mRedisServer.start())}};
	}
};

} // namespace DbImplementation

// Insert Contacts into the Registrar
class ContactInserter {
	struct ContactInsertedListener : public ContactUpdateListener {
		unordered_set<string> contactsToBeInserted;

		void onRecordFound(const shared_ptr<Record>& r) override {
			for (const auto& contact : r->getExtendedContacts()) {
				contactsToBeInserted.erase(ExtendedContact::urlToString(contact->mSipContact->m_url));
			}
		}
		void onError() override {
			BC_FAIL("This test doesn't expect an error response");
		}
		void onInvalid() override {
			BC_FAIL("This test doesn't expect an invalid response");
		}
		// Mandatory since we inherit from ContatUpdateListener
		void onContactUpdated([[maybe_unused]] const shared_ptr<ExtendedContact>& ec) override {
			BC_FAIL("This test doesn't expect a contact to be updated");
		}
	};

	RegistrarDb& mRegDb;
	shared_ptr<ContactInsertedListener> mListener;
	MsgSip mForgedMessage;
	BindingParameters mParameters;
	int mCount = 0;

public:
	ContactInserter(RegistrarDb& regDb, const flexisip::Agent& agent)
	    : mRegDb(regDb), mListener(make_shared<ContactInsertedListener>()),
	      mForgedMessage(ownership::owned(nta_msg_create(agent.getSofiaAgent(), 0))) {
		auto home = mForgedMessage.getHome();
		msg_header_add_dup(
		    mForgedMessage.getMsg(), nullptr,
		    reinterpret_cast<msg_header_t*>(sip_request_make(home, "MESSAGE sip:placeholder-address SIP/2.0\r\n")));
		mForgedMessage.getSip()->sip_call_id = sip_call_id_make(home, "placeholder-call-id");
	}

	void insert(string aor, chrono::seconds expire, string contact = "") {
		auto aorUrl = (url_string_t*)aor.c_str();
		contact = contact.empty() ? aor : contact;
		auto contactUrl = (url_string_t*)contact.c_str();
		auto sip = mForgedMessage.getSip();
		auto home = mForgedMessage.getHome();
		sip->sip_from = sip_from_create(home, aorUrl);
		sip->sip_contact =
		    sip_contact_create(home, contactUrl, ("+sip.instance=test-contact-"s + to_string(mCount)).c_str(), nullptr);
		mParameters.globalExpire = expire.count();

		mListener->contactsToBeInserted.insert(contact);
		mRegDb.bind(mForgedMessage, mParameters, mListener);
		mCount++;
	}

	bool finished() const {
		return mListener->contactsToBeInserted.empty();
	}
};

template <typename TDatabase>
class RegistrarDbTest : public AgentTest {
public:
	RegistrarDbTest(bool startAgent = false) noexcept : AgentTest(startAgent) {
	}

	void onAgentConfiguration(GenericManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);
		dbImpl.amendConfiguration(cfg);
	}

	void onAgentConfigured() override {
		mInserter = std::make_unique<ContactInserter>(*RegistrarDb::get(), *this->mAgent);
	}

	std::unique_ptr<ContactInserter> mInserter{nullptr};

protected:
	TDatabase dbImpl;
};

} // namespace tester
} // namespace flexisip
