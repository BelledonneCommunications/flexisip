/** Copyright (C) 2010-2022 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <bctoolbox/ownership.hh>

#include "../redis-server.hh"
#include "agent-test.hh"

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
};

class Redis {
	RedisServer mRedisServer{};

public:
	void amendConfiguration(GenericManager& cfg) {
		auto redisPort = mRedisServer.start();

		auto* registrarConf = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		registrarConf->get<ConfigValue>("db-implementation")->set("redis");
		registrarConf->get<ConfigValue>("redis-server-domain")->set("localhost");
		registrarConf->get<ConfigValue>("redis-server-port")->set(to_string(redisPort));
	}
};

} // namespace DbImplementation

template <typename TDatabase>
class RegistrarDbTest : public AgentTest {
	TDatabase dbImpl;

public:
	// The agent needs not be run to test the registrar DB.
	RegistrarDbTest() noexcept : AgentTest(false) {
	}

	void onAgentConfiguration(GenericManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);
		dbImpl.amendConfiguration(cfg);
	}
};

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
		void onContactUpdated(const shared_ptr<ExtendedContact>& ec) override {
			BC_FAIL("This test doesn't expect a contact to be updated");
		}
	};

	RegistrarDb& mRegDb;
	shared_ptr<ContactInsertedListener> mListener;
	MsgSip mForgedMessage;
	BindingParameters mParameters;

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

	void insert(string contact, chrono::seconds expire) {
		auto from = (url_string_t*)contact.c_str();
		auto sip = mForgedMessage.getSip();
		auto home = mForgedMessage.getHome();
		sip->sip_from = sip_from_create(home, from);
		sip->sip_contact = sip_contact_create(home, from, "+sip.instance=placeholder-uuid", nullptr);
		mParameters.globalExpire = expire.count();

		mListener->contactsToBeInserted.insert(contact);
		mRegDb.bind(mForgedMessage, mParameters, mListener);
	}

	bool finished() const {
		return mListener->contactsToBeInserted.empty();
	}
};

} // namespace tester
} // namespace flexisip
