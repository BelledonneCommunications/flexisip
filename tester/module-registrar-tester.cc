/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <csignal>

#include "bctoolbox/tester.h"

#include "flexisip/registrar/registar-listeners.hh"

#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"
#include "utils/proxy-server.hh"
#include "utils/temp-file.hh"

using namespace std::chrono_literals;
namespace flexisip {
namespace tester {
namespace module_registrar {

class ReturnRecord : public ContactUpdateListener {
public:
	std::shared_ptr<Record> mRecord;

	virtual void onRecordFound(const std::shared_ptr<Record>& r) override {
		mRecord = r;
	}
	virtual void onError(const SipStatus&) override {
		BC_FAIL(unexpected call to onError);
	}
	virtual void onInvalid(const SipStatus&) override {
		BC_FAIL(unexpected call to onInvalid);
	}
	virtual void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& _ec) override {
		BC_FAIL(unexpected call to onContactUpdated);
	}
};

void static_records_file_is_read_on_SIGUSR1() {
	const auto sendSignal = [pid = getpid()] {
		kill(pid, SIGUSR1); // No, this is not suicide
	};
	const auto aor = "sip:contact@domain";
	const auto contact1 = "<sip:127.0.0.1:5460>";
	const auto contact2 = "<sip:192.168.0.1:5160>";
	const auto contact3 = "<sip:192.168.0.2:3125>";
	const TempFile staticRecordsFile{};
	staticRecordsFile.writeStream() << "<" << aor << "> " << contact1 << "," << contact2 << "," << contact3;

	Server proxyServer({
	    {"module::Registrar/static-records-file", staticRecordsFile.name},
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0"},
	});
	auto& root = *proxyServer.getRoot();
	proxyServer.start();
	auto& regDb = *RegistrarDb::get();
	const auto listener = std::make_shared<ReturnRecord>();

	sendSignal();
	root.step(1ms);

	{
		regDb.fetch(SipUri(aor), listener);
		const auto& fetchedContacts = listener->mRecord->getExtendedContacts();
		BC_ASSERT_EQUAL(fetchedContacts.size(), 3, size_t, "%zx");
		const auto& last = **fetchedContacts.latest();
		BC_ASSERT_TRUE(url_cmp_all(last.mSipContact->m_url, sofiasip::Url(contact3).get()));
	}

	// Remove contact3
	staticRecordsFile.writeStream() << "<" << aor << "> " << contact1 << "," << contact2;
	sendSignal();
	root.step(1ms);

	{
		regDb.fetch(SipUri(aor), listener);
		const auto& fetchedContacts = listener->mRecord->getExtendedContacts();
		BC_ASSERT_EQUAL(fetchedContacts.size(), 2, size_t, "%zx");
		const auto& last = **fetchedContacts.latest();
		BC_ASSERT_TRUE(url_cmp_all(last.mSipContact->m_url, sofiasip::Url(contact2).get()));
	}
}

auto _ = [] {
	static test_t tests[] = {
	    TEST_NO_TAG_AUTO_NAMED(static_records_file_is_read_on_SIGUSR1),
	};
	static test_suite_t suite{"ModuleRegistrar", NULL, NULL, NULL, NULL, sizeof(tests) / sizeof(tests[0]), tests};
	bc_tester_add_suite(&suite);
	return nullptr;
}();

} // namespace module_registrar
} // namespace tester
} // namespace flexisip
