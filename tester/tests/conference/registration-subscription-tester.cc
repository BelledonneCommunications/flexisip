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

#include <memory>
#include <string>

#include "linphone++/chat_room.hh"
#include "linphone++/enums.hh"

#include "conference/registration-subscription.hh"
#include "utils/chat-room-builder.hh"
#include "utils/client-core.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace flexisip;
using namespace flexisip::tester;
using namespace linphone;

namespace {
class RegistrationSubscriptionTester : public RegistrationSubscription {
public:
	RegistrationSubscriptionTester(const std::shared_ptr<linphone::ChatRoom>& cr,
	                               const std::shared_ptr<const linphone::Address>& participant)
	    : RegistrationSubscription(true, cr, participant) {
	}
	bool checkCapabilities(const std::string& specs) {
		return isContactCompatible(specs);
	}
	void start() override {};
	void stop() override {};
};

auto startMinimalCore() {
	const auto core = minimalCore();
	core->setLabel("Flexisip Test");
	core->enableConferenceServer(true);
	core->enableDatabase(false);

	auto factory = Factory::get();
	const auto localhostAddress = factory->createAddress("sip:localhost");
	const auto accountParams = core->createAccountParams();
	accountParams->setIdentityAddress(factory->createAddress("sip:flexisip-test@localhost"));
	accountParams->enableRegister(false);
	accountParams->setServerAddress(localhostAddress);
	const auto account = core->createAccount(accountParams);
	account->setContactAddress(localhostAddress);

	core->addAccount(account);
	core->setDefaultAccount(account);
	core->start();
	return core;
}

auto createConference(linphone::Core& core,
                      ChatRoom::EncryptionBackend encryptionBackend,
                      ChatRoom::EphemeralMode ephemeralMode) {
	auto params = core.createConferenceParams(nullptr);
	params->setHidden(true);
	params->enableVideo(false);
	params->enableChat(true);
	params->enableLocalParticipant(false);
	params->enableOneParticipantConference(true);
	params->setConferenceFactoryAddress(nullptr);
	params->setSubject("capabilities-test");
	auto chatParams = params->getChatParams();
	chatParams->setEncryptionBackend(encryptionBackend);
	chatParams->setEphemeralMode(ephemeralMode);
	auto conference = core.createConferenceWithParams(params);
	return conference;
}

// A chat room only with chat must accept all participants with chat capabilities.
void chatOnlyChatRoomSubscription() {
	auto core = startMinimalCore();
	auto conference =
	    createConference(*core, ChatRoom::EncryptionBackend::None, ChatRoom::EphemeralMode::DeviceManaged);
	auto participant = linphone::Factory::get()->createAddress("sip:user@localhost");

	RegistrationSubscriptionTester chatOnlySubscription(conference->getChatRoom(), participant);
	BC_ASSERT_CPP_EQUAL(chatOnlySubscription.checkCapabilities("conference/2.0,ephemeral/1.1,lime"), false);
	BC_ASSERT_CPP_EQUAL(chatOnlySubscription.checkCapabilities("conference/2.0,groupchat/1.2,lime"), true);
	BC_ASSERT_CPP_EQUAL(chatOnlySubscription.checkCapabilities("conference/2.0,ephemeral/1.1,groupchat/1.2"), true);
	BC_ASSERT_CPP_EQUAL(chatOnlySubscription.checkCapabilities("conference/2.0,ephemeral/1.1,groupchat/1.2,lime"),
	                    true);
	BC_ASSERT_CPP_EQUAL(
	    chatOnlySubscription.checkCapabilities("conference/2.0,ephemeral/1.1,groupchat/1.2,lime,unknown/1.0"), true);
}

// A chat room with chat ephemeral and lime capabilities must only accept participants with at least the same
// capabilities.
void chatEphemeralAndLimeChatRoomSubscription() {
	auto core = startMinimalCore();
	auto conference = createConference(*core, ChatRoom::EncryptionBackend::Lime, ChatRoom::EphemeralMode::AdminManaged);
	auto participant = Factory::get()->createAddress("sip:user@localhost");

	RegistrationSubscriptionTester chatEphemaralLimeSubscription(conference->getChatRoom(), participant);
	BC_ASSERT_CPP_EQUAL(chatEphemaralLimeSubscription.checkCapabilities("conference/2.0,ephemeral/1.1,lime"), false);
	BC_ASSERT_CPP_EQUAL(chatEphemaralLimeSubscription.checkCapabilities("conference/2.0,groupchat/1.2,lime"), false);
	BC_ASSERT_CPP_EQUAL(chatEphemaralLimeSubscription.checkCapabilities("conference/2.0,ephemeral/1.1,groupchat/1.2"),
	                    false);
	BC_ASSERT_CPP_EQUAL(
	    chatEphemaralLimeSubscription.checkCapabilities("conference/2.0,ephemeral/1.1,groupchat/1.2,lime"), true);
	BC_ASSERT_CPP_EQUAL(
	    chatEphemaralLimeSubscription.checkCapabilities("conference/2.0,ephemeral/1.1,groupchat/1.2,lime,unknown/1.0"),
	    true);
}

TestSuite _("conference::subscription",
            {
                CLASSY_TEST(chatOnlyChatRoomSubscription),
                CLASSY_TEST(chatEphemeralAndLimeChatRoomSubscription),
            });
} // namespace
