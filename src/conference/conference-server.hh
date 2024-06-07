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

#include <filesystem>
#include <memory>

#include <linphone++/linphone.hh>

#include "participant-registration-subscription-handler.hh"
#include "registrar/registrar-db.hh"
#include "registration-subscription.hh"
#include "service-server/service-server.hh"

#ifndef DEFAULT_LIB_DIR
#define DEFAULT_LIB_DIR "/var/opt/belledonne-communications/lib/flexisip"
#endif // DEFAULT_LIB_DIR

namespace flexisip {
class ConferenceServer : public ServiceServer,
                         public RegistrarDbStateListener,
                         public std::enable_shared_from_this<ConferenceServer>,
                         public linphone::CoreListener,
                         public linphone::ChatRoomListener {
public:
	template <typename StrT, typename SuRootPtr>
	ConferenceServer(StrT&& pathUri,
	                 SuRootPtr&& root,
	                 const std::shared_ptr<ConfigManager>& cfg,
	                 const std::shared_ptr<RegistrarDb>& registrarDb)
	    : ServiceServer{std::forward<SuRootPtr>(root)}, mPath{std::forward<StrT>(pathUri)}, mConfigManager{cfg},
	      mRegistrarDb{registrarDb}, mSubscriptionHandler{*this, *mRegistrarDb} {
	}

	virtual void bindAddresses();

	void bindChatRoom(const std::string& bindingUrl,
	                  const std::string& contact,
	                  const std::string& gruu,
	                  const std::shared_ptr<ContactUpdateListener>& listener);

	/**
	 * Bind conference factory uris and focus uris on the registrardb
	 **/
	void bindFactoryUris();
	void bindFocusUris();

	bool capabilityCheckEnabled() const {
		return mCheckCapabilities;
	}
	const std::list<std::string>& getLocalDomains() const {
		return mLocalDomains;
	}
	std::shared_ptr<RegistrationEvent::ClientFactory> getRegEventClientFactory() const {
		return mRegEventClientFactory;
	}
	std::shared_ptr<linphone::Core> getCore() const {
		return mCore;
	}
	struct MediaConfig {
		bool audioEnabled = false;
		bool videoEnabled = false;
		bool textEnabled = false;
	};
	const MediaConfig& getMediaConfig() const {
		return mMediaConfig;
	}

	const GenericStruct& getServerConf() const {
		return *mConfigManager->getRoot()->get<GenericStruct>("conference-server");
	}

protected:
	void _init() override;
	void _run() override;
	std::unique_ptr<AsyncCleanup> _stop() override;

	SipUri mTransport{};

private:
	void loadFactoryUris();
	// RegistrarDbStateListener implementation
	void onRegistrarDbWritable(bool writable) override;

	// CoreListener implementation
	void onChatRoomStateChanged(const std::shared_ptr<linphone::Core>& lc,
	                            const std::shared_ptr<linphone::ChatRoom>& cr,
	                            linphone::ChatRoom::State state) override;

	// ChatRoomListener implementation
	void onConferenceAddressGeneration(const std::shared_ptr<linphone::ChatRoom>& cr) override;

	void onParticipantRegistrationSubscriptionRequested(
	    const std::shared_ptr<linphone::ChatRoom>& cr,
	    const std::shared_ptr<const linphone::Address>& participantAddr) override;
	void onParticipantRegistrationUnsubscriptionRequested(
	    const std::shared_ptr<linphone::ChatRoom>& cr,
	    const std::shared_ptr<const linphone::Address>& participantAddr) override;
	void enableSelectedCodecs(const std::list<std::shared_ptr<linphone::PayloadType>>& codecs,
	                          const std::list<std::string>& mimeTypes);
	void configureNatAddresses(std::shared_ptr<linphone::NatPolicy> policy, const std::list<std::string>& addresses);
	std::filesystem::path getUuidFilePath() const;
	std::filesystem::path getStateDir(const std::string& subdir = "") const;
	void ensureDirectoryCreated(const std::filesystem::path& directory);
	const std::string& readUuid();
	void writeUuid(const std::string& uuid);
	std::string getUuid();
	std::shared_ptr<linphone::Core> mCore{};
	std::shared_ptr<RegistrationEvent::ClientFactory> mRegEventClientFactory{};
	SipUri mPath{};
	std::shared_ptr<ConfigManager> mConfigManager;
	std::shared_ptr<RegistrarDb> mRegistrarDb;
	std::list<std::shared_ptr<linphone::ChatRoom>> mChatRooms{};
	ParticipantRegistrationSubscriptionHandler mSubscriptionHandler;
	MediaConfig mMediaConfig;
	std::list<std::pair<std::string, std::string>> mConfServerUris{};
	std::list<std::string> mLocalDomains{};
	std::string mUuid;
	bool mAddressesBound = false;
	bool mCheckCapabilities = false;
	std::filesystem::path mStateDir;
	static constexpr const char* sUuidFile = "uuid";

	static sofiasip::Home mHome;
};
} // namespace flexisip
