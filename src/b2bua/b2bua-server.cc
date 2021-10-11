/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2020  Belledonne Communications SARL, All rights reserved.

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

#include "b2bua-server.hh"
#include "flexisip/logmanager.hh"
#include "flexisip/utils/sip-uri.hh"
#include "flexisip/configmanager.hh"
using namespace std;
using namespace linphone;

namespace flexisip {

B2buaServer::Init B2buaServer::sStaticInit; // The Init object is instanciated to load the config

B2buaServer::B2buaServer (su_root_t *root) : ServiceServer(root) {}

B2buaServer::~B2buaServer () {}

void B2buaServer::onCallStateChanged(const std::shared_ptr<linphone::Core > &core, const std::shared_ptr<linphone::Call> &call,
			linphone::Call::State state, const std::string &message) {
	LOGD("b2bua server onCallStateChanged: %d", (int)state);
	switch (state) {
		case linphone::Call::State::IncomingReceived:
			{
			//TODO: Here we already sent a 100 Trying and a 180 Ringing that shall not be done before receiving answers from the legB call
			LOGD("b2bua server onCallStateChanged incomingReceived, to %s from %s", call->getToAddress()->asString().c_str(), call->getRemoteAddress()->asString().c_str());
			// Create outgoing call using parameters created from the incoming call in order to avoid duplicating the callId
			auto outgoingCallParams = mCore->createCallParams(call);
			// add this custom header so this call will not be intercepted by the b2bua
			outgoingCallParams->addCustomHeader("flexisip-b2bua", "ignore");
			//TODO: copy the From header from incoming to the outgoing call
			outgoingCallParams->addCustomHeader("From", call->getRemoteAddress()->asString()+";tag=tototo");

            auto b2bua_legB_call = new std::shared_ptr<linphone::Call>;
            *b2bua_legB_call = mCore->inviteAddressWithParams(call->getToAddress(),  outgoingCallParams);

            auto b2bua_legA_call = new std::shared_ptr<linphone::Call>;
            *b2bua_legA_call = call;

			// store ref to call in each other
			call->setData<std::shared_ptr<linphone::Call>>(B2buaServer::callKey, *b2bua_legB_call);
			(*b2bua_legB_call)->setData<std::shared_ptr<linphone::Call>>(B2buaServer::callKey, *b2bua_legA_call);
			}
			break;
		case linphone::Call::State::PushIncomingReceived:
			break;
		case linphone::Call::State::OutgoingInit:
			break;
		case linphone::Call::State::OutgoingProgress:
			break;
		case linphone::Call::State::OutgoingRinging:
			// TODO: forward the ringing to the original caller
			break;
		case linphone::Call::State::OutgoingEarlyMedia:
			break;
		case linphone::Call::State::Connected:
			break;
		case linphone::Call::State::StreamsRunning:
        {
            LOGD("b2bua server onCallStateChanged StreamRunning");
			// Do we have a ref to a peer call (it shall always be the case)
			if (!call->dataExists(B2buaServer::callKey)) {
				LOGE("B2bua Stream running but no peer call found, terminate it");
				call->terminate();
				return;
			}
			auto peerCall = call->getData<std::shared_ptr<linphone::Call>>(B2buaServer::callKey);

			// Do we have a conference associated to this call?
			if (!call->dataExists(B2buaServer::confKey)) { // No conference, this is legB answering to our call
				// create a conference
				auto conferenceParams = mCore->createConferenceParams();
				conferenceParams->setVideoEnabled(false);
				conferenceParams->setLocalParticipantEnabled(false); // b2bua core is not part of it
				auto conference = new std::shared_ptr<linphone::Conference>;
                *conference = mCore->createConferenceWithParams(conferenceParams);
				// Add legB
				(*conference)->addParticipant(call);
                (*conference)->addParticipant(peerCall);
				// reference conferences in both calls
				call->setData<std::shared_ptr<linphone::Conference>>(B2buaServer::confKey, *conference);
				peerCall->setData<std::shared_ptr<linphone::Conference>>(B2buaServer::confKey, *conference);
				// answer legA
                auto incomingCallParams = mCore->createCallParams(nullptr);
                // add this custom header so this call will not be intercepted by the b2bua
                incomingCallParams->addCustomHeader("flexisip-b2bua", "ignore");
				peerCall->acceptWithParams(incomingCallParams);
			} else { // This is legA sending 200Ok after we accepted the call, add it to the conference
				//auto conference = call->getData<std::shared_ptr<linphone::Conference>>(B2buaServer::confKey);
				//conference->addParticipant(call);
                LOGD("b2bua server onCallStateChanged StreamRunning: leg A stream runnning");
			}
        }
			break;
		case linphone::Call::State::Pausing:
			break;
		case linphone::Call::State::Paused:
			break;
		case linphone::Call::State::Resuming:
			break;
		case linphone::Call::State::Referred:
			break;
		case linphone::Call::State::Error:
			break;
		case linphone::Call::State::End:
        {
            if (call->dataExists(B2buaServer::callKey)) { // This is the first call ending
                // Get the other call
                auto peerCall = call->getData<std::shared_ptr<linphone::Call>>(B2buaServer::callKey);
                // Unset the callKey so it is not linked to this call anymore
                peerCall->unsetData(B2buaServer::callKey);
                // terminate it
                peerCall->terminate();

                // Get the conference and terminate it
                auto conference = call->getData<std::shared_ptr<linphone::Conference>>(B2buaServer::confKey);
                conference->terminate();
            }
        }
			break;
		case linphone::Call::State::PausedByRemote:
			break;
		case linphone::Call::State::UpdatedByRemote:
			break;
		case linphone::Call::State::IncomingEarlyMedia:
			break;
		case linphone::Call::State::Updating:
			break;
		case linphone::Call::State::Released:
			break;
		case linphone::Call::State::EarlyUpdating:
			break;
		case linphone::Call::State::EarlyUpdatedByRemote:
			break;

		default:
			break;
	}
}

void B2buaServer::_init () {
	auto configLinphone = Factory::get()->createConfig("");
	configLinphone->setBool("misc", "conference_server_enabled", 1);
	configLinphone->setInt("misc", "max_calls", 1000);
	configLinphone->setInt("misc", "media_resources_mode", 1); // share media resources
	configLinphone->setBool("sip", "reject_duplicated_calls", false);
	mCore = Factory::get()->createCoreWithConfig(configLinphone, nullptr);
	mCore->setCallLogsDatabasePath(" ");
	mCore->setZrtpSecretsFile(" ");
	mCore->getConfig()->setString("storage", "backend", "sqlite3");
	mCore->getConfig()->setString("storage", "uri", ":memory:");
	mCore->setUseFiles(true); //No sound card shall be used in calls
	mCore->enableEchoCancellation(false);

	// random port for UDP audio stream
	mCore->setAudioPort(-1);

	shared_ptr<Transports> b2buaTransport = Factory::get()->createTransports();
	auto config = GenericManager::get()->getRoot()->get<GenericStruct>("b2bua-server");
	string mTransport = config->get<ConfigString>("transport")->read();
	if (mTransport.length() > 0) {
		sofiasip::Home mHome;
		url_t *urlTransport = url_make(mHome.home(), mTransport.c_str());
		if (urlTransport == nullptr || mTransport.at(0) == '<') {
			LOGF("B2bua server: Your configured conference transport(\"%s\") is not an URI.\n"
				"If you have \"<>\" in your transport, remove them.", mTransport.c_str());
		}
		b2buaTransport->setTcpPort(stoi(urlTransport->url_port));
	}

	mCore->setTransports(b2buaTransport);
	mCore->addListener(shared_from_this());
	mCore->start();
}

void B2buaServer::_run () {
	mCore->iterate();
}

void B2buaServer::_stop () {
	mCore->removeListener(shared_from_this());
}

B2buaServer::Init::Init() {
	ConfigItemDescriptor items[] = {
		{
			String,
			"transport",
			"SIP uri on which the back-to-back user agent server is listening on.",
			"sip:127.0.0.1:6067;transport=tcp"
		},
		config_item_end
	};

	auto uS = make_unique<GenericStruct>(
	    "b2bua-server",
	    "Flexisip back-to-back user agent server parameters.",
	    0);
	auto s = GenericManager::get()->getRoot()->addChild(move(uS));
	s->addChildrenValues(items);
}

}
