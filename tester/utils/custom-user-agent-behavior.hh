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

#include <linphone++/call.hh>
#include <linphone++/call_params.hh>
#include <linphone++/core.hh>
#include <linphone++/core_listener.hh>

#include "flexisip/logmanager.hh"

/*
 * Custom linphone::CoreListener in order to make a client behave as a particular UAC/UAS.
 * Introduced during the Jabiru project.
 */
class JabiruServerBehavior : public linphone::CoreListener {
public:
	void onCallStateChanged(const std::shared_ptr<linphone::Core>&,
	                        const std::shared_ptr<linphone::Call>& call,
	                        linphone::Call::State state,
	                        const std::string&) override {
		SLOGD << "Call state is now set to " << static_cast<int>(state);
		switch (state) {
			case linphone::Call::State::Resuming: {
				SLOGD << "Call is in state Resuming, change audio direction in local params to SendRecv";
				setAudioDirectionToSendRecv(call);
			} break;
			default:
				break;
		}
	}

private:
	/*
	 * Set audio direction to SendRecv in the local parameters of the client.
	 * Changes will be taken into account during the very next SDP negotiation.
	 */
	static void setAudioDirectionToSendRecv(const std::shared_ptr<linphone::Call>& call) {
		const auto localParams = std::const_pointer_cast<linphone::CallParams>(call->getParams());
		localParams->setAudioDirection(linphone::MediaDirection::SendRecv);
	}
};