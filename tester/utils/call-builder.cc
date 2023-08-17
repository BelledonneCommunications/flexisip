/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "call-builder.hh"

#include <memory>
#include <string>

#include "linphone++/enums.hh"

#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/test-patterns/test.hh"

namespace flexisip::tester {

CallBuilder::CallBuilder(const CoreClient& client)
    : mClient(client), mParams(mClient.getCore()->createCallParams(nullptr)) {
}

ClientCall CallBuilder::call(const std::string& destination) const {
	return mClient.invite(destination, mParams);
}

const CallBuilder& CallBuilder::setEarlyMediaSending(OnOff enabled) const {
	mParams->enableEarlyMediaSending(bool(enabled));
	return *this;
}
const CallBuilder& CallBuilder::setVideo(OnOff enabled) const {
	mParams->enableVideo(bool(enabled));
	return *this;
}

} // namespace flexisip::tester
