/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <memory>

#include <linphone++/call.hh>
#include <linphone++/enums.hh>

#include "utils/client-builder.hh"

namespace flexisip {
namespace tester {

class CoreClient;
class ClientCall;

class CallBuilder {
public:
	explicit CallBuilder(const CoreClient&);

	const CallBuilder& setEarlyMediaSending(OnOff) const;
	const CallBuilder& setVideo(OnOff) const;
	ClientCall call(const std::string&) const;

private:
	const CoreClient& mClient;
	const std::shared_ptr<linphone::CallParams> mParams;
};

} // namespace tester
} // namespace flexisip
