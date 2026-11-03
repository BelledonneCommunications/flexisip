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

#include "refer-tweaker.hh"

#include "string-format-fields.hh"

using namespace std;

namespace flexisip::b2bua::bridge {

namespace {

const auto kReferTweakerFields = FieldsOf<LinphoneCallContext const&, Account const&>{
    {
        "incoming",
        resolve(kLinphoneCallContextFields, [](const auto& context, const auto&) -> const auto& { return context; }),
    },
    {
        "account",
        resolve(kAccountFields, [](const auto&, const auto& account) -> const auto& { return account; }),
    },
};

} // namespace

ReferTweaker::ReferTweaker(const config::v2::OutgoingInvite& config)
    : mToHeader(config.to, kReferTweakerFields),
      mFromHeader(config.from.empty() ? "{account.uri}" : config.from, kReferTweakerFields) {}

std::shared_ptr<linphone::Address> ReferTweaker::tweakRefer(const LinphoneCallContext& context,
                                                            const Account& account,
                                                            HeaderTranslation headerTranslation) const {
	const auto& headerTemplate = headerTranslation == HeaderTranslation::To ? mToHeader : mFromHeader;
	const auto referTo = formatHeader(headerTemplate, context, account, "Refer-To");
	return linphone::Factory::get()->createAddress(referTo);
}

} // namespace flexisip::b2bua::bridge