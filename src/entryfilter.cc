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

#include "entryfilter.hh"

#include "flexisip/sofia-wrapper/msg-sip.hh"

using namespace std;
using namespace flexisip;

void ConfigEntryFilter::declareConfig(GenericStruct& mc) {
	ConfigItemDescriptor config[] = {
	    {
	        Boolean,
	        "enabled",
	        "Indicate whether the module is activated.",
	        "true",
	    },
	    {
	        BooleanExpr,
	        "filter",
	        "A request/response enters module if the boolean filter evaluates to true. Ex: from.uri.domain contains "
	        "'sip.linphone.org', from.uri.domain in 'a.org b.org c.org', (to.uri.domain in 'a.org b.org c.org') && "
	        "(user-agent == 'Linphone v2'). You can consult the full filter documentation here: "
	        "https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/Filter%20syntax/",
	        "",
	    },
	    config_item_end,
	};

	mc.addChildrenValues(config, false);
	mc.createStat("count-eval-true", "Number of filter evaluations to true.");
	mc.createStat("count-eval-false", "Number of filter evaluations to false.");
}

ConfigEntryFilter::ConfigEntryFilter(GenericStruct& mc) {
	mCountEvalTrue = mc.getStat("count-eval-true");
	mCountEvalFalse = mc.getStat("count-eval-false");
}

void ConfigEntryFilter::loadConfig(const GenericStruct* mc) {
	mEnabled = mc->get<ConfigBoolean>("enabled")->read();
	if (!mEnabled) {
		return;
	}

	mEntryName = mc->getName();
	mBooleanExprFilter = mc->get<ConfigBooleanExpression>("filter")->read();
	mBooleanExprFilter->disableLogging();
}

bool ConfigEntryFilter::canEnter(const shared_ptr<MsgSip>& ms) {
	bool e = mBooleanExprFilter->eval(*ms->getSip());
	if (e) ++(*mCountEvalTrue);
	else ++(*mCountEvalFalse);
	return e;
}

bool ConfigEntryFilter::isEnabled() {
	return mEnabled;
}