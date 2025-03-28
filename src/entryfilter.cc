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

#include <stdexcept>

#include "flexisip/module.hh"
#include "flexisip/sip-boolean-expressions.hh"

#include "exceptions/bad-configuration.hh"

using namespace std;
using namespace flexisip;

void ConfigEntryFilter::declareConfig(GenericStruct& moduleConfig) {
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

	    // Deprecated parameters
	    {
	        String,
	        "from-domains",
	        "Deprecated: List of domain names in sip from allowed to enter the module.",
	        "*",
	    },
	    {
	        String,
	        "to-domains",
	        "Deprecated: List of domain names in sip to allowed to enter the module.",
	        "*",
	    },
	    config_item_end,
	};

	moduleConfig.addChildrenValues(config, false);
	moduleConfig.deprecateChild("from-domains", {"2012-09-04", "0.5.0", "Use 'filter' setting instead."});
	moduleConfig.deprecateChild("to-domains", {"2012-09-04", "0.5.0", "Use 'filter' setting instead."});
	moduleConfig.createStat("count-eval-true", "Number of filter evaluations to true.");
	moduleConfig.createStat("count-eval-false", "Number of filter evaluations to false.");
}

ConfigEntryFilter::ConfigEntryFilter(GenericStruct& moduleConfig) {
	mCountEvalTrue = moduleConfig.getStat("count-eval-true");
	mCountEvalFalse = moduleConfig.getStat("count-eval-false");
}

void ConfigEntryFilter::loadConfig(const GenericStruct* mc) {
	string filter = mc->get<ConfigValue>("filter")->get();

	if (filter.empty()) {
		string fromDomains = mc->get<ConfigString>("from-domains")->read();
		if (!fromDomains.empty() && fromDomains != "*") {
			filter = "(from.uri.domain in '" + fromDomains + "')";
		}

		string toDomains = mc->get<ConfigString>("to-domains")->read();
		if (!toDomains.empty() && toDomains != "*") {
			if (!filter.empty()) filter += " && ";
			filter += "(to.uri.domain in '" + toDomains + "')";
		}
	}
	mEnabled = mc->get<ConfigBoolean>("enabled")->read();
	try {
		mBooleanExprFilter = SipBooleanExpressionBuilder::get().parse(filter);
	} catch (exception& e) {
		throw BadConfiguration{"could not parse entry filter for module '" + mc->getName() + "' (" + e.what() + ")"};
	}
	mEntryName = mc->getName();
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