/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "configdumper.hh"

#include "flexisip/configmanager.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace flexisip;
namespace flexisip::tester {
namespace {
class ConfigDumperTester : public ConfigDumper {
public:
	ConfigDumperTester(RootConfigStruct* root) : ConfigDumper(root) {
		ConfigItemDescriptor items[] = {
		    {
		        Boolean,
		        "first-param",
		        "",
		        "true",
		    },
		    {
		        String,
		        "second-param",
		        "",
		        "default value",
		    },
		    config_item_end,
		};

		mSection = root->addChild(std::make_unique<GenericStruct>("section name", "super description", 0));
		mSection->addChildrenValues(items);
	}

	bool shouldDumpDeprecatedSection(const GenericStruct* element) const {
		return ConfigDumper::shouldDumpDeprecatedSection(element, 1);
	}

	bool shouldDumpValue(const ConfigValue* val) const {
		return ConfigDumper::shouldDumpValue(val);
	}

	GenericStruct* getSection() {
		return mSection;
	}

private:
	std::ostream& dumpSectionHead(std::ostream& ostr, const GenericStruct*, int) const override {
		return ostr;
	}
	std::ostream& dumpValue(std::ostream& ostr, const ConfigValue*, int) const override {
		return ostr;
	}

	GenericStruct* mSection{};
};

void shouldDumpDeprecatedSection() {
	RootConfigStruct configRoot{"flexisip-tester", "Fake configuration for testing purposes", {}, ""};
	ConfigDumperTester dumper{&configRoot};

	auto* section = dumper.getSection();
	section->setDeprecated("2026-06-03", "2.6", "Deprecated section");

	// All parameters of the section have their default value, it should not be dumped
	BC_ASSERT_CPP_EQUAL(dumper.shouldDumpDeprecatedSection(section), false);

	// A parameter of the section have an epxlicit value, it should be dumped
	section->get<ConfigString>("second-param")->set("something");
	BC_ASSERT_CPP_EQUAL(dumper.shouldDumpDeprecatedSection(section), true);

	// With "setRemoveDeprecated", deprecated sections should never be dumped
	dumper.setRemoveDeprecated(true);
	BC_ASSERT_CPP_EQUAL(dumper.shouldDumpDeprecatedSection(section), false);
}

void shouldDumpStandardParameter() {
	RootConfigStruct configRoot{"flexisip-tester", "Fake configuration for testing purposes", {}, ""};
	ConfigDumperTester dumper{&configRoot};
	auto* entry = dumper.getSection()->get<ConfigBoolean>("first-param");
	auto* value = dynamic_cast<const ConfigValue*>(entry);
	BC_ASSERT_CPP_EQUAL(dumper.shouldDumpValue(value), true);

	dumper.setRemoveDeprecated(true);
	BC_ASSERT_CPP_EQUAL(dumper.shouldDumpValue(value), true);
}

void shouldDumpDeprecatedParameter() {
	RootConfigStruct configRoot{"flexisip-tester", "Fake configuration for testing purposes", {}, ""};
	ConfigDumperTester dumper{&configRoot};
	auto* entry = dumper.getSection()->get<ConfigBoolean>("first-param");
	entry->setDeprecated("2026-06-03", "2.6", "Deprecated parameter");

	auto* value = dynamic_cast<const ConfigValue*>(entry);
	BC_ASSERT_CPP_EQUAL(dumper.shouldDumpValue(value), false);
}

void shouldDumpDeprecatedParameterWithValue() {
	RootConfigStruct configRoot{"flexisip-tester", "Fake configuration for testing purposes", {}, ""};
	ConfigDumperTester dumper{&configRoot};
	auto* entry = dumper.getSection()->get<ConfigBoolean>("first-param");
	auto* value = dynamic_cast<const ConfigValue*>(entry);
	entry->setDeprecated("2026-06-03", "2.6", "Deprecated parameter");
	entry->set("true");

	BC_ASSERT_CPP_EQUAL(dumper.shouldDumpValue(value), true);

	dumper.setRemoveDeprecated(true);
	BC_ASSERT_CPP_EQUAL(dumper.shouldDumpValue(value), false);
}

TestSuite _("ConfigDumper",
            {
                CLASSY_TEST(shouldDumpDeprecatedSection),
                CLASSY_TEST(shouldDumpStandardParameter),
                CLASSY_TEST(shouldDumpDeprecatedParameter),
                CLASSY_TEST(shouldDumpDeprecatedParameterWithValue),
            });

} // namespace
} // namespace flexisip::tester