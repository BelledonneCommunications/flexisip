/*
Flexisip, a flexible SIP proxy server with media capabilities.
Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

This program is free software: you can redistribute it and/or modify
                                                                 it under the terms of the GNU Affero General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version.

    This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "flexisip/configmanager.hh"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono_literals;

namespace flexisip::tester {

class ConfigDurationTest : public Test {
public:
	void operator()() override {
		/*
		 * CASE : ConfigDuration<chrono::milliseconds> test without unit.
		 */
		ConfigDuration<chrono::milliseconds> durationMS("test", "doc", "1234ms", 1);
		durationMS.set("42");
		BC_ASSERT_TRUE(durationMS.read() == 42ms);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::seconds> test without unit.
		 */
		ConfigDuration<chrono::seconds> durationS("test", "doc", "1234s", 1);
		durationS.set("42");
		BC_ASSERT_TRUE(durationS.read() == 42s);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::minutes> test without unit.
		 */
		ConfigDuration<chrono::minutes> durationMIN("test", "doc", "1234min", 1);
		durationMIN.set("42");
		BC_ASSERT_TRUE(durationMIN.read() == 42min);
		/*-------------------------------*/

		/*
		 * CASE : specified value has too high precision for this parameter (precision(ms) > precision(s)).
		 */
		ConfigDuration<chrono::seconds> durationS_ms("test", "doc", "1234s", 1);
		durationS_ms.set("42ms");
		BC_ASSERT_THROWN(durationS_ms.read(), std::runtime_error);
		/*-------------------------------*/

		/*
		 * CASE : specified value has too high precision for this parameter (precision(ms) > precision(min)).
		 */
		ConfigDuration<chrono::minutes> durationMIN_ms("test", "doc", "1234min", 1);
		durationMIN_ms.set("42ms");
		BC_ASSERT_THROWN(durationMIN_ms.read(), std::runtime_error);
		/*-------------------------------*/

		/*
		 * CASE : specified value has too high precision for this parameter (precision(s) > precision(min)).
		 */
		ConfigDuration<chrono::minutes> durationMIN_s("test", "doc", "1234min", 1);
		durationMIN_s.set("42s");
		BC_ASSERT_THROWN(durationMIN_s.read(), std::runtime_error);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with "ms" unit.
		 */
		ConfigDuration<chrono::milliseconds> duration_unit_ms("test", "doc", "1234ms", 1);
		duration_unit_ms.set("42ms");
		BC_ASSERT_TRUE(duration_unit_ms.read() == 42ms);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with "s" unit.
		 */
		ConfigDuration<chrono::milliseconds> duration_unit_s("test", "doc", "1234s", 1);
		duration_unit_s.set("42s");
		BC_ASSERT_TRUE(duration_unit_s.read() == 42s);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with "min" unit.
		 */
		ConfigDuration<chrono::milliseconds> duration_unit_min("test", "doc", "1234min", 1);
		duration_unit_min.set("42min");
		BC_ASSERT_TRUE(duration_unit_min.read() == 42min);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with "h" unit.
		 */
		ConfigDuration<chrono::milliseconds> duration_unit_h("test", "doc", "1234h", 1);
		duration_unit_h.set("42h");
		BC_ASSERT_TRUE(duration_unit_h.read() == 42h);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with "d" unit.
		 */
		ConfigDuration<chrono::milliseconds> duration_unit_d("test", "doc", "1234d", 1);
		duration_unit_d.set("42d");
		BC_ASSERT_TRUE(duration_unit_d.read() == 42 * 24h);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with "m" unit.
		 */
		ConfigDuration<chrono::milliseconds> duration_unit_m("test", "doc", "1234m", 1);
		duration_unit_m.set("42m");
		BC_ASSERT_TRUE(duration_unit_m.read() == 42 * (30.436875 * 24h));
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with "y" unit.
		 */
		ConfigDuration<chrono::milliseconds> duration_unit_y("test", "doc", "1234y", 1);
		duration_unit_y.set("42y");
		BC_ASSERT_TRUE(duration_unit_y.read() == 42 * (365.2425 * 24h));
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with an unknown unit.
		 */
		ConfigDuration<chrono::milliseconds> duration_unknown_unit("test", "doc", "1234uu", 1);
		duration_unknown_unit.set("42uu");
		BC_ASSERT_THROWN(duration_unknown_unit.read(), std::runtime_error);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with the unit set before the value.
		 */
		ConfigDuration<chrono::milliseconds> duration_unit_before_value("test", "doc", "ms1234", 1);
		duration_unit_before_value.set("ms42");
		BC_ASSERT_THROWN(duration_unit_before_value.read(), std::runtime_error);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with only the unit.
		 */
		ConfigDuration<chrono::milliseconds> duration_unit_only("test", "doc", "ms", 1);
		duration_unit_only.set("ms");
		BC_ASSERT_THROWN(duration_unit_only.read(), std::runtime_error);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with only text.
		 */
		ConfigDuration<chrono::milliseconds> duration_text_only("test", "doc", "text", 1);
		duration_text_only.set("text");
		BC_ASSERT_THROWN(duration_text_only.read(), std::runtime_error);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with multiple values and units.
		 */
		ConfigDuration<chrono::milliseconds> duration_multiple_values_and_units("test", "doc", "1234s1234ms", 1);
		duration_multiple_values_and_units.set("42s42ms");
		BC_ASSERT_THROWN(duration_multiple_values_and_units.read(), std::runtime_error);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with value set as a floating point value.
		 */
		ConfigDuration<chrono::milliseconds> duration_float("test", "doc", "1234.5", 1);
		duration_float.set("42.0");
		BC_ASSERT_THROWN(duration_float.read(), std::runtime_error);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with value set as a floating point value plus a unit.
		 */
		ConfigDuration<chrono::milliseconds> duration_float_and_unit("test", "doc", "1234.5ms", 1);
		duration_float_and_unit.set("42.0ms");
		BC_ASSERT_THROWN(duration_float_and_unit.read(), std::runtime_error);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with a value which contains other data in the string value.
		 */
		ConfigDuration<chrono::milliseconds> duration_text_before("test", "doc", "1234.5ms", 1);
		duration_text_before.set("text 42d");
		BC_ASSERT_THROWN(duration_text_before.read(), std::runtime_error);
		/*-------------------------------*/

		/*
		 * CASE : ConfigDuration<chrono::milliseconds> with a value which contains other data in the string value.
		 */
		ConfigDuration<chrono::milliseconds> duration_text_after("test", "doc", "1234.5ms", 1);
		duration_text_after.set("42d text");
		BC_ASSERT_THROWN(duration_text_after.read(), std::runtime_error);
		/*-------------------------------*/

		/*
		 * CASE : string parameter with a space character between the value and the unit.
		 */
		ConfigDuration<chrono::milliseconds> duration_space_between("test", "doc", "1234 ms", 1);
		duration_space_between.set("42 ms");
		BC_ASSERT_THROWN(duration_space_between.read(), std::runtime_error);
		/*-------------------------------*/
	}
};

namespace {
TestSuite _("ConfigValue unit tests",
            {
                TEST_NO_TAG("Test reading of duration parameters", run<ConfigDurationTest>),
            });
}
} // namespace flexisip::tester
