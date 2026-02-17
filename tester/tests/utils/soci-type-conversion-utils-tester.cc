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

#include "utils/soci-type-conversion-utils.hh"

#include <ctime>
#include <memory>
#include <optional>

#include <soci/soci.h>

#include "utils/soci/soci-tester-utils.hh"
#include "utils/string-utils.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace soci {

struct TestStructure {
	friend ostream& operator<<(ostream& stream, const TestStructure& test);

	optional<string> characters{"expected"};
	optional<double> floating_point{std::numeric_limits<double>::max()};
	optional<string> null_value{nullopt};

	mutable tm date_time{.tm_min = 52, .tm_hour = 14, .tm_mday = 16, .tm_mon = 1, .tm_year = 2026 - 1900};
	int classic_integer{std::numeric_limits<int>::max()};
	long long big_integer{std::numeric_limits<long long>::max()};
	unsigned long long big_unsigned_integer{std::numeric_limits<unsigned long long>::max()};

	bool operator==(const TestStructure& other) const noexcept {
		return other.characters == characters && other.floating_point == floating_point &&
		       other.null_value == null_value &&
		       std::difftime(std::mktime(&other.date_time), std::mktime(&date_time)) == 0 &&
		       other.classic_integer == classic_integer && other.big_integer == big_integer &&
		       other.big_unsigned_integer == big_unsigned_integer;
	}
};

ostream& operator<<(ostream& stream, const TestStructure& test) {
	stream << "{" << (test.characters.has_value() ? *test.characters : "NULL") << ", "
	       << (test.floating_point.has_value() ? to_string(*test.floating_point) : "NULL") << ", "
	       << (test.null_value.has_value() ? *test.null_value : "NULL") << ", "
	       << flexisip::string_utils::strFromTime(test.date_time) << ", " << test.classic_integer << ", "
	       << test.big_integer << ", " << test.big_unsigned_integer << "}";
	return stream;
}

using FromBaseFunc = function<void(const values&, indicator, TestStructure&)>;
static FromBaseFunc fromBaseFunc;

template <>
struct type_conversion<TestStructure> {
	using base_type = values;

	static void from_base(const values& values, indicator indicator, TestStructure& test) {
		fromBaseFunc(values, indicator, test);
	}

	static void to_base(const TestStructure& test, values& values, indicator& indicator) {
		values.set("characters", test.characters.value_or(""), test.characters.has_value() ? i_ok : i_null);
		values.set("floating_point", test.floating_point.value_or(0), test.floating_point.has_value() ? i_ok : i_null);
		values.set("null_value", test.null_value.value_or(""), test.null_value.has_value() ? i_ok : i_null);

		values.set("date_time", test.date_time);
		values.set("classic_integer", test.classic_integer);
		values.set("big_integer", test.big_integer);
		values.set("big_unsigned_integer", test.big_unsigned_integer);

		indicator = i_ok;
	}
};

} // namespace soci

using namespace soci;

namespace flexisip::tester {

template <typename DbBackend>
void test(const shared_ptr<DbBackend>& backend,
          const FromBaseFunc& func,
          const TestStructure& expected = {},
          const bool startWithEmptyStruct = true) {
	DbTestHelper<DbBackend> helper{
	    backend,
	    [&](session& session) {
		    session
		        << "create table " << DatabaseBackend::kTableName
		        << "(characters varchar(32) null, floating_point double null, null_value varchar(32) null, date_time "
		           "datetime not null, classic_integer int not null, big_integer bigint not null, big_unsigned_integer "
		           "bigint unsigned not null);";
		    session << "insert into " << DatabaseBackend::kTableName
		            << "(characters, floating_point, null_value, date_time, classic_integer, big_integer, "
		               "big_unsigned_integer) values(:characters, :floating_point, :null_value, :date_time, "
		               ":classic_integer, :big_integer, :big_unsigned_integer);",
		        use(expected);
	    },
	};

	fromBaseFunc = func;

	TestStructure actual{startWithEmptyStruct ? TestStructure{nullopt, nullopt, nullopt, {}, {}, {}, {}}
	                                          : TestStructure{}};
	helper.mClient.execute(
	    [&](session& session) { session << "SELECT * FROM " << DatabaseBackend::kTableName << ";", into(actual); });

	BC_ASSERT_CPP_EQUAL(actual, expected);
}

template <typename DbBackend>
void columnNameExists(const shared_ptr<DbBackend>& dbBackend) {
	const auto conversionFunc = [](const values& values, indicator, TestStructure&) {
		BC_ASSERT(soci_utils::columnNameExists(values, "characters"));
		BC_ASSERT(soci_utils::columnNameExists(values, "floating_point"));
		BC_ASSERT(soci_utils::columnNameExists(values, "null_value"));
		BC_ASSERT(soci_utils::columnNameExists(values, "date_time"));
		BC_ASSERT(soci_utils::columnNameExists(values, "classic_integer"));
		BC_ASSERT(soci_utils::columnNameExists(values, "big_integer"));
		BC_ASSERT(soci_utils::columnNameExists(values, "big_unsigned_integer"));

		BC_ASSERT(!soci_utils::columnNameExists(values, "unknown"));
	};
	test(dbBackend, conversionFunc, TestStructure{}, false);
}

template <typename DbBackend>
void get(const shared_ptr<DbBackend>& dbBackend) {
	const auto conversionFunc = [](const values& values, indicator, TestStructure& test) {
		if (values.get_indicator("characters") == i_null) test.characters = nullopt;
		else test.characters = soci_utils::get<string>(values, "characters");
		if (values.get_indicator("floating_point") == i_null) test.floating_point = nullopt;
		else test.floating_point = soci_utils::get<double>(values, "floating_point");
		if (values.get_indicator("null_value") == i_null) test.null_value = nullopt;
		else test.null_value = soci_utils::get<string>(values, "null_value");

		test.date_time = soci_utils::get<tm>(values, "date_time");
		test.classic_integer = soci_utils::get<int>(values, "classic_integer");
		test.big_integer = soci_utils::get<long long>(values, "big_integer");
		// Unsigned are not supported with sqlite3.
		if constexpr (!std::is_same_v<DbBackend, SqLite3Backend>) {
			test.big_unsigned_integer = soci_utils::get<unsigned long long>(values, "big_unsigned_integer");
		} else {
			test.big_unsigned_integer = soci_utils::get<long long>(values, "big_unsigned_integer");
		}
	};
	test(dbBackend, conversionFunc);
}

template <typename DbBackend>
void getWithBackwardCompatibility(const shared_ptr<DbBackend>& dbBackend) {
	const auto conversionFunc = [](const values& values, indicator, TestStructure& test) {
		test.characters = soci_utils::getWithBackwardCompatibility<string>(values, "old_characters", "characters");
		test.floating_point =
		    soci_utils::getWithBackwardCompatibility<double>(values, "old_floating_point", "floating_point");
		if (const auto null_value =
		        soci_utils::getWithBackwardCompatibility<string>(values, "old_null_value", "null_value", "");
		    !null_value.empty()) {
			test.null_value = null_value;
		}

		test.date_time = soci_utils::getWithBackwardCompatibility<tm>(values, "date_time", "old_date_time");
		test.classic_integer =
		    soci_utils::getWithBackwardCompatibility<int>(values, "classic_integer", "old_classic_integer");
		test.big_integer =
		    soci_utils::getWithBackwardCompatibility<long long>(values, "old_big_integer", "big_integer");
		// Unsigned are not supported with sqlite3.
		if constexpr (!std::is_same_v<DbBackend, SqLite3Backend>) {
			test.big_unsigned_integer = soci_utils::getWithBackwardCompatibility<unsigned long long>(
			    values, "big_unsigned_integer", "old_big_unsigned_integer");
		} else {
			test.big_unsigned_integer = soci_utils::getWithBackwardCompatibility<long long>(
			    values, "big_unsigned_integer", "old_big_unsigned_integer");
		}
	};
	test(dbBackend, conversionFunc);
}

template <typename DbBackend>
void getOptional(const shared_ptr<DbBackend>& dbBackend) {
	const auto conversionFunc = [](const values& values, indicator, TestStructure& test) {
		// Explicitly calling with an unknown colum name.
		test.characters = soci_utils::getOptional<string>(values, "unknown", "default");
		test.floating_point = soci_utils::getOptional<double>(values, "floating_point", 12.0);
		// Explicitly calling with an unknown colum name.
		if (const auto null_value = soci_utils::getOptional<string>(values, "unknown", ""); !null_value.empty())
			test.null_value = null_value;

		test.date_time = soci_utils::get<tm>(values, "date_time");
		test.classic_integer = soci_utils::get<int>(values, "classic_integer");
		test.big_integer = soci_utils::get<long long>(values, "big_integer");
		// Unsigned are not supported with sqlite3.
		if constexpr (!std::is_same_v<DbBackend, SqLite3Backend>) {
			test.big_unsigned_integer = soci_utils::get<unsigned long long>(values, "big_unsigned_integer");
		} else {
			test.big_unsigned_integer = soci_utils::get<long long>(values, "big_unsigned_integer");
		}
	};
	test(dbBackend, conversionFunc, TestStructure{.characters = "default", .floating_point = 42.0});
}

namespace sqlite3 {

shared_ptr<SqLite3Backend> sBackend{};

void columnNameExists() {
	columnNameExists(sBackend);
}

void get() {
	get(sBackend);
}

void getWithBackwardCompatibility() {
	getWithBackwardCompatibility(sBackend);
}

void getOptional() {
	getOptional(sBackend);
}

TestSuite _{
    "SociTypeConversion::sqlite3",
    {
        CLASSY_TEST(columnNameExists),
        CLASSY_TEST(get),
        CLASSY_TEST(getWithBackwardCompatibility),
        CLASSY_TEST(getOptional),
    },
    Hooks{}
        .beforeSuite([] {
	        sBackend = make_shared<SqLite3Backend>();
	        return 0;
        })
        .beforeEach([] { sBackend->clear(); })
        .afterSuite([] {
	        sBackend.reset();
	        return 0;
        }),
};

} // namespace sqlite3

namespace mysql {

shared_ptr<MySqlBackend> sBackend{};

void columnNameExists() {
	columnNameExists(sBackend);
}

void get() {
	get(sBackend);
}

void getWithBackwardCompatibility() {
	getWithBackwardCompatibility(sBackend);
}

void getOptional() {
	getOptional(sBackend);
}

TestSuite _{
    "SociTypeConversion::mysql",
    {
        CLASSY_TEST(columnNameExists),
        CLASSY_TEST(get),
        CLASSY_TEST(getWithBackwardCompatibility),
        CLASSY_TEST(getOptional),
    },
    Hooks{}
        .beforeSuite([] {
	        sBackend = make_shared<MySqlBackend>();
	        return 0;
        })
        .beforeEach([] {
	        if (sBackend->isStopped()) sBackend->restart();
	        sBackend->clear();
        })
        .afterSuite([] {
	        sBackend.reset();
	        return 0;
        }),
};

} // namespace mysql
} // namespace flexisip::tester