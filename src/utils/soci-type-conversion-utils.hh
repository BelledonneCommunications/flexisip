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

#pragma once

#include <optional>
#include <string>
#include <type_traits>

#include <soci/soci.h>

namespace flexisip::soci_utils {
/**
 * @tparam CppType cpp type corresponding to a database type
 * @return the corresponding soci database enum from the provided cpp type
 */
template <typename CppType>
static soci::data_type cppTypeToSociEnumDbType() {
	if (std::is_same_v<CppType, std::string>) return soci::dt_string;
	if (std::is_same_v<CppType, std::tm>) return soci::dt_date;
	if (std::is_same_v<CppType, double>) return soci::dt_double;
	if (std::is_same_v<CppType, int>) return soci::dt_integer;
	if (std::is_same_v<CppType, long long>) return soci::dt_long_long;
	if (std::is_same_v<CppType, unsigned long long>) return soci::dt_unsigned_long_long;
	if (std::is_same_v<CppType, soci::blob>) return soci::dt_blob;
	if (std::is_same_v<CppType, soci::xml_type>) return soci::dt_xml;
	return static_cast<soci::data_type>(-1);
}

/**
 * @param type soci enum db type
 * @return the string representation of the provided soci enum db type
 */
static std::string sociEnumDbTypeToString(const soci::data_type& type) {
	if (type == soci::dt_string) return "string";
	if (type == soci::dt_date) return "timestamp";
	if (type == soci::dt_double) return "floating-point";
	if (type == soci::dt_integer) return "integer";
	if (type == soci::dt_long_long) return "big integer";
	if (type == soci::dt_unsigned_long_long) return "unsigned big integer";
	if (type == soci::dt_blob) return "blob";
	if (type == soci::dt_xml) return "xml";
	return "unknown";
}

/**
 * @return 'true' if the column is found, 'false' otherwise.
 */
static bool columnNameExists(const soci::values& values, const std::string& name) {
	const size_t nbColumns = values.get_number_of_columns();
	for (size_t columnId = 0; columnId < nbColumns; ++columnId) {
		if (values.get_properties(columnId).get_name() == name) return true;
	}
	return false;
}

/**
 * @throw runtime_error if the column 'name' does not exist
 * @throw runtime_error if the column 'name' has an invalid data type
 * @return the value of the column 'name'
 */
template <typename DbType>
static DbType
get(const soci::values& values, const std::string& name, const std::optional<DbType>& nullValue = std::nullopt) {
	if (!columnNameExists(values, name)) throw std::runtime_error{"column '" + name + "' does not exist"};

	const auto dataType = values.get_properties(name).get_data_type();
	if (cppTypeToSociEnumDbType<DbType>() != dataType) {
		const auto typeName = sociEnumDbTypeToString(dataType);
		const auto expectedTypeName = sociEnumDbTypeToString(cppTypeToSociEnumDbType<DbType>());
		throw std::runtime_error{"invalid data type '" + typeName + "' in database for column '" + name +
		                         "' (expected: '" + expectedTypeName + "')"};
	}

	if (nullValue.has_value()) return values.get<DbType>(name, *nullValue);
	return values.get<DbType>(name);
}

/**
 * @throw runtime_error if both columns do not exist
 * @throw runtime_error if either the column 'name' or 'oldName' has an invalid data type
 * @return the value of the column 'name' or 'oldName' if the column does not exist
 */
template <typename T>
static T getWithBackwardCompatibility(const soci::values& values,
                                      const std::string& name,
                                      const std::string& oldName,
                                      const std::optional<T>& nullValue = std::nullopt) {
	if (columnNameExists(values, name)) return get<T>(values, name, nullValue);
	if (columnNameExists(values, oldName)) return get<T>(values, oldName, nullValue);
	throw std::runtime_error{"column '" + name + "' or '" + oldName + "' do not exist"};
}

/**
 * @throw runtime_error if the column 'name' has an invalid data type
 * @return the value of the column 'name' or 'defaultValue' if the column does not exist or is null
 */
template <typename T>
static T getOptional(const soci::values& values, const std::string& name, const T& defaultValue) {
	if (!columnNameExists(values, name)) return defaultValue;
	if (values.get_indicator(name) == soci::i_null) return defaultValue;
	return get(values, name, std::optional<T>{defaultValue});
}

} // namespace flexisip::soci_utils