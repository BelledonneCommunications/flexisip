/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <cstring>
#include <memory>

#include "flexisip/event.hh"

namespace flexisip {

class Transaction {
public:
	explicit Transaction(std::weak_ptr<Agent> agent) noexcept : mAgent{std::move(agent)} {
	}
	Transaction(const Transaction&) = delete;
	virtual ~Transaction() = default;

	virtual std::weak_ptr<Agent> getAgent() noexcept {
		return mAgent;
	}

	template <typename T, typename StrT>
	void setProperty(StrT&& name, const std::shared_ptr<T>& value) noexcept {
		auto typeName = typeid(T).name();
		mWeakProperties.erase(name); // ensures the property value isn't in the two lists both.
		mProperties[std::forward<StrT>(name)] = Property{value, typeName};
	}

	template <typename T, typename StrT>
	void setProperty(StrT&& name, const std::weak_ptr<T>& value) noexcept {
		auto typeName = typeid(T).name();
		mProperties.erase(name); // ensures the property value isn't in the two lists both.
		mWeakProperties[std::forward<StrT>(name)] = WProperty{value, typeName};
	}

	template <typename T>
	std::shared_ptr<T> getProperty(const std::string& name) const {
		auto prop = _getProperty(name);
		if (prop.value == nullptr) return nullptr;
		if (std::strcmp(prop.type, typeid(T).name()) != 0) {
			throw std::bad_cast{};
		}
		return std::static_pointer_cast<T>(prop.value);
	}

	void removeProperty(const std::string& name) noexcept {
		mProperties.erase(name);
		mWeakProperties.erase(name);
	}

protected:
	struct Property {
		Property() = default;
		template <typename PtrT>
		Property(PtrT&& value, const char* type) noexcept : value{std::forward<PtrT>(value)}, type{type} {
		}

		std::shared_ptr<void> value{};
		const char* type{nullptr};
	};
	struct WProperty {
		WProperty() = default;
		template <typename PtrT>
		WProperty(PtrT&& value, const char* type) noexcept : value{std::forward<PtrT>(value)}, type{type} {
		}

		std::weak_ptr<void> value{};
		const char* type{nullptr};
	};

	Property _getProperty(const std::string& name) const noexcept;

	void looseProperties() noexcept {
		mProperties.clear();
		mWeakProperties.clear();
	}

	std::weak_ptr<Agent> mAgent = std::weak_ptr<Agent>{};
	std::unordered_map<std::string, Property> mProperties{};
	std::unordered_map<std::string, WProperty> mWeakProperties{};
};

} // namespace flexisip
