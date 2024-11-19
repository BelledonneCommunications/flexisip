/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

namespace flexisip::tester {

/** A lazily initialized objet.
 *
 * Construction of the object is delayed until the first time it is accessed.
 * (i.e. one of the accessor methods is called.)
 *
 * Wrapped type T must have a default constructor
 */
template <typename T>
class Lazy {
public:
	explicit Lazy() = default;

	/**
	 * Obtain a reference to the wrapped object, initializing it if it isn't already.
	 * (The reference is guaranteed to be valid.)
	 */
	T& operator*() {
		if (!mObject.has_value()) {
			mObject.emplace();
		}
		return *mObject;
	}

	/**
	 * Access the wrapped object, initializing it if it isn't already.
	 * (The pointer is guaranteed to be non-null and valid.)
	 */
	T* operator->() {
		return &this->operator*();
	}

	/**
	 * Destructs the wrapped object.
	 * (Note that it will be constructed again upon the next access.)
	 */
	void reset() {
		return mObject.reset();
	}

private:
	std::optional<T> mObject = std::nullopt;
};

} // namespace flexisip::tester
