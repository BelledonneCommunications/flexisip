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

#pragma once

#include <memory>

// Backports of the C++ Standard Library
namespace flexisip::stl_backports {

template <typename Signature>
class move_only_function;

// https://en.cppreference.com/w/cpp/utility/functional/move_only_function
// Allows moving data in and out of a function, which is required for e.g. std::unique_ptr,
// but impossible with a std::function
template <typename TReturn, typename... Args>
class move_only_function<TReturn(Args...)> {
public:
	move_only_function() noexcept = default;
	move_only_function(move_only_function&& other) = default;
	template <typename TFunction>
	move_only_function(TFunction&& function)
	    : mPtr(std::make_unique<WrappedFunction<TFunction>>(std::forward<TFunction>(function))) {
	}
	move_only_function& operator=(move_only_function&& other) = default;

	// "Unlike std::function, invoking an empty std::move_only_function results in undefined behavior."
	TReturn operator()(Args&&... args) {
		return (*mPtr)(std::forward<Args>(args)...);
	}

	operator bool() {
		return mPtr.operator bool();
	}

private:
	class TypeErasedFunction {
	public:
		virtual ~TypeErasedFunction() = default;

		virtual TReturn operator()(Args&&...) = 0;
	};

	template <typename TFunction>
	class WrappedFunction : public TypeErasedFunction {
	public:
		WrappedFunction(TFunction&& function) : mWrapped(std::forward<TFunction>(function)) {
		}

		TReturn operator()(Args&&... args) {
			return mWrapped(std::forward<Args>(args)...);
		}

	private:
		TFunction mWrapped;
	};

	std::unique_ptr<TypeErasedFunction> mPtr{};
};

} // namespace flexisip::stl_backports