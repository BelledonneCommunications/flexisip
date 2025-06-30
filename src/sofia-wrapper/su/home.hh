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

#include <cassert>
#include <memory>

#include "sofia-sip/su_alloc.h"

// The `su_` prefix in Sofia types and functions means "Sofia Utility".
// Thin wrappers for those types should be placed in the `sofiasip::utility` namespace
namespace sofiasip::utility {

class Home;
template <typename T>
class Homed;
template <typename THome = Home>
class HomePtr;

/** Thin wrapper for `su_home_t`.
 * The goal is to provide an interface to the C types and functions that is both more type-safe and more ergonomic,
 * while staying as close to the library as possible.
 * That means, among other things, keeping the exact same memory layout as the underlying type (hence the "thin").
 */
class Home : protected su_home_t {
public:
	struct Deleter {
		void operator()(Home* home) noexcept;
	};

	template <typename T, typename... Args>
	static HomePtr<Homed<T>> make(Args&&... args) {
		return Homed<T>::make(nullptr, std::forward<Args>(args)...);
	}

	template <typename T, typename... Args>
	HomePtr<Homed<T>> makeChild(Args&&... args) {
		return Homed<T>::make(this, std::forward<Args>(args)...);
	}

	static Home* wrap(su_home_t*);

	Home() : su_home_t() {
		if (::su_home_init(this) < 0) throw std::bad_alloc{};
	}
	Home(const Home& src) = delete;
	Home(Home&& src) = delete;

	~Home() noexcept {
		::su_home_deinit(this);
	}

protected:
	int setDestructor(void (*destructor)(void*));
};
static_assert(sizeof(Home) == sizeof(su_home_t));
static_assert(alignof(Home) == alignof(su_home_t));

// Regular unique_ptrs can be upgraded to shared_ptr, which can be misleading when you hold several of them.
// Imagine you hold two different unique_ptrs to the same home (rc == 2). You upgrade them both to shared_ptrs.
// You may overlook that those two shared_ptrs, managing the same home, have different ref count blocks.
// So if you e.g. turn the first one into a weak, thinking the second one will still hold the home... You'd be half
// right, in that the memory will still be there, but your weak_ptr will be null.
template <typename THome>
class HomePtr : std::unique_ptr<THome, Home::Deleter> {
public:
	template <typename T>
	friend class HomePtr;
	using Base = std::unique_ptr<THome, Home::Deleter>;

	/* NOLINT(google-explicit-constructor) */ HomePtr(std::nullptr_t null) : Base(null) {
	}
	explicit HomePtr(THome* ref) : Base(ref) {
	}
	template <typename TDerived>
	explicit HomePtr(HomePtr<TDerived>&& ptrToDerived) : Base(std::move(ptrToDerived)) {
	}

	using Base::operator*;
	using Base::operator->;
	using Base::get;
	using Base::release;
	using Base::operator bool;
};

template <typename T>
class Homed : public Home {
public:
	Homed() = delete;

	T& get() {
		return mPayload;
	}

	T& operator*() {
		return mPayload;
	}

	template <typename... Args>
	static HomePtr<Homed> make(Home* parent, Args&&... args) {
		static_assert(sizeof(Homed) >= sizeof(su_home_t));

		auto self = HomePtr<Homed>(static_cast<Homed*>(::su_home_clone(parent, sizeof(Homed))));
		if (!self) return nullptr;

		auto* payloadMemory = reinterpret_cast<std::byte*>(&self->mPayload);
		assert(payloadMemory == reinterpret_cast<std::byte*>(self.get()) + sizeof(su_home_t));
		new (payloadMemory) T(std::forward<Args>(args)...);
		self->setDestructor([](void* self) { static_cast<Homed*>(self)->mPayload.~T(); });
		return self;
	}

private:
	T mPayload;
};

} // namespace sofiasip::utility