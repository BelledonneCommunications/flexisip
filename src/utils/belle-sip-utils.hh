/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2011  Belledonne Communications SARL, All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <cstddef>
#include <memory>
#include <type_traits>

#include <belle-sip/object.h>

namespace bellesip {

/*
   These templates mimic std::shared_ptr<> and std::weak_ptr<> from C++ standard library but are designed to
   handle belle_sip_object_t instances. They should be used each time the C++ code needs to take ownership (or weak
   reference) on a C object of BelleSip stack.
*/

template <typename T>
class weak_ptr;

template <typename T>
class shared_ptr {
public:
	shared_ptr() noexcept = default;
	shared_ptr(std::nullptr_t) noexcept {}
	shared_ptr(T *ptr) noexcept : mData{ref(ptr)} {}
	shared_ptr(const shared_ptr &r) noexcept : shared_ptr{r.mData.get()} {}
	shared_ptr(shared_ptr &&r) noexcept = default;
	shared_ptr(const weak_ptr<T> &r) noexcept : shared_ptr{r.mData} {}
	~shared_ptr() noexcept = default;

	shared_ptr &operator=(const shared_ptr &r) noexcept {
		mData.reset(ref(r.mData.get()));
		return *this;
	}
	shared_ptr &operator=(shared_ptr &&r) noexcept {
		mData = std::move(r.mData);
		return *this;
	}

	void reset(T *ptr) noexcept {mData.reset(ref(ptr));}
	void swap(shared_ptr &r) noexcept {mData.swap(r.mData);}

	T *get() const noexcept {return mData.get();}
	T &operator*() const noexcept {return *mData;}

	explicit operator bool() const noexcept {return bool(mData);}

private:
	struct DataDeleter {
		void operator()(T *ptr) {belle_sip_object_unref(const_cast<std::remove_const_t<T> *>(ptr));}
	};
	using DataPtr = std::unique_ptr<T, DataDeleter>;

	static T *ref(T *ptr) noexcept {
		return ptr
			? reinterpret_cast<T *>(belle_sip_object_ref(const_cast<std::remove_const_t<T> *>(ptr)))
			: nullptr;
	}

	DataPtr mData{};

	friend weak_ptr<T>;
};

template <typename T>
class weak_ptr {
public:
	weak_ptr() noexcept = default;
	weak_ptr(T *ptr) noexcept : mData{ptr} {
		if (mData) belle_sip_object_weak_ref(mData, onDestroyCb, &mData);
	}
	weak_ptr(const weak_ptr<T> &r) noexcept : weak_ptr{r.mData} {}
	weak_ptr(const shared_ptr<T> &r) noexcept : weak_ptr{r.mData.get()} {}
	weak_ptr(weak_ptr<T> &&r) noexcept : weak_ptr{r} {
		r.reset();
	}
	~weak_ptr() noexcept {
		if (mData) belle_sip_object_weak_unref(mData, onDestroyCb, &mData);
	}

	weak_ptr &operator=(const weak_ptr &r) noexcept {
		mData = r.mData;
		if (mData) belle_sip_object_weak_ref(mData, onDestroyCb, &mData);
		return *this;
	}
	weak_ptr &operator=(const shared_ptr<T> &r) noexcept {
		mData = r.mData.get();
		if (mData) belle_sip_object_weak_ref(mData, onDestroyCb, &mData);
		return *this;
	}
	weak_ptr &operator=(weak_ptr &&r) noexcept {
		*this = r;
		r.reset();
		return *this;
	}

	void reset() noexcept {
		if (mData) {
			belle_sip_object_weak_unref(mData, onDestroyCb, &mData);
			mData = nullptr;
		}
	}
	bool expired() const noexcept {return mData == nullptr;}
	shared_ptr<T> lock() const noexcept {return shared_ptr<T>{*this};}

private:
	static void onDestroyCb(void *userData, [[maybe_unused]] belle_sip_object_t *obj) {
		auto mDataAttr = static_cast<T **>(userData);
		*mDataAttr = nullptr;
	};

	T *mData{nullptr};

	friend shared_ptr<T>;
};

}
