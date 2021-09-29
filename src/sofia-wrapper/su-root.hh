/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2021  Belledonne Communications SARL.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <stdexcept>

#include <sofia-sip/su_wait.h>

namespace sofiasip {

class SuRoot {
public:
	SuRoot() : mCPtr{su_root_create(nullptr)} {
		if (mCPtr == nullptr) {
			throw std::runtime_error{"su_root_t allocation failed"};
		}
	}
	SuRoot(const SuRoot&) = delete;
	~SuRoot() {su_root_destroy(mCPtr);}

	su_root_t* getCPtr() const noexcept {return mCPtr;}

	void run() {su_root_run(mCPtr);}
	void quit() {su_root_break(mCPtr);}
	_su_task_r getTask() {return su_root_task(mCPtr);}


private:
	::su_root_t* mCPtr {nullptr};
};

} // namespace sofiasip
