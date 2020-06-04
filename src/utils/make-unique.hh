/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2020  Belledonne Communications SARL.

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

#include <memory>

namespace flexisip {

/*
   Backport of std::make_unique in order to be used
   in C++11 code. Remove this header once C++14 standard
   is enabled.
*/
template <typename T, typename... ArgT>
std::unique_ptr<T> make_unique(ArgT&&... args) {
	return std::unique_ptr<T>{new T{std::forward<ArgT>(args)...}};
}

}
