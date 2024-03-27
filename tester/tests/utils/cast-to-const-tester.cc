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

#include "utils/cast-to-const.hh"

#include <string>
#include <vector>

namespace flexisip::tester {
namespace {

using namespace std;

static_assert(is_interior_const<int>);
static_assert(is_interior_const<char>);
static_assert(is_interior_const<const int>);
static_assert(is_interior_const<const int&>);
static_assert(is_interior_const<int&>);
static_assert(!is_interior_const<int*>);
static_assert(!is_interior_const<int* const>);
static_assert(is_interior_const<int const*>);
static_assert(!is_interior_const<const unique_ptr<int>>);
static_assert(is_interior_const<unique_ptr<const int>>);
static_assert(is_interior_const<string>);
static_assert(is_interior_const<string>);
static_assert(is_interior_const<array<int, 3>>);

static_assert(is_same_v<add_interior_const_t<int>, int>);
static_assert(is_same_v<add_interior_const_t<unique_ptr<int>>, unique_ptr<const int>>);
static_assert(is_same_v<add_interior_const_t<vector<int>>, vector<int>>);
static_assert(is_same_v<add_interior_const_t<array<int, 4>>, array<int, 4>>);
static_assert(is_same_v<add_interior_const_t<array<weak_ptr<int>, 4>>, array<weak_ptr<const int>, 4>>);
static_assert(is_same_v<add_interior_const_t<weak_ptr<int>>, weak_ptr<const int>>);
static_assert(is_same_v<add_interior_const_t<weak_ptr<weak_ptr<int>>>, weak_ptr<const weak_ptr<const int>>>);
static_assert(is_same_v<add_interior_const_t<shared_ptr<int>>, shared_ptr<const int>>);
static_assert(is_same_v<add_interior_const_t<vector<weak_ptr<int>>>, vector<weak_ptr<const int>>>);
static_assert(is_same_v<add_interior_const_t<vector<shared_ptr<int>>>, vector<shared_ptr<const int>>>);
static_assert(is_same_v<add_interior_const_t<char>, char>);
static_assert(is_same_v<basic_string<char, char_traits<char>, allocator<char>>, string>);
static_assert(is_same_v<add_interior_const_t<string>, string>);
static_assert(is_same_v<add_interior_const_t<multimap<string, int>>, multimap<string, int>>);
static_assert(is_same_v<add_interior_const_t<multimap<string, weak_ptr<int>>>, multimap<string, weak_ptr<const int>>>);

} // namespace
} // namespace flexisip::tester