/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <flexisip/sofia-wrapper/home.hh>

#include <string_view>

#include "bctoolbox/tester.h"
#include "sofia-sip/sip.h"
#include "sofia-sip/sip_protos.h"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace {
using namespace flexisip::tester;
using namespace sofiasip;
using namespace std::string_view_literals;
using namespace std;

void movingHomesDoesNotInvalidatePointers() {
	Home newHome{};
	const sip_from_t* inhabitant;
	{
		Home oldHome{};
		inhabitant = ::sip_from_make(oldHome.home(), "sip:couch-surfer@sip.example.org");
		BC_HARD_ASSERT_CPP_EQUAL(string_view(inhabitant->a_url->url_user), "couch-surfer"sv);
		newHome = std::move(oldHome);
	}

	BC_ASSERT_CPP_EQUAL(string_view(inhabitant->a_url->url_user), "couch-surfer"sv);
}

TestSuite _("sofiasip::Home",
            {
                CLASSY_TEST(movingHomesDoesNotInvalidatePointers),
            });
} // namespace
