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

// Note: actual test functions are defined in this file.
#include "call-transfer-commons.hh"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

/*
 * TE: Transferee
 * TO: Transferor
 * TT: TransferTarget
 * ---x--> INVITE with Call-Id 'x'
 *
 * TE calls TO
 * TO sends a REFER to TE containing the URI of TT
 * TE calls TT
 */
namespace flexisip::tester::blind {

/**
 * In these test cases, every call is routed through the B2BUA (including "internal" calls).
 */
namespace full_routing {
namespace scenario {

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TE ---1--> ----2---╷
 *     TO <--3--- <-------╵
 *                                     TO sends a REFER to TE containing the URI of TT
 *     TE ---4--> ----5---╷
 *     TT <--6--- <-------╵            the initial and the transfer calls bounce through the external proxy
 */
void bidirectionalBridgeForAll(const test::Function& test,
                               const CallTransferAccount& transfereeInt,
                               const CallTransferAccount& transferorInt,
                               const CallTransferAccount& transferTargetInt) {
	test::III(test, kAllCallsRoutedToB2bua, transfereeInt, transferorInt, transferTargetInt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TE ---1--> ----2---╷
 *     TO <--3--- <-------╵            the initial call bounces through the external proxy
 *                                     TO sends a REFER to TE containing the URI of TT
 *     TE ---4--> ---5--> TT
 */
void bidirectionalBridgeForInitialCall(const test::Function& test,
                                       const CallTransferAccount& transfereeInt,
                                       const CallTransferAccount& transferorInt,
                                       const CallTransferAccount& transferTargetExt) {
	test::IIE(test, kAllCallsRoutedToB2bua, transfereeInt, transferorInt, transferTargetExt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TE ---1--> ---2--> TO
 *                                     TO sends a REFER to TE containing the URI of TT
 *     TE ---3--> ----4---╷
 *     TT <--5--- <-------╵            the initial call bridges out; the transfer call bounces through the external
 * proxy
 */
void bidirectionalBridgeForTransferCall(const test::Function& test,
                                        const CallTransferAccount& transfereeInt,
                                        const CallTransferAccount& transferorExt,
                                        const CallTransferAccount& transferTargetInt) {
	test::IEI(test, kAllCallsRoutedToB2bua, transfereeInt, transferorExt, transferTargetInt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TE ---1--> ---2--> TO
 *                                     TO sends a REFER to TE containing the URI of TT
 *     TE ---3--> ---4--> TT           the initial and the transfer calls bridge out to the external domain
 */
void bridgeOutboundInitialAndTransferCalls(const test::Function& test,
                                           const CallTransferAccount& transfereeInt,
                                           const CallTransferAccount& transferorExt,
                                           const CallTransferAccount& transferTargetExt) {
	test::IEE(test, kAllCallsRoutedToB2bua, transfereeInt, transferorExt, transferTargetExt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     					  TE --1-╷     the initial call stays on the external domain
 *                        TO <---╵
 *                                     TO sends a REFER to TE containing the URI of TT
 *     TT <--3--- <--2--- TE
 */
void bridgeInboundTransferCall(const test::Function& test,
                               const CallTransferAccount& transfereeExt,
                               const CallTransferAccount& transferorExt,
                               const CallTransferAccount& transferTargetInt) {
	test::EEI(test, kAllCallsRoutedToB2bua, transfereeExt, transferorExt, transferTargetInt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TO <--2--- <--1--- TE
 *                                     TO sends a REFER to TE containing the URI of TT
 *     					  TE --3-╷     only the initial call bridges in; the transfer call stays on the external domain
 *                        TT <---╵
 */
void bridgeInboundInitialCall(const test::Function& test,
                              const CallTransferAccount& transfereeExt,
                              const CallTransferAccount& transferorInt,
                              const CallTransferAccount& transferTargetExt) {
	test::EIE(test, kAllCallsRoutedToB2bua, transfereeExt, transferorInt, transferTargetExt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TO <--1--- <--2--- TE
 *                                   TO sends a REFER to TE containing the URI of TT
 *     TT <--3--- <--4--- TE         the initial and the transfer calls bridge in to the Flexisip domain
 */
void bridgeInboundInitialAndTransferCalls(const test::Function& test,
                                          const CallTransferAccount& transfereeExt,
                                          const CallTransferAccount& transferorInt,
                                          const CallTransferAccount& transferTargetInt) {
	test::EII(test, kAllCallsRoutedToB2bua, transfereeExt, transferorInt, transferTargetInt);
}

} // namespace scenario

/**
 * Cases: users on the Flexisip domain and the external domain share the same usernames.
 */
namespace shared_usernames {

void bidirectionalBridgeForAll() {
	scenario::bidirectionalBridgeForAll(successful, kTransfereeIntern, kTransferorIntern, kTransferTargetIntern);
}

void bidirectionalBridgeForInitialCall() {
	scenario::bidirectionalBridgeForInitialCall(successful, kTransfereeIntern, kTransferorIntern,
	                                            kTransferTargetExtern);
}

void bidirectionalBridgeForTransferCall() {
	scenario::bidirectionalBridgeForTransferCall(successful, kTransfereeIntern, kTransferorExtern,
	                                             kTransferTargetIntern);
}

void bridgeOutboundInitialAndTransferCalls() {
	scenario::bridgeOutboundInitialAndTransferCalls(successful, kTransfereeIntern, kTransferorExtern,
	                                                kTransferTargetExtern);
}

void bridgeInboundTransferCall() {
	scenario::bridgeInboundTransferCall(successful, kTransfereeExtern, kTransferorIntern, kTransferTargetIntern);
}

void bridgeInboundInitialCall() {
	scenario::bridgeInboundInitialCall(successful, kTransfereeExtern, kTransferorIntern, kTransferTargetExtern);
}

void bridgeInboundInitialAndTransferCalls() {
	scenario::bridgeInboundInitialAndTransferCalls(successful, kTransfereeExtern, kTransferorExtern,
	                                               kTransferTargetExtern);
}

/**
 * Cases: transfer calls are declined by the transfer target.
 */
namespace hangup {

void bidirectionalBridgeForAll() {
	scenario::bidirectionalBridgeForAll(declined, kTransfereeIntern, kTransferorIntern, kTransferTargetIntern);
}

void bidirectionalBridgeForInitialCall() {
	scenario::bidirectionalBridgeForInitialCall(declined, kTransfereeIntern, kTransferorIntern, kTransferTargetExtern);
}

void bidirectionalBridgeForTransferCall() {
	scenario::bidirectionalBridgeForTransferCall(declined, kTransfereeIntern, kTransferorExtern, kTransferTargetIntern);
}

void bridgeOutboundInitialAndTransferCalls() {
	scenario::bridgeOutboundInitialAndTransferCalls(declined, kTransfereeIntern, kTransferorExtern,
	                                                kTransferTargetExtern);
}

void bridgeInboundTransferCall() {
	scenario::bridgeInboundTransferCall(declined, kTransfereeExtern, kTransferorIntern, kTransferTargetIntern);
}

void bridgeInboundInitialCall() {
	scenario::bridgeInboundInitialCall(declined, kTransfereeExtern, kTransferorIntern, kTransferTargetExtern);
}

void bridgeInboundInitialAndTransferCalls() {
	scenario::bridgeInboundInitialAndTransferCalls(declined, kTransfereeExtern, kTransferorExtern,
	                                               kTransferTargetExtern);
}

} // namespace hangup

TestSuite _{
    "integration::b2bua::sip-bridge::blind-call-transfer::shared-usernames",
    {
        CLASSY_TEST(bidirectionalBridgeForAll),
        CLASSY_TEST(bidirectionalBridgeForInitialCall),
        CLASSY_TEST(bidirectionalBridgeForTransferCall),
        CLASSY_TEST(bridgeOutboundInitialAndTransferCalls),
        CLASSY_TEST(bridgeInboundTransferCall),
        CLASSY_TEST(bridgeInboundInitialCall),
        CLASSY_TEST(bridgeInboundInitialAndTransferCalls),

        CLASSY_TEST(hangup::bidirectionalBridgeForAll),
        CLASSY_TEST(hangup::bidirectionalBridgeForInitialCall),
        CLASSY_TEST(hangup::bidirectionalBridgeForTransferCall),
        CLASSY_TEST(hangup::bridgeOutboundInitialAndTransferCalls),
        CLASSY_TEST(hangup::bridgeInboundTransferCall),
        CLASSY_TEST(hangup::bridgeInboundInitialCall),
        CLASSY_TEST(hangup::bridgeInboundInitialAndTransferCalls),
    },
};

} // namespace shared_usernames
} // namespace full_routing

/**
 * In these test cases, only calls that contain the username of an external user (starts with '++') is routed through
 * the B2BUA.
 */
namespace filtered_routing {
namespace scenario {

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TE --1-╷
 *     TO <---╵
 *     TE ---4--> ---5--> TT
 */
void bridgeOutboundTransferCall(const test::Function& test,
                                const CallTransferAccount& transfereeInt,
                                const CallTransferAccount& transferorInt,
                                const CallTransferAccount& transferTargetExt) {
	test::IIE(test, kInternalDirectSettings, transfereeInt, transferorInt, transferTargetExt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TE ---1--> ---2--> TO
 *     TE --3-╷
 *     TT <---╵
 */
void bridgeOutboundInitialCall(const test::Function& test,
                               const CallTransferAccount& transfereeInt,
                               const CallTransferAccount& transferorExt,
                               const CallTransferAccount& transferTargetInt) {
	test::IEI(test, kInternalDirectSettings, transfereeInt, transferorExt, transferTargetInt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TE ---1--> ---2--> TO
 *     TE ---3--> ---4--> TT
 */
void bridgeOutboundInitialAndTransferCalls(const test::Function& test,
                                           const CallTransferAccount& transfereeInt,
                                           const CallTransferAccount& transferorExt,
                                           const CallTransferAccount& transferTargetExt) {
	test::IEE(test, kInternalDirectSettings, transfereeInt, transferorExt, transferTargetExt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     					  TE --1-╷
 *                        TO <---╵
 *     TT <--3--- <--2--- TE
 */
void bridgeInboundTransferCall(const test::Function& test,
                               const CallTransferAccount& transfereeExt,
                               const CallTransferAccount& transferorExt,
                               const CallTransferAccount& transferTargetInt) {
	test::EEI(test, kInternalDirectSettings, transfereeExt, transferorExt, transferTargetInt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TO <--2--- <--1--- TE
 *     					  TE --3-╷
 *                        TT <---╵
 */
void bridgeInboundInitialCall(const test::Function& test,
                              const CallTransferAccount& transfereeExt,
                              const CallTransferAccount& transferorInt,
                              const CallTransferAccount& transferTargetExt) {
	test::EIE(test, kInternalDirectSettings, transfereeExt, transferorInt, transferTargetExt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TO <--1--- <--2--- TE
 *     TT <--3--- <--4--- TE
 */
void bridgeInboundInitialAndTransferCalls(const test::Function& test,
                                          const CallTransferAccount& transfereeExt,
                                          const CallTransferAccount& transferorInt,
                                          const CallTransferAccount& transferTargetInt) {
	test::EII(test, kInternalDirectSettings, transfereeExt, transferorInt, transferTargetInt);
}

} // namespace scenario

/**
 * Cases: users on the Flexisip domain and the external domain have *distinct* usernames.
 * So, for each account: "uri.user != alias.user".
 */
namespace distinct_usernames {

void bridgeOutboundTransferCall() {
	scenario::bridgeOutboundTransferCall(successful, kTransfereeInternD, kTransferorInternD, kTransferTargetInternD);
}

void bridgeOutboundInitialCall() {
	scenario::bridgeOutboundInitialCall(successful, kTransfereeInternD, kTransferorInternD, kTransferTargetExternD);
}

void bridgeOutboundInitialAndTransferCalls() {
	scenario::bridgeOutboundInitialAndTransferCalls(successful, kTransfereeInternD, kTransferorExternD,
	                                                kTransferTargetInternD);
}

void bridgeInboundTransferCall() {
	scenario::bridgeInboundTransferCall(successful, kTransfereeExternD, kTransferorInternD, kTransferTargetInternD);
}

void bridgeInboundInitialCall() {
	scenario::bridgeInboundInitialCall(successful, kTransfereeExternD, kTransferorInternD, kTransferTargetExternD);
}

void bridgeInboundInitialAndTransferCalls() {
	scenario::bridgeInboundInitialAndTransferCalls(successful, kTransfereeExternD, kTransferorExternD,
	                                               kTransferTargetExternD);
}

/**
 * Cases: transfer calls are declined.
 */
namespace hangup {

void bridgeOutboundTransferCall() {
	scenario::bridgeOutboundTransferCall(declined, kTransfereeInternD, kTransferorInternD, kTransferTargetInternD);
}

void bridgeOutboundInitialCall() {
	scenario::bridgeOutboundInitialCall(declined, kTransfereeInternD, kTransferorInternD, kTransferTargetExternD);
}

void bridgeOutboundInitialAndTransferCalls() {
	scenario::bridgeOutboundInitialAndTransferCalls(declined, kTransfereeInternD, kTransferorExternD,
	                                                kTransferTargetInternD);
}

void bridgeInboundTransferCall() {
	scenario::bridgeInboundTransferCall(declined, kTransfereeExternD, kTransferorInternD, kTransferTargetInternD);
}

void bridgeInboundInitialCall() {
	scenario::bridgeInboundInitialCall(declined, kTransfereeExternD, kTransferorInternD, kTransferTargetExternD);
}

void bridgeInboundInitialAndTransferCalls() {
	scenario::bridgeInboundInitialAndTransferCalls(declined, kTransfereeExternD, kTransferorExternD,
	                                               kTransferTargetExternD);
}

} // namespace hangup

TestSuite _{
    "integration::b2bua::sip-bridge::blind-call-transfer",
    {
        CLASSY_TEST(bridgeOutboundTransferCall),
        CLASSY_TEST(bridgeOutboundInitialCall),
        CLASSY_TEST(bridgeOutboundInitialAndTransferCalls),
        CLASSY_TEST(bridgeInboundTransferCall),
        CLASSY_TEST(bridgeInboundInitialCall),
        CLASSY_TEST(bridgeInboundInitialAndTransferCalls),

        CLASSY_TEST(hangup::bridgeOutboundTransferCall),
        CLASSY_TEST(hangup::bridgeOutboundInitialCall),
        CLASSY_TEST(hangup::bridgeOutboundInitialAndTransferCalls),
        CLASSY_TEST(hangup::bridgeInboundTransferCall),
        CLASSY_TEST(hangup::bridgeInboundInitialCall),
        CLASSY_TEST(hangup::bridgeInboundInitialAndTransferCalls),
    },
};

} // namespace distinct_usernames
} // namespace filtered_routing
} // namespace flexisip::tester::blind