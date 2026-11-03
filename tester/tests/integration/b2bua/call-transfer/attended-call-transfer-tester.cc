/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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
 * TO calls TT
 * TO sends a REFER to TE containing the call-Id that TO has with TT
 * TE calls TT with a 'Replaces' header containing the call-Id that TT has with TO
 */
namespace flexisip::tester::attended {

/**
 * In these test cases, every call is routed through the B2BUA (including "internal" calls).
 */
namespace full_routing {
namespace scenario {

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TE ---1--> ----2---╷
 *     TO <--3--- <-------╵
 *
 *     TO ---4--> ----5---╷
 *     TT <--6--- <-------╵
 *                                     TO send a REFER to TE with call-ID 4
 *     TE ---7--> ----8---╷
 *     TT <--9--- <-------╵            TT must receive a 'Replaces' header containing call-ID 6
 */
void bidirectionalBridgeForAll(const test::Function& test,
                               const CallTransferAccount& transfereeInt,
                               const CallTransferAccount& transferorInt,
                               const CallTransferAccount& transferTInt) {
	test::III(test, kAllCallsRoutedToB2bua, transfereeInt, transferorInt, transferTInt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TE ---1--> ----2---╷
 *     TO <--3--- <-------╵
 *                                     TO sends a REFER to TE with call-ID 4
 *     TO ---4--> ---5--> TT
 *     TE ---6--> ---7--> TT           TT must receive a 'Replaces' header containing call-ID 5
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
 *                                     TO sends a REFER to TE with call-ID 3.
 *     TT <--4--- <--3--- TO
 *     TE ---5--> ---6---╷
 *     TT <--7--- <------╵             TT must receive a 'Replaces' header containing call-ID 4.
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
 *
 *     					  TO --3-╷
 *                        TT <---╵
 *                                   TO sends a REFER to TE with call-ID 3
 *     TE ---4--> ---5--> TT         TT must receive a 'Replaces' header containing call-ID 3
 */
void noBridgeForReplacementCall(const test::Function& test,
                                const CallTransferAccount& transfereeInt,
                                const CallTransferAccount& transferorExt,
                                const CallTransferAccount& transferTargetExt) {
	test::IEE(test, kAllCallsRoutedToB2bua, transfereeInt, transferorExt, transferTargetExt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     					  TE --1-╷
 *                        TO <---╵
 *
 *     TT <--3--- <--2--- TO
 *                                   TO sends a REFER to TE with call-ID 2
 *     TT <--5--- <--4--- TE         TT must receive a 'Replaces' header containing call-ID 3
 */
void unidirectionalBridgeForTransferAndReplacementCalls(const test::Function& test,
                                                        const CallTransferAccount& transfereeExt,
                                                        const CallTransferAccount& transferorExt,
                                                        const CallTransferAccount& transferTargetInt) {
	test::EEI(test, kAllCallsRoutedToB2bua, transfereeExt, transferorExt, transferTargetInt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TO <--2--- <--1--- TE
 *
 *     TO ---3--> ---4--> TT
 *                                    TO sends a REFER to TE with call-ID 3
 *     					  TE --5-╷
 *                        TT <---╵    TT must receive a 'Replaces' header containing call-ID 4
 */
void unidirectionalBridgeForInitialAndReplacementCalls(const test::Function& test,
                                                       const CallTransferAccount& transfereeExt,
                                                       const CallTransferAccount& transferorInt,
                                                       const CallTransferAccount& transferTargetExt) {
	test::EIE(test, kAllCallsRoutedToB2bua, transfereeExt, transferorInt, transferTargetExt);
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

void noBridgeForReplacementCall() {
	scenario::noBridgeForReplacementCall(successful, kTransfereeIntern, kTransferorExtern, kTransferTargetExtern);
}

void unidirectionalBridgeForInitialAndReplacementCalls() {
	scenario::unidirectionalBridgeForInitialAndReplacementCalls(successful, kTransfereeExtern, kTransferorIntern,
	                                                            kTransferTargetExtern);
}

void unidirectionalBridgeForTransferAndReplacementCalls() {
	scenario::unidirectionalBridgeForTransferAndReplacementCalls(successful, kTransfereeExtern, kTransferorExtern,
	                                                             kTransferTargetIntern);
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

void noBridgeForReplacementCall() {
	scenario::noBridgeForReplacementCall(declined, kTransfereeIntern, kTransferorExtern, kTransferTargetExtern);
}

void unidirectionalBridgeForTransferAndReplacementCalls() {
	scenario::unidirectionalBridgeForTransferAndReplacementCalls(declined, kTransfereeExtern, kTransferorExtern,
	                                                             kTransferTargetIntern);
}

void unidirectionalBridgeForInitialAndReplacementCalls() {
	scenario::unidirectionalBridgeForInitialAndReplacementCalls(declined, kTransfereeExtern, kTransferorIntern,
	                                                            kTransferTargetExtern);
}

} // namespace hangup

TestSuite _{
    "integration::b2bua::sip-bridge::attended-call-transfer::shared-usernames",
    {
        CLASSY_TEST(bidirectionalBridgeForAll),
        CLASSY_TEST(bidirectionalBridgeForInitialCall),
        CLASSY_TEST(bidirectionalBridgeForTransferCall),
        CLASSY_TEST(noBridgeForReplacementCall),
        CLASSY_TEST(unidirectionalBridgeForTransferAndReplacementCalls),
        CLASSY_TEST(unidirectionalBridgeForInitialAndReplacementCalls),

        CLASSY_TEST(hangup::bidirectionalBridgeForAll),
        CLASSY_TEST(hangup::bidirectionalBridgeForInitialCall),
        CLASSY_TEST(hangup::bidirectionalBridgeForTransferCall),
        CLASSY_TEST(hangup::noBridgeForReplacementCall),
        CLASSY_TEST(hangup::unidirectionalBridgeForTransferAndReplacementCalls),
        CLASSY_TEST(hangup::unidirectionalBridgeForInitialAndReplacementCalls),
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
 *     TO ---4--> ---5--> TT
 *     TE ---6--> ---7--> TT
 */
void outgoingBridgeTransferAndReplacementCalls(const test::Function& test,
                                               const CallTransferAccount& transfereeInt,
                                               const CallTransferAccount& transferorInt,
                                               const CallTransferAccount& transferTargetExt) {
	test::IIE(test, kInternalDirectSettings, transfereeInt, transferorInt, transferTargetExt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TE ---1--> ---2--> TO
 *     TT <--4--- <--3--- TO
 *     TE --5-╷
 *     TO <---╵
 */
void bridgeOutgoingInitialAndIncomingTransferCalls(const test::Function& test,
                                                   const CallTransferAccount& transfereeInt,
                                                   const CallTransferAccount& transferorExt,
                                                   const CallTransferAccount& transferTargetInt) {
	test::IEI(test, kInternalDirectSettings, transfereeInt, transferorExt, transferTargetInt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TE ---1--> ---2--> TO
 *     					  TO --3-╷
 *                        TT <---╵
 *     TE ---4--> ---5--> TT
 */
void outgoingBridgeInitialAndReplacementCalls(const test::Function& test,
                                              const CallTransferAccount& transfereeInt,
                                              const CallTransferAccount& transferorExt,
                                              const CallTransferAccount& transferTargetExt) {
	test::IEE(test, kInternalDirectSettings, transfereeInt, transferorExt, transferTargetExt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     					  TE --1-╷
 *                        TO <---╵
 *     TT <--3--- <--2--- TO
 *     TT <--5--- <--4--- TE
 */
void incomingBridgeTransferAndReplacementCalls(const test::Function& test,
                                               const CallTransferAccount& transfereeExt,
                                               const CallTransferAccount& transferorExt,
                                               const CallTransferAccount& transferTargetInt) {
	test::EEI(test, kInternalDirectSettings, transfereeExt, transferorExt, transferTargetInt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TO <--2--- <--1--- TE
 *     TO ---3--> ---4--> TT
 *     					  TE --5-╷
 *                        TT <---╵
 */
void bridgeIncomingInitialAndOutgoingTransferCalls(const test::Function& test,
                                                   const CallTransferAccount& transfereeExt,
                                                   const CallTransferAccount& transferorInt,
                                                   const CallTransferAccount& transferTargetExt) {
	test::EIE(test, kInternalDirectSettings, transfereeExt, transferorInt, transferTargetExt);
}

/*
 * FLEXISIP    B2BUA    EXTERNAL
 *     TO <--2--- <--1--- TE
 *     TO --3-╷
 *     TT <---╵
 *     TT <--5--- <--4--- TE
 */
void incomingBridgeInitialAndReplacementCalls(const test::Function& test,
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

void outgoingBridgeTransferAndReplacementCalls() {
	scenario::outgoingBridgeTransferAndReplacementCalls(successful, kTransfereeInternD, kTransferorInternD,
	                                                    kTransferTargetExternD);
}

void bridgeOutgoingInitialAndIncomingTransferCalls() {
	scenario::bridgeOutgoingInitialAndIncomingTransferCalls(successful, kTransfereeInternD, kTransferorExternD,
	                                                        kTransferTargetInternD);
}

void outgoingBridgeInitialAndReplacementCalls() {
	scenario::outgoingBridgeInitialAndReplacementCalls(successful, kTransfereeInternD, kTransferorExternD,
	                                                   kTransferTargetExternD);
}

void incomingBridgeTransferAndReplacementCalls() {
	scenario::incomingBridgeTransferAndReplacementCalls(successful, kTransfereeExternD, kTransferorExternD,
	                                                    kTransferTargetInternD);
}

void bridgeIncomingInitialAndOutgoingTransferCalls() {
	scenario::bridgeIncomingInitialAndOutgoingTransferCalls(successful, kTransfereeExternD, kTransferorInternD,
	                                                        kTransferTargetExternD);
}

void incomingBridgeInitialAndReplacementCalls() {
	scenario::incomingBridgeInitialAndReplacementCalls(successful, kTransfereeExternD, kTransferorInternD,
	                                                   kTransferTargetInternD);
}

/**
 * Cases: transfer calls are declined by the transfer target.
 */
namespace hangup {

void outgoingBridgeTransferAndReplacementCalls() {
	scenario::outgoingBridgeTransferAndReplacementCalls(declined, kTransfereeInternD, kTransferorInternD,
	                                                    kTransferTargetExternD);
}

void bridgeOutgoingInitialAndIncomingTransferCalls() {
	scenario::bridgeOutgoingInitialAndIncomingTransferCalls(declined, kTransfereeInternD, kTransferorExternD,
	                                                        kTransferTargetInternD);
}

void outgoingBridgeInitialAndReplacementCalls() {
	scenario::outgoingBridgeInitialAndReplacementCalls(declined, kTransfereeInternD, kTransferorExternD,
	                                                   kTransferTargetExternD);
}

void incomingBridgeTransferAndReplacementCalls() {
	scenario::incomingBridgeTransferAndReplacementCalls(declined, kTransfereeExternD, kTransferorExternD,
	                                                    kTransferTargetInternD);
}

void bridgeIncomingInitialAndOutgoingTransferCalls() {
	scenario::bridgeIncomingInitialAndOutgoingTransferCalls(declined, kTransfereeExternD, kTransferorInternD,
	                                                        kTransferTargetExternD);
}

void incomingBridgeInitialAndReplacementCalls() {
	scenario::incomingBridgeInitialAndReplacementCalls(declined, kTransfereeExternD, kTransferorInternD,
	                                                   kTransferTargetInternD);
}

} // namespace hangup

TestSuite _{
    "integration::b2bua::sip-bridge::attended-call-transfer",
    {
        CLASSY_TEST(outgoingBridgeTransferAndReplacementCalls),
        CLASSY_TEST(bridgeOutgoingInitialAndIncomingTransferCalls),
        CLASSY_TEST(outgoingBridgeInitialAndReplacementCalls),
        CLASSY_TEST(incomingBridgeTransferAndReplacementCalls),
        CLASSY_TEST(bridgeIncomingInitialAndOutgoingTransferCalls),
        CLASSY_TEST(incomingBridgeInitialAndReplacementCalls),

        CLASSY_TEST(hangup::outgoingBridgeTransferAndReplacementCalls),
        CLASSY_TEST(hangup::bridgeOutgoingInitialAndIncomingTransferCalls),
        CLASSY_TEST(hangup::outgoingBridgeInitialAndReplacementCalls),
        CLASSY_TEST(hangup::incomingBridgeTransferAndReplacementCalls),
        CLASSY_TEST(hangup::bridgeIncomingInitialAndOutgoingTransferCalls),
        CLASSY_TEST(hangup::incomingBridgeInitialAndReplacementCalls),
    },
};

} // namespace distinct_usernames
} // namespace filtered_routing
} // namespace flexisip::tester::attended