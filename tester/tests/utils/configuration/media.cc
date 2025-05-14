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

#include "utils/configuration/media.hh"

#include "exceptions/bad-configuration.hh"
#include "flexisip/configmanager.hh"
#include "linphone++/factory.hh"
#include "linphone/misc.h"
#include "utils/client-core.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester {

namespace {

using namespace configuration_utils;

void configureAudioEngineMode() {
	{
		const auto configuration = linphone::Factory::get()->createConfig("");
		const ConfigString parameter{"audio-engine-mode", "", "mixer", 0};

		configureMediaEngineMode(configuration, MediaEngine::AUDIO, &parameter);

		BC_ASSERT_CPP_EQUAL(configuration->getInt("sound", "conference_mode", -1), 0);
	}
	{
		const auto configuration = linphone::Factory::get()->createConfig("");
		const ConfigString parameter{"audio-engine-mode", "", "semi-sfu", 0};

		configureMediaEngineMode(configuration, MediaEngine::AUDIO, &parameter);

		BC_ASSERT_CPP_EQUAL(configuration->getInt("sound", "conference_mode", -1), 1);
	}
	{
		const auto configuration = linphone::Factory::get()->createConfig("");
		const ConfigString parameter{"audio-engine-mode", "", "sfu", 0};

		configureMediaEngineMode(configuration, MediaEngine::AUDIO, &parameter);

		BC_ASSERT_CPP_EQUAL(configuration->getInt("sound", "conference_mode", -1), 2);
	}
}

void configureVideoEngineMode() {
	{
		const auto configuration = linphone::Factory::get()->createConfig("");
		const ConfigString parameter{"video-engine-mode", "", "semi-sfu", 0};

		configureMediaEngineMode(configuration, MediaEngine::VIDEO, &parameter);

		BC_ASSERT_CPP_EQUAL(configuration->getInt("video", "conference_mode", -1), 1);
	}
	{
		const auto configuration = linphone::Factory::get()->createConfig("");
		const ConfigString parameter{"video-engine-mode", "", "sfu", 0};

		configureMediaEngineMode(configuration, MediaEngine::VIDEO, &parameter);

		BC_ASSERT_CPP_EQUAL(configuration->getInt("video", "conference_mode", -1), 2);
	}
}

void configureMediaEngineModeWithUnknownMediaEngine() {
	const auto configuration = linphone::Factory::get()->createConfig("");
	const ConfigString parameter{"audio-engine-mode", "", "mixer", 0};
	BC_ASSERT_THROWN(configureMediaEngineMode(configuration, static_cast<MediaEngine>(-1), &parameter),
	                 BadConfiguration);
}

void configureMediaEngineModeWithUnknownMode() {
	const auto configuration = linphone::Factory::get()->createConfig("");
	const ConfigString parameter{"audio-engine-mode", "", "unknown", 0};
	BC_ASSERT_THROWN(configureMediaEngineMode(configuration, MediaEngine::VIDEO, &parameter), BadConfiguration);
}

TestSuite _{
    "utils::configuration::media",
    {
        CLASSY_TEST(configureAudioEngineMode),
        CLASSY_TEST(configureVideoEngineMode),
        CLASSY_TEST(configureMediaEngineModeWithUnknownMediaEngine),
        CLASSY_TEST(configureMediaEngineModeWithUnknownMode),
    },
};

} // namespace
} // namespace flexisip::tester