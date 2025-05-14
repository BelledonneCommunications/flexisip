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

#include "media.hh"

#include "exceptions/bad-configuration.hh"

namespace flexisip::configuration_utils {

void setMediaPort(int min,
                  int max,
                  linphone::Core& core,
                  const std::function<void(linphone::Core&, int)>& setPort,
                  const std::function<void(linphone::Core&, int, int)>& setPortRange) {
	if (min == max) {
		if (min == 0) {
			setPort(core, LC_SIP_TRANSPORT_RANDOM);
		} else {
			setPort(core, min);
		}
	} else {
		setPortRange(core, min, max);
	}
}

std::string mediaEngineToStr(MediaEngine media) {
	switch (media) {
		case MediaEngine::AUDIO:
			return "sound";
		case MediaEngine::VIDEO:
			return "video";
	}
	throw BadConfiguration{"unknown media engine '" + std::to_string(static_cast<int>(media)) + "'"};
}

void configureMediaEngineMode(const std::shared_ptr<linphone::Config>& configuration,
                              MediaEngine media,
                              const ConfigString* mode) {
	static const std::map<MediaEngine, std::map<std::string, int>> modes{
	    {
	        MediaEngine::AUDIO,
	        {{"mixer", 0}, {"semi-sfu", 1}, {"sfu", 2}},
	    },
	    {
	        MediaEngine::VIDEO,
	        {{"semi-sfu", 1}, {"sfu", 2}},
	    },
	};

	const auto selectedMedia = mediaEngineToStr(media);
	const auto mediaModes = modes.find(media)->second;
	const auto selectedMode = mediaModes.find(mode->read());
	if (selectedMode == mediaModes.end())
		throw BadConfiguration{mode->getCompleteName() + "='" + mode->read() + "' is not supported"};

	configuration->setInt(selectedMedia, "conference_mode", selectedMode->second);
}

} // namespace flexisip::configuration_utils