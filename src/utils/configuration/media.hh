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

#include <functional>

#include "flexisip/configmanager.hh"
#include "linphone++/linphone.hh"
#include "linphone/misc.h"

namespace flexisip::configuration_utils {

/**
 * @brief Set a media port or a port range on the given core.
 *
 * If min == max: use setPort method (special value 0 will set port value to LC_SIP_TRANSPORT_RANDOM).\n
 * Else:          use setPortRange method.
 *
 * @param min           lower bound of the port range to use
 * @param max           upper bound of the port range to use
 * @param core          linphone core instance
 * @param setPort       pointer to the 'setAudioPort' or 'setVideoPort' method of the core
 * @param setPortRange  pointer to the 'setAudioPortRange' or 'setVideoPortRange' method of the core
 */
void setMediaPort(int min,
                  int max,
                  linphone::Core& core,
                  const std::function<void(linphone::Core&, int)>& setPort,
                  const std::function<void(linphone::Core&, int, int)>& setPortRange);

enum class MediaEngine { AUDIO, VIDEO };

std::string mediaEngineToStr(MediaEngine media);

/**
 * @param media media type to configure ("audio" or "video")
 * @param mode engine mode to set
 * @param configuration Linphone::Core configuration
 */
void configureMediaEngineMode(const std::shared_ptr<linphone::Config>& configuration,
                              MediaEngine media,
                              const ConfigString* mode);

} // namespace flexisip::configuration_utils