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

#include <string>

#include "exceptions/exit.hh"

namespace flexisip {

/*
 * Exception to indicate a bad configuration.
 * The program should be stopped when this exception is thrown.
 */
class BadConfiguration : public ExitFailure {
public:
	template <typename... Args>
	explicit BadConfiguration(Args&&... args) : ExitFailure{-1, std::forward<Args>(args)...} {
	}
};

/*
 * Exception to indicate a configuration error while also providing the "Help" section of the parameter.
 * The program should be stopped when this exception is thrown.
 */
class BadConfigurationWithHelp : public BadConfiguration {
public:
	template <typename ConfigType>
	explicit BadConfigurationWithHelp(const ConfigType* configField, const std::string& message)
	    : BadConfiguration{message + "\n\n" + configField->getCompleteName() + ":\n" + configField->getHelp() + "\n"} {
	}
};

/*
 * Exception to indicate an error with the value of a parameter in the configuration.
 * The "Help" section of the parameter is also provided.
 * The program should be stopped when this exception is thrown.
 */
class BadConfigurationValue : public BadConfigurationWithHelp {
public:
	template <typename ConfigType>
	explicit BadConfigurationValue(const ConfigType* configField)
	    : BadConfigurationWithHelp{configField, "invalid value for parameter '" + configField->getCompleteName() +
	                                                "' (" + configField->get() + ")"} {
	}

	template <typename ConfigType>
	BadConfigurationValue(const ConfigType* configField, const std::string& additionalMessage)
	    : BadConfigurationWithHelp{configField, "invalid value for parameter '" + configField->getCompleteName() +
	                                                "' (" + configField->get() + "): " + additionalMessage} {
	}
};

/*
 * Exception to indicate the emptiness of a mandatory parameter in the configuration.
 * The "Help" section of the parameter is also provided.
 * The program should be stopped when this exception is thrown.
 */
class BadConfigurationEmpty : public BadConfigurationWithHelp {
public:
	template <typename ConfigType>
	explicit BadConfigurationEmpty(const ConfigType* configField)
	    : BadConfigurationWithHelp{configField, "parameter '" + configField->getCompleteName() + "' must be set"} {
	}
};

} // namespace flexisip