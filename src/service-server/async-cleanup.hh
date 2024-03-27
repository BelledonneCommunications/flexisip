/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL.

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

namespace flexisip {

/**
 * Post-destruction cleanup operations that need to be performed after a ServiceServer has been stopped.
 */
class AsyncCleanup {
public:
	virtual ~AsyncCleanup() = default;

	/**
	 * Keep calling this function until it returns false.
	 * It will perform the necessary checks, then run an iteration of the appropriate loop(s) if need be.
	 */
	virtual bool finished() = 0;
};

} // namespace flexisip
