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

#include <memory>

#include "soci-helper.hh"

#include "flexisip/logmanager.hh"

using namespace std;
using namespace chrono;

namespace flexisip {

namespace {

/**
 * Compute duration in milliseconds between two timestamps.
 *
 * @param start start timestamp
 * @param stop  stop timestamp
 * @return duration in milliseconds between the given timestamps
 */
chrono::milliseconds duration(chrono::steady_clock::time_point start, chrono::steady_clock::time_point stop) {
	return chrono::duration_cast<chrono::milliseconds>(stop - start);
}

} // namespace

void SociHelper::execute(const function<void(soci::session&)>& requestLambda) {
	steady_clock::time_point start, stop;
	unique_ptr<soci::session> session;

	// Grab a connection from the pool (thread safe).
	try {
		start = steady_clock::now();
		session = make_unique<soci::session>(mPool);
		stop = steady_clock::now();
		LOGD << "Session acquired from pool in " << duration(start, stop).count() << "ms";
	} catch (const runtime_error& exception) {
		LOGE << "Caught an unexpected exception during session acquisition: " << exception.what();
		throw DatabaseException();
	}

	for (int trials = 0;; trials++) {
		try {
			start = steady_clock::now();
			requestLambda(*session);
			stop = steady_clock::now();
			LOGD << "Successfully executed SQL query in " << duration(start, stop).count() << "ms";
			return;
		} catch (const runtime_error& exception) { // soci::mysql_soci_error is a subclass of std::runtime_error
			stop = steady_clock::now();
			bool retry = false;

			if (const auto* mysqlError = dynamic_cast<const soci::mysql_soci_error*>(&exception)) {
				/** Retryable errors:
				 *  - code=4031: "The client was disconnected by the server because of inactivity".
				 *  - code=2014: "Commands out of sync; you can't run this command now".
				 *                At this time we don't know if it is a soci or mysql bug, or bug with the sql request
				 *                being executed.
				 *  - code=2006: "MySQL server has gone away".
				 */
				retry = (trials < kMaxTrials) &&
				        (mysqlError->err_num_ == 4031 || mysqlError->err_num_ == 2014 || mysqlError->err_num_ == 2006);

				// Log with warning level if the error can be fixed quickly (retryable error).
				(retry ? LOGW : LOGE) << "MySQL error after " << duration(start, stop).count() << "ms ["
				                      << mysqlError->err_num_ << "]: " << exception.what();
			} else {
				LOGE << "Error after " << duration(start, stop).count() << "ms: " << exception.what();
			}

			// Always try to reconnect even if we know that we will not try to execute the SQL query again.
			// That is currently the only place where we can refresh sessions of the connection pool.
			reconnectSession(*session);

			if (retry) {
				LOGI << "Trying SQL query execution again";
				continue;
			}
			throw DatabaseException();
		}
	}
}

void SociHelper::reconnectSession(soci::session& session) {
	try {
		LOGI << "Closing and reconnecting session...";
		session.close();
		session.reconnect();
		LOGI << "Session [" << session.get_backend_name() << "] successfully reconnected";
	} catch (const soci::mysql_soci_error& exception) {
		LOGE << "MySQL error [" << exception.err_num_ << "]: " << exception.what();
		throw DatabaseException();
	} catch (const exception& exception) {
		LOGE << "Error: " << exception.what();
		throw DatabaseException();
	}
}

} // namespace flexisip