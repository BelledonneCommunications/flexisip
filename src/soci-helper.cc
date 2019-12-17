/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2019  Belledonne Communications SARL, All rights reserved.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include "flexisip/logmanager.hh"
#include "soci-helper.hh"

using namespace std;

namespace flexisip{

void SociHelper::execute(const std::function<void (soci::session &)> &requestLambda) {
	const int N_TRIES = 1;
	chrono::steady_clock::time_point start, stop;
	unique_ptr<soci::session> sql;

	// will grab a connection from the pool. This is thread safe.
	try {
		start = chrono::steady_clock::now();
		sql.reset(new soci::session(mPool));
		stop = chrono::steady_clock::now();
		LOGD("[SOCI] Session acquired from pool in %lu ms", durationMs(start, stop));
	} catch (const runtime_error &e) {
		SLOGE << "[SOCI] " << e.what();
		throw DatabaseException();
	}

	for(int errorCount = 0;; errorCount++) {
		try {
			start = stop;
			requestLambda(*sql);
			stop = chrono::steady_clock::now();
			LOGD("[SOCI] statement successfully executed in %lu ms", durationMs(start, stop));
			return;
		} catch (const runtime_error &e) { // soci::mysql_soci_error is a subclass of std::runtime_error
			stop = chrono::steady_clock::now();
			const auto *sqlErr = dynamic_cast<const soci::mysql_soci_error *>(&e);

			SLOGE << "[SOCI] " << (sqlErr ? "MySQL " : "") << "error after " << durationMs(start, stop) << "ms: "
			      << (sqlErr ? to_string(sqlErr->err_num_) : "") << " " << e.what();

			reconnectSession(*sql);

			if (sqlErr && (sqlErr->err_num_ == 2014 || sqlErr->err_num_ == 2006) && errorCount < N_TRIES) {
				/* 2014 is the infamous "Commands out of sync; you can't run this command now" mysql error,
				* which is retryable.
				* At this time we don't know if it is a soci or mysql bug, or bug with the sql request being executed.
				*
				* 2006 is "MySQL server has gone away" which is also retryable.
				*/
				SLOGE << "[SOCI] retryable mysql error [" << sqlErr->err_num_ << "], so trying statement execution again...";
				continue;
			}
			throw DatabaseException();
		}
	}
}

void SociHelper::reconnectSession(soci::session &session) {
	try {
		SLOGE << "[SOCI] Trying close/reconnect session";
		session.close();
		session.reconnect();
		SLOGD << "[SOCI] Session " << session.get_backend_name() << " successfully reconnected";
	} catch (soci::mysql_soci_error const & e) {
		SLOGE << "[SOCI] reconnectSession MySQL error: " << e.err_num_ << " " << e.what();
	} catch (std::exception const &e) {
		SLOGE << "[SOCI] reconnectSession error: " << e.what();
	}
}

}
