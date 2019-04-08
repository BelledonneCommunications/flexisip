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

#pragma once

#include "soci/soci.h"
#include "soci/mysql/soci-mysql.h"

#include "flexisip/logmanager.hh"

#include <chrono>

namespace flexisip{

/*
 * This is a helper class to execute soci queries in a reliable way, ie
 * it will take care automatically to reconnect the session if it has been disconnected.
 * Indeed, inactive connections are dropped by mariadb/mysqld after some time, so this case
 * happens quite frequently on a system where there are few users.
 */
class SociHelper{
public:
	class DatabaseException : std::exception{
		virtual const char* what() const noexcept override{
			return "Database failure"; //The great thing about exception.
		}
	};
	// Initialize the SociHelper by giving the connection pool.
	SociHelper(soci::connection_pool &pool) : mPool(pool){};
	
	// Execute the database query safely. The code to execute the query shall be provided in the lambda argument.
	template <typename _lambda>
	soci::rowset<soci::row> execute(_lambda requestLambda){
		std::chrono::steady_clock::time_point start;
		std::chrono::steady_clock::time_point stop;
		soci::session *sql = nullptr;
		int errorCount = 0;
		bool retry;
		
		do{
			retry = false;
			try{
				start = std::chrono::steady_clock::now();
				// will grab a connection from the pool. This is thread safe.
				sql = new soci::session(mPool);
				stop = std::chrono::steady_clock::now();
				LOGD("[SOCI] Session acquired from pool in %lu ms", durationMs(start, stop));
				start = stop;
				auto ret = requestLambda(*sql);
				stop = std::chrono::steady_clock::now();
				LOGD("[SOCI] statement successfully executed in %lu ms", durationMs(start, stop));
				return ret;
			} catch (soci::mysql_soci_error const &e) {
				errorCount++;
				stop = std::chrono::steady_clock::now();
				SLOGE << "[SOCI] MySQL error after " << durationMs(start, stop) << " ms : " << e.err_num_ << " " << e.what();
				if (sql) reconnectSession(*sql);

				if ((e.err_num_ == 2014 || e.err_num_ == 2006) && errorCount == 1){
					/* 2014 is the infamous "Commands out of sync; you can't run this command now" mysql error,
					* which is retryable.
					* At this time we don't know if it is a soci or mysql bug, or bug with the sql request being executed.
					*
					* 2006 is "MySQL server has gone away" which is also retryable.
					*/
					SLOGE << "[SOCI] retryable mysql error ["<< e.err_num_<<"], so trying statement execution again...";
					retry = true;
				}
			} catch (const std::runtime_error &e) {
				errorCount++;
				stop = std::chrono::steady_clock::now();
				SLOGE << "[SOCI] error after " << durationMs(start, stop) << " ms : " << e.what();
				if (sql) reconnectSession(*sql);
			}
		} while (retry);
		if (sql) delete sql;
		throw DatabaseException();
	}
	// Variant of the previous method for the case where no rowset is needed as return value.
	// Probably it is possible to merge the two methods thanks std::enable_if (TODO later).
	template <typename _lambda>
	void executeNoReturn(_lambda requestLambda){
		std::chrono::steady_clock::time_point start;
		std::chrono::steady_clock::time_point stop;
		soci::session *sql = nullptr;
		int errorCount = 0;
		bool retry;
		
		do{
			retry = false;
			try{
				
				// will grab a connection from the pool. This is thread safe.
				if (!sql) {
					start = std::chrono::steady_clock::now();
					sql = new soci::session(mPool);
					stop = std::chrono::steady_clock::now();
					LOGD("[SOCI] Session acquired from pool in %lu ms", durationMs(start, stop));
					start = stop;
				}else{
					start = std::chrono::steady_clock::now();
				}
				requestLambda(*sql);
				stop = std::chrono::steady_clock::now();
				LOGD("[SOCI] statement successfully executed in %lu ms", durationMs(start, stop));
				return;
			} catch (soci::mysql_soci_error const &e) {
				errorCount++;
				stop = std::chrono::steady_clock::now();
				SLOGE << "[SOCI] MySQL error after " << durationMs(start, stop) << " ms : " << e.err_num_ << " " << e.what();
				if (sql) reconnectSession(*sql);

				if ((e.err_num_ == 2014 || e.err_num_ == 2006) && errorCount == 1){
					/* 2014 is the infamous "Commands out of sync; you can't run this command now" mysql error,
					* which is retryable.
					* At this time we don't know if it is a soci or mysql bug, or bug with the sql request being executed.
					*
					* 2006 is "MySQL server has gone away" which is also retryable.
					*/
					SLOGE << "[SOCI] retryable mysql error ["<< e.err_num_<<"], so trying statement execution again...";
					retry = true;
				}
			} catch (const std::runtime_error &e) {
				errorCount++;
				stop = std::chrono::steady_clock::now();
				SLOGE << "[SOCI] error after " << durationMs(start, stop) << " ms : " << e.what();
				if (sql) reconnectSession(*sql);
			}
		} while (retry);
		if (sql) delete sql;
		throw DatabaseException();
	}
private:
	void reconnectSession(soci::session &session);
	unsigned long durationMs(std::chrono::steady_clock::time_point start, std::chrono::steady_clock::time_point stop){
		return (unsigned long) std::chrono::duration_cast<std::chrono::milliseconds>((stop) - (start)).count();
	}
	soci::connection_pool &mPool;
};

} //end of namespace

