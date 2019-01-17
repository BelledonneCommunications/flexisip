/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2018  Belledonne Communications SARL, All rights reserved.

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

#include <soci/soci.h>

#include <flexisip/logmanager.hh>

// =============================================================================

#define DB_TRANSACTION(SESSION) \
	DbTransactionInfo().set(__func__, SESSION) * [&](SmartTransaction &tr)

namespace flexisip {

class SmartTransaction {
public:
	SmartTransaction (soci::session *session, const char *name) : mSession(session), mName(name), mIsCommitted(false) {
		SLOGI << "Start transaction " << this << " in " << mName << ".";
		mSession->begin();
	}

	SmartTransaction (const SmartTransaction &) = delete;
	SmartTransaction &operator= (const SmartTransaction &) = delete;

	~SmartTransaction () {
		if (!mIsCommitted) {
			SLOGI << "Rollback transaction " << this << " in " << mName << ".";
			mSession->rollback();
		}
	}

	void commit () {
		if (mIsCommitted) {
			SLOGE << "Transaction " << this << " in " << mName << " already committed!!!";
			return;
		}

		SLOGI << "Commit transaction " << this << " in " << mName << ".";
		mIsCommitted = true;
		mSession->commit();
	}

private:
	soci::session *mSession;
	const char *mName;
	bool mIsCommitted;
};

struct DbTransactionInfo {
	DbTransactionInfo &set (const char *_name, const soci::session *_session) {
		name = _name;
		session = const_cast<soci::session *>(_session);
		return *this;
	}

	const char *name = nullptr;
	soci::session *session = nullptr;
};

template<typename Function>
class DbTransaction {
	using InternalReturnType = typename std::remove_reference<
		decltype(std::declval<Function>()(std::declval<SmartTransaction &>()))
	>::type;

public:
	using ReturnType = typename std::conditional<
		std::is_same<InternalReturnType, void>::value,
		bool,
		InternalReturnType
	>::type;

	DbTransaction (DbTransactionInfo &info, Function &&function) : mFunction(std::move(function)) {
		const char *name = info.name;
		soci::session *session = info.session;

		try {
			SmartTransaction tr(session, name);
			mResult = exec<InternalReturnType>(tr);
		} catch (const soci::soci_error &e) {
			SLOGE << "Catched exception in " << name << "(" << e.what() << ").";
			soci::soci_error::error_category category = e.get_error_category();
			if (
				(category == soci::soci_error::connection_error || category == soci::soci_error::unknown) &&
				forceReconnect(session)
			) {
				try {
					SmartTransaction tr(session, name);
					mResult = exec<InternalReturnType>(tr);
				} catch (const std::exception &e) {
					SLOGE << "Unable to execute query after reconnect in " << name << "(" << e.what() << ").";
				}
				return;
			}
			SLOGE << "Unhandled [" << getErrorCategoryAsString(category) << "] exception in " <<
				name << ": `" << e.what() << "`.";
		} catch (const std::exception &e) {
			SLOGE << "Unhandled generic exception in " << name << ": `" << e.what() << "`.";
		}
	}

	DbTransaction (DbTransaction &&DbTransaction) : mFunction(std::move(DbTransaction.mFunction)) {}

	DbTransaction (const DbTransaction &) = delete;
	DbTransaction &operator= (const DbTransaction &) = delete;

	operator ReturnType () const { return mResult; }

private:
	// Exec function with no return type.
	template<typename T>
	typename std::enable_if<std::is_same<T, void>::value, bool>::type exec (SmartTransaction &tr) const {
		mFunction(tr);
		return true;
	}

	// Exec function with return type.
	template<typename T>
	typename std::enable_if<!std::is_same<T, void>::value, T>::type exec (SmartTransaction &tr) const {
		return mFunction(tr);
	}

	bool forceReconnect (soci::session *session) {
		constexpr int retryCount = 2;
		SLOGI << "Trying sql backend reconnect...";

		try {
			for (int i = 0; i < retryCount; ++i) {
				try {
					SLOGI << "Reconnect... Try: " << i;
					session->reconnect();
					SLOGI << "Database reconnection successful!";
					return true;
				} catch (const soci::soci_error &e) {
					if (e.get_error_category() != soci::soci_error::connection_error)
						throw e;
				}
			}
		} catch (const std::exception &e) {
			SLOGE << "Unable to reconnect: `" << e.what() << "`.";
			return false;
		}

		SLOGE << "Database reconnection failed!";

		return false;
	}

	static const char *getErrorCategoryAsString (soci::soci_error::error_category category) {
		switch (category) {
			case soci::soci_error::connection_error:
				return "CONNECTION ERROR";
			case soci::soci_error::invalid_statement:
				return "INVALID STATEMENT";
			case soci::soci_error::no_privilege:
				return "NO PRIVILEGE";
			case soci::soci_error::no_data:
				return "NO DATA";
			case soci::soci_error::constraint_violation:
				return "CONSTRAINT VIOLATION";
			case soci::soci_error::unknown_transaction_state:
				return "UNKNOWN TRANSACTION STATE";
			case soci::soci_error::system_error:
				return "SYSTEM ERROR";
			case soci::soci_error::unknown:
				return "UNKNOWN";
		}

		// Unreachable.
		return nullptr;
	}

	Function mFunction;
	ReturnType mResult{};
};

template<typename Function>
typename DbTransaction<Function>::ReturnType operator* (DbTransactionInfo &info, Function &&function) {
	return DbTransaction<Function>(info, std::forward<Function>(function));
}

}