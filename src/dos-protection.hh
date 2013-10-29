/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010  Belledonne Communications SARL.

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

#include <string>
#include <list>
#include "configmanager.hh"
#include "agent.hh"
struct Agent;


class DosProtection : protected ConfigValueListener {
	public:
		static DosProtection *get();
		bool doOnConfigStateChanged(const ConfigValue &conf, ConfigState state);
		void start();
		void stop();
		static nta_agent_t *sSofiaAgent;
	private:
		DosProtection();
		static void atexit(); // Don't call directly!
		virtual ~DosProtection();
		void load();
		static DosProtection *sInstance;
		int mPeriod;
		const char *mLogLevel;
		const char *mLogPrefix;
		const char *mFlexisipChain;
		const char *mBlacklistChain;
		const char *mCounterlist;
		const char *mPath;
		const char* mRecentDirectoryName;
		bool mLoaded;
		bool mEnabled;
		int mBanDuration;
		int mPacketsLimit;
		int mNetmaskToUseToFilterSimultaneousConnections;
		int mMaximumConnections;
		int mMaximumConnectionsToWatch;
		std::list<std::string> mAuthorizedIPs;
};
