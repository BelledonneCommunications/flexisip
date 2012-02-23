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

class DosProtection{
	public:
		static DosProtection *get();
		void start();
		void stop();
	private:
		void load();
		DosProtection();
		~DosProtection();
		static DosProtection *sInstance;
		static const int mPort;
		static const int mBlacklistMax;
		static const int mPeriod;
		static const char* mProtocol;
		static const char *mLogLevel;
		static const char *mLogPrefix;
		static const char *mFlexisipChain;
		static const char *mBlacklistChain;
		static const char *mCounterlist;
		static const char *mPath;
		bool isLoaded;
		bool mEnabled;
		int mBanDuration;
		int mPacketsLimit;
		int mMaximumConnections;
		std::list<std::string> mAuthorizedIPs;
};
