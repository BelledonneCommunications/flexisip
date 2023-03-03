/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/thread/auto-thread-pool.hh"
#include "utils/thread/basic-thread-pool.hh"

using namespace std;

namespace flexisip {
namespace tester {

template <typename ThreadPoolType>
class ThreadPoolTest : public Test {
public:
	void operator()() override {
		unique_ptr<ThreadPool> threadPool = make_unique<ThreadPoolType>(5, 5);

		try {
			for (int i = 0; i < 5; i++) {
				auto taskAdded = threadPool->run([&]() { _run(); });
				BC_HARD_ASSERT_TRUE(taskAdded);
			}
			BC_HARD_ASSERT_TRUE(waitFor([&]() { return mStartedCounter == 5; }, 100ms));
			BC_HARD_ASSERT_TRUE(mRunningCounter == 0);
			BC_HARD_ASSERT_TRUE(mEndedCounter == 0);

			for (int i = 0; i < 5; i++) {
				auto taskAdded = threadPool->run([&]() { _run(); });
				BC_HARD_ASSERT_TRUE(taskAdded);
			}
			BC_HARD_ASSERT_TRUE(mStartedCounter == 5);
			BC_HARD_ASSERT_TRUE(mRunningCounter == 0);
			BC_HARD_ASSERT_TRUE(mEndedCounter == 0);

			for (int i = 0; i < 5; i++) {
				auto taskAdded = threadPool->run([&]() { _run(); });
				BC_HARD_ASSERT_FALSE(taskAdded);
			}
			BC_HARD_ASSERT_TRUE(mStartedCounter == 5);
			BC_HARD_ASSERT_TRUE(mRunningCounter == 0);
			BC_HARD_ASSERT_TRUE(mEndedCounter == 0);

			mCanRun = true;
			mCondition.notify_all();
			BC_HARD_ASSERT_TRUE(waitFor([&]() { return mRunningCounter == 5; }, 200ms));
			BC_HARD_ASSERT_TRUE(mStartedCounter == 5);
			BC_HARD_ASSERT_TRUE(mEndedCounter == 0);

			mCanRun = false;
			mCanStop = true;
			mCondition.notify_all();
			BC_HARD_ASSERT_TRUE(waitFor([&]() { return mEndedCounter == 5; }, 200ms));
			BC_HARD_ASSERT_TRUE(waitFor([&]() { return mStartedCounter == 10; }, 200ms));
			BC_HARD_ASSERT_TRUE(mRunningCounter == 5);

			mCanRun = true;
			mCanStop = false;
			mCondition.notify_all();
			BC_HARD_ASSERT_TRUE(waitFor([&]() { return mRunningCounter == 10; }, 200ms));
			BC_HARD_ASSERT_TRUE(mStartedCounter == 10);
			BC_HARD_ASSERT_TRUE(mEndedCounter == 5);

			mCanStop = true;
			mCondition.notify_all();
			threadPool->stop();
			BC_HARD_ASSERT_TRUE(mStartedCounter == 10);
			BC_HARD_ASSERT_TRUE(mRunningCounter == 10);
			BC_HARD_ASSERT_TRUE(mEndedCounter == 10);
		} catch (exception& e) {
			mCanRun = true;
			mCanStop = true;
			mCondition.notify_all();
			threadPool->stop();
			throw e;
		}
	}

private:
	void _run() {
		mStartedCounter++;
		unique_lock<mutex> lock(mCondMutex);
		mCondition.wait(lock, [&]() { return mCanRun.load(); });
		lock.unlock();
		mRunningCounter++;

		lock.lock();
		mCondition.wait(lock, [&]() { return mCanStop.load(); });
		lock.unlock();
		mEndedCounter++;
	};

	std::atomic_uint mStartedCounter;
	std::atomic_uint mRunningCounter;
	std::atomic_uint mEndedCounter;

	std::atomic_bool mCanRun{false};
	std::atomic_bool mCanStop{false};

	std::mutex mCondMutex;
	std::condition_variable mCondition{};
};

namespace {
TestSuite _("Thread pool tests",
            {
                TEST_NO_TAG("BasicThreadPool testing", run<ThreadPoolTest<BasicThreadPool>>),
                TEST_NO_TAG("AutoThreadPool testing", run<ThreadPoolTest<AutoThreadPool>>),
            });
}
} // namespace tester
} // namespace flexisip
