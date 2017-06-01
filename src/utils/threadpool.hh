/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2016  Belledonne Communications SARL.

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

// From http://alexagafonov.com/2015/05/05/thread-pool-implementation-in-c-11/ and modified for queue size handling

#pragma once

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <iostream>
#include <functional>
#include <unistd.h>

class ThreadPool {
  public:
	// Constructor.
	ThreadPool(unsigned int threads, unsigned int max_queue_size);

	// Destructor.
	~ThreadPool();

	// Adds task to a task queue.
	bool Enqueue(std::function<void()> f);

	// set pool size (only allowed if not yet populated)
	void setPoolSize(int threads);

	// Shut down the pool.
	void ShutDown();

  private:
	// Thread pool storage.
	std::vector<std::thread> threadPool;

	// Queue to keep track of incoming tasks.
	std::queue<std::function<void()>> tasks;

	// Task queue mutex.
	std::mutex tasksMutex;

	// Condition variable.
	std::condition_variable condition;

	// Maximum amount of tasks to be enqueued
	unsigned int max_queue_size;

	// Indicates that pool needs to be shut down.
	bool terminate;

	// Indicates that pool has been terminated.
	bool stopped;

	// Function that will be invoked by our threads.
	void Invoke();

	bool conditionCheck() const;
};
