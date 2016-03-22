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

#include "threadpool.hh"
#include "log/logmanager.hh"

// Constructor.
ThreadPool::ThreadPool(unsigned int threads, unsigned int max_queue_size)
	: max_queue_size(max_queue_size), terminate(false), stopped(false) {
	SLOGE << "[POOL] Init with " << threads << " threads and queue size " << max_queue_size;

	// Create number of required threads and add them to the thread pool vector.
	for (unsigned int i = 0; i < threads; i++) {
		threadPool.emplace_back(thread(&ThreadPool::Invoke, this));
	}
}

bool ThreadPool::Enqueue(function<void()> f) {
	bool enqueued = false;
	// Scope based locking.
	{
		// Put unique lock on task mutex.
		unique_lock<mutex> lock(tasksMutex);

		// Push task into queue.
		if (tasks.size() < max_queue_size) {

			//SLOGE << "[POOL] Enqueue(" << tasks.size() << ")";

			tasks.push(f);
			enqueued = true;
		}
	}

	// Wake up one thread if the task was successfully queued
	if (enqueued)
		condition.notify_one();

	return enqueued;
}

bool ThreadPool::conditionCheck() const {
	return !tasks.empty() || terminate;
}

void ThreadPool::Invoke() {

	function<void()> task;
	while (true) {
		// Scope based locking.
		{
			// Put unique lock on task mutex.
			unique_lock<mutex> lock(tasksMutex);
			
			auto predicate = std::bind(&ThreadPool::conditionCheck, this);

			// Wait until queue is not empty or termination signal is sent.
			condition.wait(lock, predicate);

			// If termination signal received and queue is empty then exit else continue clearing the queue.
			if (terminate && tasks.empty()) {
				SLOGE << "[POOL] Terminate thread";
				return;
			}

			// Get next task in the queue.
			task = tasks.front();

			// Remove it from the queue.
			tasks.pop();
			//SLOGE << "[POOL] Pop task " << tasks.size();
		}

		// Execute the task.
		//SLOGE << "[POOL] Task()";
		task();
	}
}

void ThreadPool::ShutDown() {
	SLOGE << "[POOL] Shutdown";
	// Scope based locking.
	{
		// Put unique lock on task mutex.
		unique_lock<mutex> lock(tasksMutex);

		// Set termination flag to true.
		terminate = true;
	}

	// Wake up all threads.
	condition.notify_all();

	// Join all threads.
	for (auto it = threadPool.begin(); it != threadPool.end(); ++it) {
		it->join();
	}

	// Empty workers vector.
	threadPool.empty();

	// Indicate that the pool has been shut down.
	stopped = true;
}

// Destructor.
ThreadPool::~ThreadPool() {
	if (!stopped) {
		ShutDown();
	}
}
