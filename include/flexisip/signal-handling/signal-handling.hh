/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <unistd.h>

#include <csignal>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace flexisip {

namespace signal_handling {

using SigNum = decltype(SIGTERM);
using PipeDescriptor = int;

union SignalData {
	SigNum signum;
	uint8_t bytes[sizeof(signum)];
};

/**
 * Registers a simple handler for the given POSIX signals that will forward the signal number to a pipe on reception.
 * A safe handler can then be implemented that reads the value from the pipe outside of the special signal context.
 *
 * On destruction, the PipedSignal will unbind the signal handler from the given signals and close the pipe.
 *
 * In the event that two PipedSignals are created for the same signal, the one created last will shadow the first (which
 * will therefore never be called again)
 */
class PipedSignal {
public:
	PipedSignal(std::vector<SigNum>&& signals);
	~PipedSignal();

	PipedSignal(PipedSignal&& other) = delete;
	PipedSignal(const PipedSignal& other) = delete;
	PipedSignal& operator=(const PipedSignal& other) = delete;
	PipedSignal& operator=(PipedSignal&& other) = delete;

	/* Get the file descriptor for the read end of the pipe */
	PipeDescriptor descriptor() {
		return mPipe.fd.read;
	}

	/* Read a signal number from the pipe into `data`.
	 * This is just a wrapper for POSIX `read` and will __block__ until there is data in the pipe
	 */
	ssize_t read(SignalData& data);

private:
	static std::unordered_map<SigNum, PipeDescriptor> sSignalToPipe;

	union SignalPipe {
		struct Descriptors {
			PipeDescriptor read;
			PipeDescriptor write;
		} fd;
		PipeDescriptor array[2];
	} mPipe;
	std::vector<SigNum> mSignals{};
};

} // namespace signal_handling

} // namespace flexisip
