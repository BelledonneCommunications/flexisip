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

#pragma once

#include <chrono>
#include <csignal>
#include <cstdint>
#include <functional>
#include <variant>

#include "pipe.hh"
#include "utils/sys-err.hh"

namespace flexisip {
namespace process {

using SigNum = decltype(SIGTERM);

class Process;

/**
 * A state that should never be reached, even under abnormal circumstances such as exceptions or syscall errors.
 */
class Unexpected {};

std::ostream& operator<<(std::ostream&, const Unexpected&);

/**
 * A running Process, with its associated pipes (stdin, stdout, stderr).
 */
class Running {
	friend Process;
	friend std::ostream& operator<<(std::ostream&, const Running&);
	friend std::ostream& operator<<(std::ostream&, Running&&);

public:
	pipe::Pipe mStdin;
	pipe::Pipe mStdout;
	pipe::Pipe mStderr;

	// Send given signal to child process, as if by calling ::kill() with its pid.
	[[nodiscard]] std::optional<SysErr> signal(SigNum);

private:
	Running(pipe::WriteOnly&& in, pipe::ReadOnly&& out, pipe::ReadOnly&& err, pid_t pid)
	    : mStdin(std::move(in)), mStdout(std::move(out)), mStderr(std::move(err)), mPid(pid) {
	}

	pid_t mPid;
};

/**
 * A process that finished executing in normal conditions (e.g. not aborted). A process that exited normally could still
 * be reporting errors in its execution and users are expected to check the exit code.
 */
class ExitedNormally {
	friend Process;
	friend std::ostream& operator<<(std::ostream&, const ExitedNormally&);
	friend std::ostream& operator<<(std::ostream&, ExitedNormally&&);

public:
	uint8_t mExitCode;
	pipe::Pipe mStdout;
	pipe::Pipe mStderr;

private:
	ExitedNormally(Running&& process, uint8_t exitCode)
	    : mExitCode(exitCode), mStdout(std::move(process.mStdout)), mStderr(std::move(process.mStderr)) {
	}
};

using State = std::variant<Unexpected, Running, ExitedNormally, SysErr>;

/**
 * Type-safe API to spawn and manage a POSIX (sub)process.
 *
 * Creating an instance of this class will spawn a process running the function passed as argument. Users are then
 * expected to repeatedly call state() to get updated of the process state and interact with it, and/or wait() to block
 * until the process exits.
 *
 * The standard streams of the spawned process (stdin, stdout, stderr) are rewired to internal pipes. This means you
 * will not see a subprocess' stdout unless you print it, and a subprocess will not receive anything from the parent's
 * stdin unless you forward it.
 *
 * Except closing the potential pipes, the destructor does *absolutely nothing*. It is the responsibility of the user to
 * signal and wait for the child process to quit if they so desire.
 *
 * See the classes in the State variant for available interactions.
 */
class Process {
	friend std::ostream& operator<<(std::ostream&, const Process&);
	friend std::ostream& operator<<(std::ostream&, Process&&);

public:
	explicit Process(std::function<void()>&&);

	// no copy only move
	Process(const Process&) = delete;
	Process& operator=(const Process&) = delete;
	Process(Process&&) noexcept = default;
	Process& operator=(Process&&) noexcept = default;

	// Checks and updates the state of the Process and returns a ref to it.
	// Depending on that state, you can then interact further with the process, such as writing to stdin, reading from
	// stdout, or signaling the process for termination.
	State& state();

	// ⚠️ BLOCKING
	// Blocks the current thread until the subprocess exits, returning the state it exited in.
	std::variant<Unexpected, TimeOut, ExitedNormally, SysErr>
	wait(std::chrono::milliseconds timeout = std::chrono::seconds(10)) &&;

private:
	void _wait(int noHang);

	State mState;
};

} // namespace process
} // namespace flexisip