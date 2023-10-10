/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <chrono>
#include <string>
#include <utility>
#include <variant>

#include "compat/optional.hh"

#include "utils/sys-err.hh"

namespace flexisip {

/**
 * Indicates that a blocking syscall didn't return in time.
 */
class TimeOut {
public:
	std::chrono::microseconds duration; // The (minimum) amount of time waited
};

std::ostream& operator<<(std::ostream&, const TimeOut&);

namespace pipe {

using RawPipeDesc = int;

/**
 * File descriptor wrapper for one end of a Posix pipe. Closes the descriptor on destruction.
 */
class Descriptor {
	friend std::ostream& operator<<(std::ostream&, const Descriptor&);
	friend class Ready;

public:
	Descriptor(Descriptor&&);
	Descriptor& operator=(Descriptor&&);
	Descriptor(const Descriptor&) = delete;
	Descriptor& operator=(const Descriptor&) = delete;
	~Descriptor();

	// Attempts to duplicate this file descriptor to another number (with the ::dup2 syscall)
	[[nodiscard]] std::optional<SysErr> duplicateTo(RawPipeDesc);

protected:
	RawPipeDesc mDesc;

private:
	Descriptor(RawPipeDesc); // Private constructor for use in the Ready class
};

/**
 * A closed pipe.
 */
class Closed {};
std::ostream& operator<<(std::ostream&, const Closed&);

/**
 * A freshly created pipe as returned by pipe::open(), containing the file descriptors for its 2 ends.
 *
 * This state is designed to be transitioned to either ReadOnly, or WriteOnly after a process fork to facilitate
 * inter-process communication.
 */
class Ready {
	friend std::variant<Ready, SysErr> open();

public:
	Ready(Ready&&) = default;
	Ready& operator=(Ready&&) = default;

	Descriptor readEnd;
	Descriptor writeEnd;

private:
	Ready(RawPipeDesc[2]); // Private constructor for use in pipe::open()
};
std::ostream& operator<<(std::ostream&, const Ready&);

/**
 * The read end of a pipe.
 */
class ReadOnly : public Descriptor {
	friend std::ostream& operator<<(std::ostream&, const ReadOnly&);
	// Also read and print the contents of the pipe
	friend std::ostream& operator<<(std::ostream&, ReadOnly&&);

public:
	ReadOnly(Ready&&);

	// ⚠️ BLOCKING
	// Attempts to read the given amount of bytes from the pipe, blocking the current thread until either data is read,
	// the pipe is closed, or the timeout is reached.
	[[nodiscard]] std::variant<std::string, TimeOut, SysErr>
	read(size_t, std::chrono::microseconds timeout = std::chrono::seconds(5)) const;
};

/**
 * The write end of a pipe.
 */
class WriteOnly : public Descriptor {
	friend std::ostream& operator<<(std::ostream&, const WriteOnly&);

public:
	WriteOnly(Ready&&);

	// Attempts to write the string passed as argument to the pipe
	[[nodiscard]] std::optional<SysErr> write(const std::string&);
};

/**
 * A type-safe interface to Posix pipes. See the possible alternative classes for details.
 */
using Pipe = std::variant<Closed, Ready, ReadOnly, WriteOnly, SysErr>;

/**
 * Attempts to open a Posix pipe
 */
std::variant<Ready, SysErr> open();

} // namespace pipe
} // namespace flexisip
