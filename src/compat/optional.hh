#pragma once

#if __has_include(<optional>)
#include <optional>

#else
// Debian 9
#include <experimental/optional>
#include "scope-in-experimental.hh"

#endif