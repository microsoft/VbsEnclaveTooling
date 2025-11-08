#pragma once
#include <cstdint>

namespace veil::any::logger
{
    enum class eventLevel : uint32_t
    {
        EVENT_LEVEL_CRITICAL = 1,
        EVENT_LEVEL_ERROR,
        EVENT_LEVEL_WARNING,
        EVENT_LEVEL_INFO,
        EVENT_LEVEL_VERBOSE
    };
}
