#pragma once

#include "cpprest/asyncrt_utils.h"

#include <string>

namespace utils
{
class Logger
{
public:
    virtual void log(const std::string& message) = 0;
};

extern void _ASYNCRTIMP set_logger(utils::Logger* logger);

extern void _ASYNCRTIMP log(const std::string& message);

}

