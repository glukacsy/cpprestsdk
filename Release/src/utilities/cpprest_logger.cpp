#include "cpprest/cpprest_logger.h"



utils::Logger* slogger = nullptr;

void utils::set_logger(utils::Logger* logger)
{
    slogger = logger;
}

void utils::log(const std::string& message)
{
    if (slogger)
    {
        slogger->log(message);
    }
}
