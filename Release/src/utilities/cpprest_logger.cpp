#include "cpprest/cpprest_logger.h"



utils::Logger* slogger = nullptr;

utils::Logger* utils::set_logger(utils::Logger* logger)
{
    auto oldLogger = slogger;
    slogger = logger;
    
    return oldLogger;
}

void utils::log(const std::string& message)
{
    if (slogger)
    {
        slogger->log(message);
    }
}
