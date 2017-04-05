#pragma once

#ifndef _CASA_FAST_IPV4_FALLBACK_H
#define _CASA_FAST_IPV4_FALLBACK_H

#include <boost/asio.hpp>

#include "timeout_timer.h"

#include <memory>
#include <map>
#include <mutex>
#include <functional>

namespace web { namespace http{namespace details{
    using Iterator = boost::asio::ip::tcp::resolver::iterator;
    using Endpoints = std::vector<Iterator::value_type>;
    
    Iterator createHappyEyeballsEndpointList(Iterator endpoint);
    Iterator insertFront(const boost::asio::ip::tcp::resolver::endpoint_type &front, Iterator endpoint);


    class AddressCache : public std::enable_shared_from_this<AddressCache>
    {
    public:
        
        class Key
        {
        public:
            Key(const std::string& host, const std::string& port);
            
            Key();
            
            bool isEmpty() const;
            
            bool operator<(const Key& key) const;
            
        private:
            std::string m_key;
        };
        
        using Delay = cpprest_chrono::minutes;
        using key_type = Key;
        using value_type = boost::asio::ip::tcp::resolver::endpoint_type;
        
        const Delay purgeCacheDelay = Delay(10);
        
        static std::shared_ptr<AddressCache> create(boost::asio::io_service& io_service);
        
        ~AddressCache();
        
        void add(const key_type& key, const value_type& value);
        
        value_type get(const key_type& key) const;
    protected:
        AddressCache(boost::asio::io_service& io_service);
        
    private:
        std::function<void (utils::timeout_timer *timer)> createCallback();
        
        using ScopedLock = std::unique_lock<std::mutex>;
        mutable std::mutex m_mutex;
        
        std::shared_ptr<utils::timeout_timer> m_timer;
        
        std::map<key_type, value_type> storage;
    };
}
}
}

#endif

