#ifndef _WIN32

#include "stdafx.h"
#include <cpprest/details/fast_ipv4_fallback.h>

#include <iterator>



using Iterator = boost::asio::ip::tcp::resolver::iterator;
using Endpoints = std::vector<Iterator::value_type>;

static Endpoints arrangeEndpoints(Endpoints&& endpoints)
{
    if (!endpoints.empty())
    {
        if (endpoints[0].endpoint().address().is_v6())
        {
            auto found = std::find_if(endpoints.begin() + 1, endpoints.end(),[](const Endpoints::value_type& endpoint)
            {
                return endpoint.endpoint().address().is_v4();
            });
            
            if (found != endpoints.end())
            {
                typedef Endpoints::iterator iter_t;
                Endpoints ipv6Endpoints;
                
                std::copy(std::move_iterator<iter_t>(endpoints.begin() + 1), std::move_iterator<iter_t>(found), std::back_inserter(ipv6Endpoints));
                endpoints.erase(endpoints.begin() + 1, found);
                endpoints.insert(endpoints.end(), ipv6Endpoints.begin(), ipv6Endpoints.end());
            }
        }
    }
    return endpoints;
}

namespace web { namespace http{namespace details{
boost::asio::ip::tcp::resolver::iterator createHappyEyeballsEndpointList(boost::asio::ip::tcp::resolver::iterator endpoint)
{
    Endpoints endpoints;
    
    for(auto itr = endpoint; itr != Iterator(); ++itr)
    {
        endpoints.emplace_back(*itr);
    }
    
    endpoints = arrangeEndpoints(std::move(endpoints));
    
    auto host    = !endpoints.empty() ? endpoints[0].host_name() : std::string();
    auto service = !endpoints.empty() ? endpoints[0].service_name() : std::string();
    
    return boost::asio::ip::tcp::resolver::iterator::create(endpoints.begin(), endpoints.end(), host, service);
}
    
boost::asio::ip::tcp::resolver::iterator insertFront(const boost::asio::ip::tcp::resolver::endpoint_type &front, boost::asio::ip::tcp::resolver::iterator endpoint)
{
    Endpoints endpoints;
    
    auto host    = endpoint->host_name();
    auto service = endpoint->service_name();
    
    endpoints.emplace_back(front, host, service);
        
    for(auto itr = endpoint; itr != Iterator(); ++itr)
    {
        endpoints.emplace_back(*itr, host, service);
    }
        
    return boost::asio::ip::tcp::resolver::iterator::create(endpoints.begin(), endpoints.end(), host, service);
}
    
    

AddressCache::Key::Key(const std::string& host, const std::string& service) : m_key(host + service)
{
}
        
AddressCache::Key::Key(): Key("", "")
{
}
        
bool AddressCache::Key::isEmpty() const
{
    return m_key.empty();
}
        
bool AddressCache::Key::operator<(const Key& key) const
{
    return m_key < key.m_key;
}

std::shared_ptr<AddressCache> AddressCache::create(boost::asio::io_service& io_service)
{
    auto instance = std::shared_ptr<AddressCache>(new AddressCache(io_service));
    
    instance->m_timer = utils::timeout_timer::create(io_service, utils::timeout_timer::Duration(instance->purgeCacheDelay), instance->createCallback());
    instance->m_timer->start();
    
    return instance;
}
    
AddressCache::AddressCache(boost::asio::io_service& io_service)
{
}
        
AddressCache::~AddressCache()
{
    ScopedLock l(m_mutex);
    m_timer->stop();
}
        
void AddressCache::add(const key_type& key, const value_type& value)
{
    ScopedLock l(m_mutex);
            
    storage[key] = value;
}
        
AddressCache::value_type AddressCache::get(const key_type& key) const
{
    ScopedLock l(m_mutex);
            
    auto found = storage.find(key);
            
    return found != storage.end() ? found->second : value_type();
}
    
std::function<void (utils::timeout_timer *timer)> AddressCache::createCallback()
{
    auto weakThis = std::weak_ptr<AddressCache>(shared_from_this());
    return  [weakThis](utils::timeout_timer *timer)
    {
        auto sharedThis = weakThis.lock();
        if (sharedThis)
        {
            {
                ScopedLock l(sharedThis->m_mutex);
                sharedThis->storage.clear();
            }
            sharedThis->m_timer->retrigger();
        }
    };
}
}
}
}

#endif
