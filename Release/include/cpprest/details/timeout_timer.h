#pragma once

#ifndef _CASA_TIMEOUT_TIMER_H
#define _CASA_TIMEOUT_TIMER_H

#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>

#include <memory>
#include <mutex>

namespace utils
{
    // Simple timer class wrapping Boost deadline timer.
    
    class timeout_timer : public std::enable_shared_from_this<timeout_timer>
    {
    public:
        
        using CommandHandler = std::function<void(timeout_timer *)>;
#if defined(ANDROID) || defined(__ANDROID__)
#define cpprest_chrono boost::chrono
        using Duration = cpprest_chrono::microseconds;
#else
#define cpprest_chrono std::chrono
        using Duration = cpprest_chrono::microseconds;
#endif
        
        static std::shared_ptr<timeout_timer> create(boost::asio::io_service& service, const Duration& timeout, CommandHandler commandHandler)
        {
            return std::shared_ptr<timeout_timer>(new timeout_timer(service, timeout, commandHandler));
        }
        
        ~timeout_timer()
        {
            stop();
        }
        
        void start()
        {
            ScopedLock l(m_mutex);
            
            if (m_state == created || m_state == stopped)
            {
                m_state = started;
            
                m_timer.expires_from_now(m_duration);
                m_timer.async_wait(getHandler());
            }
        }
        
        void reset()
        {
            ScopedLock l(m_mutex);
            assert(m_state == started);
            if(m_timer.expires_from_now(m_duration) > 0)
            {
                // The existing handler was canceled so schedule a new one.
                assert(m_state == started);
                m_timer.async_wait(getHandler());
            }
        }
        
        void retrigger()
        {
            ScopedLock l(m_mutex);
            m_timer.expires_from_now(m_duration);
            m_timer.async_wait(getHandler());
        }
        
        
        bool has_started() const
        {
            ScopedLock l(m_mutex);
            return m_state == started;
        }
        
        void stop()
        {
            ScopedLock l(m_mutex);
            m_state = stopped;
            m_timer.cancel();
        }
        
        bool isTimedout() const
        {
            ScopedLock l(m_mutex);
            return m_state == timedout;
        }
    
    protected:
        timeout_timer(boost::asio::io_service& service, const Duration& timeout, CommandHandler commandHandler) :
        m_duration(timeout.count()),
        m_state(created),
        m_timer(service),
        m_handler(commandHandler)
        {}
        
    private:
        enum timer_state
        {
            created,
            started,
            stopped,
            timedout
        };
        
        timer_state testAndSetState(timer_state newState)
        {
            ScopedLock l(m_mutex);
            auto oldState = m_state;
            m_state = newState;
            return oldState;
        }
        
        std::function<void (const boost::system::error_code&)> getHandler()
        {
            auto handler = m_handler;
            std::weak_ptr<timeout_timer> weakThis = shared_from_this();
            return [handler, weakThis](const boost::system::error_code& ec)
            {
                auto lockedThis = weakThis.lock();
                if (lockedThis)
                {
                    switch (lockedThis->testAndSetState(timedout))
                    {
                    case started:
                        if (!ec)
                        {
                            handler(lockedThis.get());
                        }
                        break;
                    default:
                        break;
                    }
                }
            };
        }
        
        using ScopedLock = std::unique_lock<std::mutex>;
        
        Duration m_duration;
        timer_state m_state {created};
        boost::asio::steady_timer m_timer;
        CommandHandler m_handler;
        mutable std::mutex m_mutex;
    };
}

#endif

