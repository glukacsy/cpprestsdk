/***
* Copyright (C) Microsoft. All rights reserved.
* Licensed under the MIT license. See LICENSE.txt file in the project root for full license information.
*
* =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
*
* HTTP Library: Request and reply message definitions (client side).
*
* For the latest on this and related APIs, please see: https://github.com/Microsoft/cpprestsdk
*
* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
****/
#include "stdafx.h"
#include "../common/internal_http_helpers.h"

namespace web { namespace http
{

uri details::_http_request::relative_uri() const
{
    // If the listener path is empty, then just return the request URI.
    if(m_listener_path.empty() || m_listener_path == _XPLATSTR("/"))
    {
        return m_uri.resource();
    }

    utility::string_t prefix = uri::decode(m_listener_path);
    utility::string_t path = uri::decode(m_uri.resource().to_string());
    if(path.empty())
    {
        path = _XPLATSTR("/");
    }

    auto pos = path.find(prefix);
    if (pos == 0)
    {
        return uri(uri::encode_uri(path.erase(0, prefix.length())));
    }
    else
    {
        throw http_exception(_XPLATSTR("Error: request was not prefixed with listener uri"));
    }
}

uri details::_http_request::absolute_uri() const
{
    if (m_base_uri.is_empty())
    {
        return m_uri;
    }
    else
    {
        return uri_builder(m_base_uri).append(m_uri).to_uri();
    }
}

void details::_http_request::set_request_uri(const uri& relative)
{
    m_uri = relative;
}

utility::string_t details::_http_request::to_string() const
{
    utility::ostringstream_t buffer;
    buffer.imbue(std::locale::classic());
    buffer << m_method << _XPLATSTR(" ") << (this->m_uri.is_empty() ? _XPLATSTR("/") : this->m_uri.to_string()) << _XPLATSTR(" HTTP/1.1\r\n");
    buffer << http_msg_base::to_string();
    return buffer.str();
}

}} // namespace web::http
