// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>

#include "EventRecord.hpp"
#include "EventRecordError.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Delegate called when a new ETW <see cref="O365::Security::ETW::EventRecord"/> is received.
    /// </summary>
    public delegate void IEventRecordDelegate(IEventRecord^ record);

    /// <summary>
    /// Delegate called on errors when processing an <see cref="O365::Security::ETW::EventRecord"/>.
    /// </summary>
    public delegate void EventRecordErrorDelegate(IEventRecordError^ error);

    ref class CallbackBridge {
    private:

        delegate void EventReceivedDelegate(const EVENT_RECORD&, const krabs::trace_context&);
        delegate void ErrorReceivedDelegate(const EVENT_RECORD&, const std::string&);

        EventReceivedDelegate^ eventDelegateKeepAlive = gcnew EventReceivedDelegate(this, &CallbackBridge::EventNotification);
        ErrorReceivedDelegate^ errorDelegateKeepAlive = gcnew ErrorReceivedDelegate(this, &CallbackBridge::ErrorNotification);

        void EventNotification(const EVENT_RECORD& record, const krabs::trace_context& trace_context);
        void ErrorNotification(const EVENT_RECORD& record, const std::string& error_message);

    public:

        IEventRecordDelegate^ OnEvent;
        EventRecordErrorDelegate^ OnError;

        krabs::c_provider_callback GetOnEventBridge()
		{
			return (krabs::c_provider_callback)Marshal::GetFunctionPointerForDelegate(eventDelegateKeepAlive).ToPointer();
		}

        krabs::c_provider_error_callback GetOnErrorBridge()
        {
			return (krabs::c_provider_error_callback)Marshal::GetFunctionPointerForDelegate(errorDelegateKeepAlive).ToPointer();
        }
    };

    inline void CallbackBridge::EventNotification(const EVENT_RECORD& record, const krabs::trace_context& trace_context)
    {
        auto onEvent = OnEvent;
        if (!onEvent)
            return;

        TDHSTATUS status = ERROR_SUCCESS;
        trace_context.schema_locator.get_event_schema_no_throw(record, status);

        if (status == ERROR_SUCCESS) {
            krabs::schema schema(record, trace_context.schema_locator);
            krabs::parser parser(schema);

            onEvent(gcnew EventRecord(record, schema, parser));
        }
        else {
            auto error_message = krabs::get_status_and_record_context(status, record);
            ErrorNotification(record, error_message);
        }
    }

    inline void CallbackBridge::ErrorNotification(const EVENT_RECORD& record, const std::string& error_message)
    {
        auto onError = OnError;
        if (!onError)
            return;

        auto msg = gcnew String(error_message.c_str());
        auto metadata = gcnew EventRecordMetadata(record);

        onError(gcnew EventRecordError(msg, metadata));
    }

#define OnEventHelper(bridge) \
    { \
        void add(IEventRecordDelegate^ callback) \
        { \
            IEventRecordDelegate^ original = bridge->OnEvent; \
            IEventRecordDelegate^ comparand; \
            do \
            { \
                comparand = original; \
                original = (IEventRecordDelegate^)System::Threading::Interlocked::CompareExchange(bridge->OnEvent, (IEventRecordDelegate^)Delegate::Combine(comparand, callback), comparand); \
            } while (original != comparand); \
        } \
        void remove(IEventRecordDelegate^ callback) \
        { \
            IEventRecordDelegate^ original = bridge->OnEvent; \
            IEventRecordDelegate^ comparand; \
            do \
            { \
                comparand = original; \
                original = (IEventRecordDelegate^)System::Threading::Interlocked::CompareExchange(bridge->OnEvent, (IEventRecordDelegate^)Delegate::Remove(comparand, callback), comparand); \
            } while (original != comparand); \
        } \
        void raise(IEventRecord^ record) \
        { \
            IEventRecordDelegate^ onEvent = bridge->OnEvent; \
            if (onEvent) \
            { \
                onEvent(record); \
            } \
        } \
    } \

#define OnErrorHelper(bridge) \
    { \
        void add(EventRecordErrorDelegate^ callback) \
        { \
            EventRecordErrorDelegate^ original = bridge->OnError; \
            EventRecordErrorDelegate^ comparand; \
            do \
            { \
                comparand = original; \
                original = (EventRecordErrorDelegate^)System::Threading::Interlocked::CompareExchange(bridge->OnError, (EventRecordErrorDelegate^)Delegate::Combine(comparand, callback), comparand); \
            } while (original != comparand); \
        } \
        void remove(EventRecordErrorDelegate^ callback) \
        { \
            EventRecordErrorDelegate^ original = bridge->OnError; \
            EventRecordErrorDelegate^ comparand; \
            do \
            { \
                comparand = original; \
                original = (EventRecordErrorDelegate^)System::Threading::Interlocked::CompareExchange(bridge->OnError, (EventRecordErrorDelegate^)Delegate::Remove(comparand, callback), comparand); \
            } while (original != comparand); \
        } \
        void raise(IEventRecordError^ error) \
        { \
            EventRecordErrorDelegate^ onError = bridge->OnError; \
            if (onError) \
            { \
                onError(error); \
            } \
        } \
    } \

} } } }