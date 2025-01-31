// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include <krabs.hpp>
#include <krabs/perfinfo_groupmask.hpp>

#include "EventRecord.hpp"
#include "EventRecordMetadata.hpp"
#include "Guid.hpp"
#include "NativePtr.hpp"
#include "Filtering/EventFilter.hpp"

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Microsoft { namespace O365 { namespace Security { namespace ETW {

    /// <summary>
    /// Represents a kernel trace provider and its configuration.
    /// </summary>
    public ref class KernelProvider {
    public:

        /// <summary>
        /// Constructs a KernelProvider that is identified by its GUID.
        /// </summary>
        /// <param name="flags">the trace flags to set</param>
        /// <param name="id">the guid of the kernel trace</param>
        /// <remarks>
        /// More information about trace flags can be found on MSDN:
        /// <see href="https://msdn.microsoft.com/en-us/library/windows/desktop/aa363784(v=vs.85).aspx"/>
        /// </remarks>
        KernelProvider(unsigned int flags, System::Guid id);

        /// <summary>
        /// Constructs a KernelProvider that is identified by its GUID.
        /// </summary>
        /// <param name="id">the guid of the kernel trace</param>
        /// <param name="mask">the group mask to set</param>
        /// <remarks>
        /// Only supported on Windows 8 and newer.
        /// More information about group masks can be found here:
        /// <see href="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/tracesup/perfinfo_groupmask.htm"/>
        /// </remarks>
        KernelProvider(System::Guid id, PERFINFO_MASK mask);

        /// <summary>
        /// Destructs a KernelProvider.
        /// </summary>
        ~KernelProvider();

        /// <summary>
        /// Adds a new EventFilter to the provider.
        /// </summary>
        /// <param name="filter">
        /// the <see cref="O365::Security::ETW::EventFilter"/> to
        /// filter incoming events with
        /// </param>
        void AddFilter(O365::Security::ETW::EventFilter ^filter) {
            provider_->add_filter(filter);
        }

        /// <summary>
        /// An event that is invoked when an ETW event is fired in this
        /// provider.
        /// </summary>
        event IEventRecordDelegate^ OnEvent;

        /// <summary>
        /// An event that is invoked when an ETW event is received
        /// but an error occurs handling the record.
        /// </summary>
        event EventRecordErrorDelegate^ OnError;

        /// <summary>
        /// Retrieves the GUID associated with this provider
        /// </summary>
        /// <returns>returns the GUID associated with this provider object</returns>
        property Guid Id {
            Guid get() {
                GUID guid = provider_->id();
                return Guid(guid.Data1, guid.Data2, guid.Data3,
                            guid.Data4[0], guid.Data4[1],
                            guid.Data4[2], guid.Data4[3],
                            guid.Data4[4], guid.Data4[5],
                            guid.Data4[6], guid.Data4[7]);
            }
        }


    internal:
        void EventNotification(const EVENT_RECORD&, const krabs::trace_context&);
        void ErrorNotification(const EVENT_RECORD&, const std::string&);

    internal:
        delegate void EventReceivedNativeHookDelegate(const EVENT_RECORD&, const krabs::trace_context&);
        delegate void ErrorReceivedNativeHookDelegate(const EVENT_RECORD&, const std::string&);

        NativePtr<krabs::kernel_provider> provider_;
        EventReceivedNativeHookDelegate^ eventReceivedDelegate_;
        ErrorReceivedNativeHookDelegate^ errorReceivedDelegate_;
        GCHandle eventReceivedDelegateHookHandle_;
        GCHandle errorReceivedDelegateHookHandle_;
        GCHandle eventReceivedDelegateHandle_;
        GCHandle errorReceivedDelegateHandle_;
        void RegisterCallbacks();
    };

    // Implementation
    // ------------------------------------------------------------------------

    inline KernelProvider::KernelProvider(unsigned int flags, System::Guid id)
    : provider_(flags, ConvertGuid(id))
    {
        RegisterCallbacks();
    }

    inline KernelProvider::KernelProvider(System::Guid id, PERFINFO_MASK mask)
        : provider_(ConvertGuid(id), mask)
    {
        RegisterCallbacks();
    }

    inline KernelProvider::~KernelProvider()
    {
        if (eventReceivedDelegateHandle_.IsAllocated)
        {
            eventReceivedDelegateHandle_.Free();
        }

        if (eventReceivedDelegateHookHandle_.IsAllocated)
        {
            eventReceivedDelegateHookHandle_.Free();
        }

        if (errorReceivedDelegateHandle_.IsAllocated)
        {
            errorReceivedDelegateHandle_.Free();
        }

        if (errorReceivedDelegateHookHandle_.IsAllocated)
        {
            errorReceivedDelegateHookHandle_.Free();
        }
    }

    inline void KernelProvider::RegisterCallbacks()
    {
        eventReceivedDelegate_ = gcnew EventReceivedNativeHookDelegate(this, &KernelProvider::EventNotification);
        eventReceivedDelegateHandle_ = GCHandle::Alloc(eventReceivedDelegate_);
        auto bridgedEventDelegate = Marshal::GetFunctionPointerForDelegate(eventReceivedDelegate_);
        eventReceivedDelegateHookHandle_ = GCHandle::Alloc(bridgedEventDelegate);

        provider_->add_on_event_callback((krabs::c_provider_callback)bridgedEventDelegate.ToPointer());

        errorReceivedDelegate_ = gcnew ErrorReceivedNativeHookDelegate(this, &KernelProvider::ErrorNotification);
        errorReceivedDelegateHandle_ = GCHandle::Alloc(errorReceivedDelegate_);
        auto bridgedErrorDelegate = Marshal::GetFunctionPointerForDelegate(errorReceivedDelegate_);
        errorReceivedDelegateHookHandle_ = GCHandle::Alloc(bridgedErrorDelegate);

        provider_->add_on_error_callback((krabs::c_provider_error_callback)bridgedErrorDelegate.ToPointer());
    }

    inline void KernelProvider::EventNotification(const EVENT_RECORD& record, const krabs::trace_context& trace_context)
    {
        TDHSTATUS status = ERROR_SUCCESS;
        trace_context.schema_locator.get_event_schema_no_throw(record, status);

        if (status == ERROR_SUCCESS) {
            krabs::schema schema(record, trace_context.schema_locator);
            krabs::parser parser(schema);

            OnEvent(gcnew EventRecord(record, schema, parser));
        }
        else {
            auto error_message = krabs::get_status_and_record_context(status, record);
            ErrorNotification(record, error_message);
        }
    }

    inline void KernelProvider::ErrorNotification(const EVENT_RECORD& record, const std::string& error_message)
    {
        auto msg = gcnew String(error_message.c_str());
        auto metadata = gcnew EventRecordMetadata(record);

        OnError(gcnew EventRecordError(msg, metadata));
    }

} } } }