#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <windef.h>
#include <intrin.h>
#include <ntstrsafe.h>

#include "ia32.h"
#include "definitions.h"
#include "encrypt.h"
#include "crt.h"
#include "utils.h"
#include "interface.h"
#include "cache.h"
#include "cleaning.h"
#include "physical_internals.h"

/*
*	details: my vmt driver just recoded + with more checks, mdl cleaning functionality has been removed
*   so you must specify it in kdmapper when you map this driver.
* 
*	args: kdmapper.exe driver.sys --mdl
* 
*	the imports are still there but anticheats don't care about them.
* 
*	aswell as the apc is not queueable when the data ptr is invoked.
*/

__int64 __fastcall cache::f_hook( void *a1 )
{
	PKTHREAD_META thread = ((PKTHREAD_META)((uintptr_t)KeGetCurrentThread( )));

	if (thread->ApcQueueable == 1 )
		thread->ApcQueueable = 0;

	if ( !a1 || ExGetPreviousMode( ) != UserMode || reinterpret_cast< request_data * >( a1 )->unique != request_unique )
	{
		return cache::o_hook( a1 );
	}

	const auto request = reinterpret_cast< request_data * >( a1 );

	switch ( request->code )
	{
	case request_base:
	{
		base_request data { 0 };

		if ( !utils::safe_copy( &data, request->data, sizeof( base_request ) ) )
		{
			return 0;
		}

		if ( !data.pid )
		{
			return 0;
		}

		const auto base = utils::get_module_handle( data.pid, data.name );

		if ( !base )
		{
			return 0;
		}

		reinterpret_cast< base_request * > ( request->data )->handle = base;

		break;
	}
	case request_guardreg:
	{	
		guardreg_request data{ 0 };

		const auto allocation = utils::find_guarded_region();

		reinterpret_cast<guardreg_request*> (request->data)->allocation = allocation;

		break;
	}
	case request_write:
	{
		write_request data { 0 };

		if ( !utils::safe_copy( &data, request->data, sizeof( write_request ) ) )
		{
			return 0;
		}

		if ( !data.address || !data.pid || !data.buffer || !data.size )
		{
			return 0;
		}

		PEPROCESS process = 0;
		if (!NT_SUCCESS( PsLookupProcessByProcessId( (HANDLE)data.pid, &process ) ))
			return 0;

		ULONG_PTR process_dirbase = internals::process_cr3( process );
		if (!process_dirbase)
			return 0;

		ObDereferenceObject( process );

		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = data.size;

		while (TotalSize)
		{
			NTSTATUS out = 0;
			uint64_t CurPhysAddr = internals::translate_linear_address( process_dirbase, (ULONG64)data.address + CurOffset );
			if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

			ULONG64 WriteSize = min( PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize );
			SIZE_T BytesWritten = 0;
			out = internals::write_physical_address( CurPhysAddr, (PVOID)((ULONG64)reinterpret_cast<write_request*> (request->data)->buffer + CurOffset), WriteSize, &BytesWritten );
			TotalSize -= BytesWritten;
			CurOffset += BytesWritten;

			if (out != STATUS_SUCCESS)
				break;

			if (BytesWritten == 0)
				break;
		}

		break;
	}

	case request_process_base:
	{
		process_base_request data{ 0 };

		if (!utils::safe_copy( &data, request->data, sizeof( process_base_request ) ))
		{
			return 0;
		}

		if (!data.pid)
		{
			return 0;
		}

		PEPROCESS target_proc;
		if (!NT_SUCCESS( PsLookupProcessByProcessId( (HANDLE)data.pid, &target_proc ) ))
			return 0;

		uintptr_t base = (uintptr_t)PsGetProcessSectionBaseAddress( target_proc );
		if (!base)
			return 0;

		reinterpret_cast<process_base_request*> (request->data)->handle = base;

		ObDereferenceObject( target_proc );
		break;
	}

	case request_read:
	{
		read_request data { 0 };

		if ( !utils::safe_copy( &data, request->data, sizeof( read_request ) ) )
		{
			return 0;
		}

		if ( !data.address || !data.pid || !data.buffer || !data.size )
		{
			return 0;
		}

		PEPROCESS process = 0;
		if (!NT_SUCCESS(PsLookupProcessByProcessId( (HANDLE)data.pid, &process )))
			return 0;

		ULONG_PTR process_dirbase = internals::process_cr3( process );
		if (!process_dirbase)
			return 0;

		ObDereferenceObject( process );

		SIZE_T CurOffset = 0;
		SIZE_T TotalSize = data.size;

		while (TotalSize)
		{
			NTSTATUS out = 0;

			uint64_t CurPhysAddr = internals::translate_linear_address( process_dirbase, (ULONG64)data.address + CurOffset );
			if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

			ULONG64 ReadSize = min( PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize );
			SIZE_T BytesRead = 0;
			out = internals::read_physical_memory( CurPhysAddr, (PVOID)((ULONG64) reinterpret_cast<write_request*> (request->data)->buffer + CurOffset), ReadSize, &BytesRead );
			TotalSize -= BytesRead;
			CurOffset += BytesRead;

			if (out != STATUS_SUCCESS)
				break;

			if (BytesRead == 0)
				break;
		}

		break;
	} 
	}

	if (thread->ApcQueueable == 0)
		thread->ApcQueueable = 1;

	return 0;
}

NTSTATUS DriverEntry( PDRIVER_OBJECT, PUNICODE_STRING )
{
	const auto win32k = utils::get_kernel_module( e( "win32k.sys" ) );
	if (!win32k)
		return STATUS_ABANDONED;

	cache::qword_address = utils::find_pattern( win32k, e( "\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x06\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x06\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x06\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x06\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x06\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x06\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x38\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x10\x44\x8B\x54\x24\x00\x44\x89\x54\x24\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x38\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x06\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x06\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x38" ), e( "xxx????xxxxxxx????xxxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxxxxxxxxxxxxxxxxxxxx????xxxxxxxxx?xxxx?xx????xxxxxxxxxxxxxxxxxxx????xxxxxxx????xxxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxxxxxxxxxxxxxxxxx" ) );
	if (!cache::qword_address)
		return STATUS_ABANDONED;


	*(void**)&cache::o_hook = InterlockedExchangePointer( (void**)dereference( cache::qword_address ), (void*)cache::f_hook );

	return STATUS_SUCCESS;
}