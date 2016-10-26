#include "RemoteCode.h"

#pragma warning(disable : 4311 4302)

ULONG_PTR Align( ULONG_PTR val, ULONG_PTR alignment );

#pragma alloc_text(PAGE, BeginCall64)
#pragma alloc_text(PAGE, EndCall64)
#pragma alloc_text(PAGE, BeginCall32)
#pragma alloc_text(PAGE, EndCall32)

#pragma alloc_text(PAGE, AddPointerToBuffer)
#pragma alloc_text(PAGE, AddULong64ToBuffer)
#pragma alloc_text(PAGE, AddULongToBuffer)
#pragma alloc_text(PAGE, AddLong64ToBuffer)
#pragma alloc_text(PAGE, AddLongToBuffer)
#pragma alloc_text(PAGE, AddByteToBuffer)

#pragma alloc_text(PAGE, PushCall)
#pragma alloc_text(PAGE, PushUnicodeString32)
#pragma alloc_text(PAGE, PushUnicodeString)
#pragma alloc_text(PAGE, PushBool)
#pragma alloc_text(PAGE, PushByte)
#pragma alloc_text(PAGE, PushULong64)
#pragma alloc_text(PAGE, PushULong)
#pragma alloc_text(PAGE, PushLong64)
#pragma alloc_text(PAGE, PushLong)
#pragma alloc_text(PAGE, PushPointer)
#pragma alloc_text(PAGE, PushParameter)
#pragma alloc_text(PAGE, LoopCall)

#pragma alloc_text(PAGE, Call)
#pragma alloc_text(PAGE, Parameter)
#pragma alloc_text(PAGE, JumpShort)

#pragma alloc_text(PAGE, Align)

// Helper function
ULONG_PTR Align( ULONG_PTR val, ULONG_PTR alignment )
{
	if (val % alignment == 0)
		return val;
	return (val / alignment + 1) * alignment;
}

//
// CODE_BUFFER routines
//
VOID LoopCall( IN PCODE_BUFFER Buffer )
{
	Buffer->LoopCall = TRUE;
}

LONG JumpShort( IN PCODE_BUFFER Buffer, IN LONG Jump )
{
	LONG size = 0;
	size += AddByteToBuffer( Buffer, 0xEB );
	if (Jump < 2)
		size += AddByteToBuffer( Buffer, (UCHAR)(0xFE + Jump) );
	else
		size += AddByteToBuffer( Buffer, (UCHAR)(Jump - 0x02) );
	return size;
}

LONG Call( IN PCODE_BUFFER Buffer, IN PVOID CallAddress )
{
	LONG size = 0;
	if (Buffer->Is64Bit)
	{
		// mov rax, calladdress
		size += AddByteToBuffer( Buffer, 0x48 );// 14
		size += AddByteToBuffer( Buffer, 0xB8 );
		size += AddULong64ToBuffer( Buffer, (ULONG64)CallAddress );
		// call rax
		size += AddByteToBuffer( Buffer, 0xFF );
		size += AddByteToBuffer( Buffer, 0xD0 );
	}
	else
	{
		// mov eax, calladdress
		size += AddByteToBuffer( Buffer, 0xB8 );
		size += AddULongToBuffer( Buffer, (ULONG)(ULONG_PTR)CallAddress );
		// call calladdress
		size += AddByteToBuffer( Buffer, 0xFF );
		size += AddByteToBuffer( Buffer, 0xD0 );
	}

	return size;
}

LONG AddParameterToBuffer( IN PCODE_BUFFER Buffer, IN PPARAMETER_INFO Param )
{
	LONG size = 0;

	switch (Param->Type)
	{
	case PARAM_TYPE_DOUBLE:		// all the same 8 bytes
	case PARAM_TYPE_LONG64:		//
	{
		if (Buffer->Is64Bit)
		{
			// mov r13, ulParam
			size += AddByteToBuffer( Buffer, 0x49 );
			size += AddByteToBuffer( Buffer, 0xBD );
			size += AddULong64ToBuffer( Buffer, Param->Param64 );
			//push r13	
			size += AddByteToBuffer( Buffer, 0x41 );
			size += AddByteToBuffer( Buffer, 0x55 );
		}
		else // 32 bit
		{
			// ill do this later
			// push ulParam
			size += AddByteToBuffer( Buffer, 0x68 );
			size += AddULongToBuffer( Buffer, Param->Param32 );
		}
		break;
	}
	case PARAM_TYPE_UNICODE_STRING: // 8 or 4 bytes, depending on architecture
	case PARAM_TYPE_POINTER:	
	{
		if (Buffer->Is64Bit)
		{
			// mov r13, ptr		
			size += AddByteToBuffer( Buffer, 0x49 );
			size += AddByteToBuffer( Buffer, 0xBD );
			size += AddPointerToBuffer( Buffer, (PVOID)Param->Param64 );
			//push r13
			size += AddByteToBuffer( Buffer, 0x41 );
			size += AddByteToBuffer( Buffer, 0x55 );
		}
		else // 32 bit
		{
			// push ptr
			size += AddByteToBuffer( Buffer, 0x68 );
			size += AddPointerToBuffer( Buffer, (PVOID)Param->Param32 );
		}
		break;
	}
	case PARAM_TYPE_SHORT:		// (short is interpreted as 4 bytes in this case)
	case PARAM_TYPE_LONG:		// all the same shit 4 bytes 
	case PARAM_TYPE_FLOAT:		//
	{
		// push ulParam
		size += AddByteToBuffer( Buffer, 0x68 );
		size += AddULongToBuffer( Buffer, Param->Param32 );
		break;
	}
	case PARAM_TYPE_BYTE:
	{
		// push ucParam
		size += AddByteToBuffer( Buffer, 0x6A ); // 0x6A is for pushing bytes
		size += AddByteToBuffer( Buffer, (UCHAR)Param->Param32 );
		break;
	}
	case PARAM_TYPE_BOOL:
	{
		BOOLEAN ucParam = (Param->Param32) ? TRUE : FALSE;

		// push ucParam
		size += AddByteToBuffer( Buffer, 0x6A );
		size += AddByteToBuffer( Buffer, ucParam );
		break;
	}
	default: // Default to ULONG
	{
		// push Ulong
		size += AddByteToBuffer( Buffer, 0x68 );
		size += AddULongToBuffer( Buffer, Param->Param32 );
		break;
	}
	}

	return size;
}

LONG Parameter( IN PCODE_BUFFER Buffer, IN PPARAMETER_INFO Param )
{
	LONG size = 0;

	if (Buffer->Is64Bit)
	{
		switch (Buffer->ParamCount)
		{
		case PARAM_INDEX_RCX:
		{
			// mov	rcx, pparam
			size += AddByteToBuffer( Buffer, 0x48 );
			size += AddByteToBuffer( Buffer, 0xB9 );
			size += AddULong64ToBuffer( Buffer, Param->Param64 );
			break;
		}
		case PARAM_INDEX_RDX:
		{
			// mov  rdx, ulRdxParam
			size += AddByteToBuffer( Buffer, 0x48 );
			size += AddByteToBuffer( Buffer, 0xBA );
			size += AddULong64ToBuffer( Buffer, Param->Param64 );
			break;
		}
		case PARAM_INDEX_R8:
		{
			// mov  r8, ulR8Param
			size += AddByteToBuffer( Buffer, 0x49 );
			size += AddByteToBuffer( Buffer, 0xB8 );
			size += AddULong64ToBuffer( Buffer, Param->Param64 );
			break;
		}
		case PARAM_INDEX_R9:
		{
			// mov  r9, ulR9Param
			size += AddByteToBuffer( Buffer, 0x49 );
			size += AddByteToBuffer( Buffer, 0xB9 );
			size += AddULong64ToBuffer( Buffer, Param->Param64 );
			break;
		}
		default: // Push remainder of params onto stack
		{
			size += AddParameterToBuffer( Buffer, Param );
			break;
		}

		}
	}
	else
	{
		size += AddParameterToBuffer( Buffer, Param );
	}

	return size;
}

PPARAMETER_INFO AllocateParameter( VOID )
{
	PPARAMETER_INFO Param = ExAllocatePoolWithTag( PagedPool, sizeof(PARAMETER_INFO), PARAM_POOL_TAG );
	RtlZeroMemory( Param, sizeof( PARAMETER_INFO ) );
	return Param;
}

VOID FreeParameter( PPARAMETER_INFO Param )
{
	ExFreePoolWithTag( Param, PARAM_POOL_TAG );
}

VOID PushParameter( IN PCODE_BUFFER Buffer, IN PPARAMETER_INFO Param )
{
	Buffer->Params[Buffer->ParamCount] = Param;
	Buffer->ParamCount += 1;
}

VOID PushPointer( IN PCODE_BUFFER Buffer, IN PVOID Ptr )
{
	PPARAMETER_INFO Param = AllocateParameter( );
	Param->Type = PARAM_TYPE_POINTER;
	if (Buffer->Is64Bit)
		Param->Param64 = (ULONGLONG)Ptr;
	else
	{
		Param->HighBits = 0;
		Param->Param32 = (ULONG)Ptr;
	}
	PushParameter( Buffer, Param );
}

VOID PushLong( IN PCODE_BUFFER Buffer, IN LONG Long )
{
	PPARAMETER_INFO Param = AllocateParameter( );
	Param->Type = PARAM_TYPE_LONG;
	Param->Param32 = (LONG)Long;
	PushParameter( Buffer, Param );
}

VOID PushLong64( IN PCODE_BUFFER Buffer, IN LONGLONG Long64 )
{
	PPARAMETER_INFO Param = AllocateParameter( );
	Param->Type = PARAM_TYPE_LONG64;
	Param->Param64 = (LONGLONG)Long64;
	PushParameter( Buffer, Param );
}

VOID PushULong( IN PCODE_BUFFER Buffer, IN ULONG ULong )
{
	PPARAMETER_INFO Param = AllocateParameter( );
	Param->Type = PARAM_TYPE_LONG;
	Param->Param32 = (ULONG)ULong;
	PushParameter( Buffer, Param );
}

VOID PushULong64( IN PCODE_BUFFER Buffer, IN ULONGLONG ULong64 )
{
	PPARAMETER_INFO Param = AllocateParameter( );
	Param->Type = PARAM_TYPE_LONG64;
	Param->Param64 = (ULONGLONG)ULong64;
	PushParameter( Buffer, Param );
}

VOID PushByte( IN PCODE_BUFFER Buffer, IN UCHAR Byte )
{
	PPARAMETER_INFO Param = AllocateParameter( );
	Param->Type = PARAM_TYPE_BYTE;
	Param->Param32 = (UCHAR)Byte;
	PushParameter( Buffer, Param );
}

VOID PushBool( IN PCODE_BUFFER Buffer, IN BOOLEAN Bool )
{
	PPARAMETER_INFO Param = AllocateParameter( );
	Param->Type = PARAM_TYPE_BOOL;
	Param->Param32 = (UCHAR)(Bool != FALSE);
	PushParameter( Buffer, Param );
}

VOID PushUnicodeString( IN PCODE_BUFFER Buffer, IN PUNICODE_STRING UStr )
{
	PPARAMETER_INFO Param = AllocateParameter( );
	Param->Type = PARAM_TYPE_UNICODE_STRING;
	Param->Param64 = (ULONG_PTR)UStr;
	PushParameter( Buffer, Param );
}

VOID PushUnicodeString32( IN PCODE_BUFFER Buffer, IN PUNICODE_STRING32 UStr )
{
	PPARAMETER_INFO Param = AllocateParameter( );
	Param->Type = PARAM_TYPE_UNICODE_STRING;
	Param->Param32 = (ULONG)UStr;
	PushParameter( Buffer, Param );
}

LONG PushAllParameters( IN PCODE_BUFFER Buffer, IN BOOLEAN right_to_left )
{
	LONG size = 0;
	ULONG i = 0;
	ULONG ParamCount = Buffer->ParamCount;
	Buffer->ParamCount = 0;

	if (right_to_left == FALSE)
	{
		// left-to-right
		for (i = 0; i < ParamCount; i++)
		{
			PPARAMETER_INFO Param = Buffer->Params[i];
			if (Param)
			{
				size += Parameter( Buffer, Param );

				FreeParameter( Param );
				Buffer->Params[i - 1] = NULL;

				Buffer->ParamCount += 1;
			}
		}
	}
	else
	{
		// right-to-left
		for (i = ParamCount; i > 0; i--)
		{
			PPARAMETER_INFO Param = Buffer->Params[i - 1];
			if (Param)
			{
				size += Parameter( Buffer, Param );
				
				FreeParameter( Param );
				Buffer->Params[i - 1] = NULL;

				Buffer->ParamCount += 1;
			}
		}
	}
	return size;
}

LONG PushCall( IN PCODE_BUFFER Buffer, IN CALLING_CONVENTION cconv, IN PVOID CallAddress )
{
	LONG size = 0;

	if (Buffer->Is64Bit) // CCONV_FASTCALL but a little different
	{
		ULONG64 rsp_dif = 0x28;
		if (Buffer->ParamCount > 4)
			rsp_dif = (ULONG64)(Buffer->ParamCount * sizeof( ULONG64 ));
		rsp_dif = Align( rsp_dif, 0x10 ); // 16 byte aligned

		// sub rsp, rsp_dif
		size += AddByteToBuffer( Buffer, 0x48 );
		size += AddByteToBuffer( Buffer, 0x83 );
		size += AddByteToBuffer( Buffer, 0xEC );
		size += AddByteToBuffer( Buffer, (UCHAR)(rsp_dif + sizeof( ULONG64 )) );

		// Push all parameters (or store in rcx, rdx, r8, r9 in 64 bit)
		size += PushAllParameters( Buffer, FALSE );

		// mov r13, calladdress
		size += AddByteToBuffer( Buffer, 0x49 );
		size += AddByteToBuffer( Buffer, 0xBD );
		size += AddLong64ToBuffer( Buffer, (LONG64)CallAddress );
		// call r13
		size += AddByteToBuffer( Buffer, 0x41 );
		size += AddByteToBuffer( Buffer, 0xFF );
		size += AddByteToBuffer( Buffer, 0xD5 );

		// add rsp, (rsp_dif + 8)
		size += AddByteToBuffer( Buffer, 0x48 );
		size += AddByteToBuffer( Buffer, 0x83 );
		size += AddByteToBuffer( Buffer, 0xC4 );
		size += AddByteToBuffer( Buffer, (UCHAR)(rsp_dif + sizeof( ULONG64 )) );
	}
	else // 32 bit
	{
		if (cconv == CCONV_FASTCALL)
		{
			dbgprint( "Entering __fastcall\n" );

			// Is actually a stdcall
			if (Buffer->ParamCount == 0) 
			{
				size += PushCall( Buffer, CCONV_STDCALL, CallAddress );
				// Return here to make sure we dont clear data again
				return size;
			}
			else if (Buffer->ParamCount == 1) // Is actually a stdcall using EDX
			{
				PPARAMETER_INFO EdxParam = Buffer->Params[0];
				// mov edx, EdxParam
				AddByteToBuffer( Buffer, 0xBA );
				AddLongToBuffer( Buffer, EdxParam->Param32 );

				// erase EDX param
				FreeParameter( Buffer->Params[0] );
				Buffer->Params[0] = NULL;

				size += PushCall( Buffer, CCONV_STDCALL, CallAddress );
				// Return here to make sure we dont clear data again
				return size;
			}
			else // Fastcall only if more than one param
			{
				PPARAMETER_INFO EcxParam = Buffer->Params[0]; // ECX param
				PPARAMETER_INFO EdxParam = Buffer->Params[1]; // EDX param
				// mov ecx, ulEcxParam
				size += AddByteToBuffer( Buffer, 0xB9 );
				size += AddLongToBuffer( Buffer, EcxParam->Param32 );
				// mov edx, ulEdxParam
				size += AddByteToBuffer( Buffer, 0xBA );
				size += AddLongToBuffer( Buffer, EdxParam->Param32 );

				// erase ECX (first) param
				FreeParameter( Buffer->Params[0] );
				Buffer->Params[0] = NULL;
				// erase EDX (second) param
				FreeParameter( Buffer->Params[1] );
				Buffer->Params[1] = NULL;

				// Push the rest onto the stack right to left - fastcalls are weird.
				size += PushAllParameters( Buffer, TRUE );

				// mov ebx, calladdress
				size += AddByteToBuffer( Buffer, 0xBB );
				size += AddLongToBuffer( Buffer, (ULONG)CallAddress );
				// call ebx
				size += AddByteToBuffer( Buffer, 0xFF );
				size += AddByteToBuffer( Buffer, 0xD3 );
			}
		}
		else if (cconv == CCONV_CDECL)
		{
			dbgprint( "Entering __cdecl\n" );
			ULONG ulCalculateAddEsp = (Buffer->ParamCount * 4);

			size += PushAllParameters( Buffer, TRUE );
			// mov eax, calladdress
			size += AddByteToBuffer( Buffer, 0xB8 );
			size += AddLongToBuffer( Buffer, (ULONG)CallAddress );
			// call eax
			size += AddByteToBuffer( Buffer, 0xFF );
			size += AddByteToBuffer( Buffer, 0xD0 );

			if (ulCalculateAddEsp != 0)
			{
				BOOLEAN UseByte = ((ulCalculateAddEsp <= 0xFF /* 255 */) == TRUE);
				if (UseByte)
				{
					// add esp, (byte)ulCalculateAddEsp
					size += AddByteToBuffer( Buffer, 0x83 ); // 0x83 is for adding a byte value
					size += AddByteToBuffer( Buffer, 0xC4 );
					size += AddByteToBuffer( Buffer, (UCHAR)ulCalculateAddEsp );
				}
				else
				{
					// add esp, iCalculateAddEsp
					size += AddByteToBuffer( Buffer, 0x81 ); // 0x81 is for adding a long value
					size += AddByteToBuffer( Buffer, 0xC4 );
					size += AddULongToBuffer( Buffer, ulCalculateAddEsp );
				}
			}
		}
		else if (cconv == CCONV_STDCALL)
		{
			dbgprint( "Entering __stdcall" );

			size += PushAllParameters( Buffer, TRUE );
	
			// mov eax, calladdress
			size += AddByteToBuffer( Buffer, 0xB8 );
			size += AddLongToBuffer( Buffer, (ULONG)CallAddress );
			// call eax
			size += AddByteToBuffer( Buffer, 0xFF );
			size += AddByteToBuffer( Buffer, 0xD0 );
		}
		else if (cconv == CCONV_THISCALL)
		{
			dbgprint( "Entering __thiscall" );

			if (Buffer->ParamCount == 0)
			{	//no params...
				dbgprint( "No parameters passed for __thiscall, requires at least one parameter (ECX)" );
			}

			// first parameter of __thiscall is ALWAYS ECX. ALWAYS.
			// the parameter type should also be PARAM_TYPE_POINTER
			if (Buffer->Params[0]->Type != PARAM_TYPE_POINTER)
			{
				dbgprint( "Warning: \"THIS\" parameter type invalid [%i], should be PARAM_TYPE_POINTER", Buffer->Params[0]->Type );
			}

			if (!Buffer->Params[0]->Param32)
			{
				dbgprint( "Warning: \"THIS\" parameter NULL for __thiscall function (ECX)" );
			}

			// mov ecx, ptr
			size += AddByteToBuffer( Buffer, 0x8B );
			size += AddByteToBuffer( Buffer, 0x0D );
			size += AddLongToBuffer( Buffer, (ULONG)Buffer->Params[0]->Param32 );

			// now we need to remove the first parameter from the array, so when we execute the
			// parameter iteration function it is not included.
			Buffer->Params[0] = NULL;

			// Push remainder of params
			size += PushAllParameters( Buffer, TRUE );

			// mov eax, calladdress
			size += AddByteToBuffer( Buffer, 0xB8 );			
			size += AddLongToBuffer( Buffer, (ULONG)CallAddress );
			// call eax
			size += AddByteToBuffer( Buffer, 0xFF );
			size += AddByteToBuffer( Buffer, 0xD0 );
		}
	}

	// clear data
	for (ULONG i = 0; i < Buffer->ParamCount; i++)
	{
		if (Buffer->Params[i] != NULL)
		{
			FreeParameter( Buffer->Params[i] );
			Buffer->Params[i] = NULL;
		}
	}

	return size;
}

LONG AddByteToBuffer( IN PCODE_BUFFER Buffer, IN UCHAR Byte )
{
	*(PUCHAR)(Buffer->Code + Buffer->CurrentIndex) = Byte;
	Buffer->CurrentIndex += 1;
	return sizeof( UCHAR );
}

LONG AddLongToBuffer( IN PCODE_BUFFER Buffer, IN LONG Long )
{
	*(PLONG)(Buffer->Code + Buffer->CurrentIndex) = Long;
	Buffer->CurrentIndex += sizeof( LONG );
	return sizeof( LONG );

}

LONG AddLong64ToBuffer( IN PCODE_BUFFER Buffer, IN LONG64 Long64 )
{
	LONG size = 0;
	LONG lowLong32	= (LONG)(Long64 & 0xffffffff);
	LONG highLong32	= (LONG)(Long64 >> 32);

	size += AddLongToBuffer( Buffer, lowLong32 );
	size += AddLongToBuffer( Buffer, highLong32 );

	return size;
}

LONG AddULongToBuffer( IN PCODE_BUFFER Buffer, IN ULONG ULong )
{
	*(PULONG)(Buffer->Code + Buffer->CurrentIndex) = ULong;
	Buffer->CurrentIndex += sizeof( ULONG );
	return sizeof( ULONG );
}

LONG AddULong64ToBuffer( IN PCODE_BUFFER Buffer, IN ULONG64 ULong64 )
{
	LONG size = 0;
	ULONG lowULong32 = (ULONG)(ULong64 & 0xffffffff);
	ULONG highULong32 = (ULONG)(ULong64 >> 32);

	size += AddULongToBuffer( Buffer, lowULong32 );
	size += AddULongToBuffer( Buffer, highULong32 );

	return size;
}

LONG AddPointerToBuffer( IN PCODE_BUFFER Buffer, IN PVOID Ptr )
{
	if (Buffer->Is64Bit)
		return AddULong64ToBuffer( Buffer, (ULONGLONG)Ptr );
	return AddULongToBuffer( Buffer, (ULONG)Ptr );
}

LONG BeginCall64( IN PCODE_BUFFER Buffer )
{
	// Backup registers on stack
	LONG size = 0;
	// mov QWORD PTR [rsp+0x8], rcx
	size += AddByteToBuffer( Buffer, 0x48 );
	size += AddByteToBuffer( Buffer, 0x89 );
	size += AddByteToBuffer( Buffer, 0x4C );
	size += AddByteToBuffer( Buffer, 0x24 );
	size += AddByteToBuffer( Buffer, 1 * sizeof( ULONG_PTR ) );
	// mov QWORD PTR [rsp+0x10], rdx
	size += AddByteToBuffer( Buffer, 0x48 );
	size += AddByteToBuffer( Buffer, 0x89 );
	size += AddByteToBuffer( Buffer, 0x54 );
	size += AddByteToBuffer( Buffer, 0x24 );
	size += AddByteToBuffer( Buffer, 2 * sizeof( ULONG_PTR ) );
	// mov QWORD PTR [rsp+0x18], r8
	size += AddByteToBuffer( Buffer, 0x4C );
	size += AddByteToBuffer( Buffer, 0x89 );
	size += AddByteToBuffer( Buffer, 0x44 );
	size += AddByteToBuffer( Buffer, 0x24 );
	size += AddByteToBuffer( Buffer, 3 * sizeof( ULONG_PTR ) );
	// mov QWORD PTR [rsp+0x20], r9
	size += AddByteToBuffer( Buffer, 0x4C );
	size += AddByteToBuffer( Buffer, 0x89 );
	size += AddByteToBuffer( Buffer, 0x4C );
	size += AddByteToBuffer( Buffer, 0x24 );
	size += AddByteToBuffer( Buffer, 4 * sizeof( ULONG_PTR ) );
	return size;
}

LONG EndCall64( IN PCODE_BUFFER Buffer )
{
	// Restore registers and return
	LONG size = 0;
	// mov	rcx,QWORD PTR [rsp+0x8]
	size += AddByteToBuffer( Buffer, 0x48 );
	size += AddByteToBuffer( Buffer, 0x8B );
	size += AddByteToBuffer( Buffer, 0x4C );
	size += AddByteToBuffer( Buffer, 0x24 );
	size += AddByteToBuffer( Buffer, 1 * sizeof( size_t ) );
	// mov	rdx,QWORD PTR [rsp+0x10]
	size += AddByteToBuffer( Buffer, 0x48 );
	size += AddByteToBuffer( Buffer, 0x8B );
	size += AddByteToBuffer( Buffer, 0x54 );
	size += AddByteToBuffer( Buffer, 0x24 );
	size += AddByteToBuffer( Buffer, 2 * sizeof( size_t ) );
	// mov	r8,QWORD PTR [rsp+0x18]
	size += AddByteToBuffer( Buffer, 0x4C );
	size += AddByteToBuffer( Buffer, 0x8B );
	size += AddByteToBuffer( Buffer, 0x44 );
	size += AddByteToBuffer( Buffer, 0x24 );
	size += AddByteToBuffer( Buffer, 3 * sizeof( size_t ) );
	// mov	r9,QWORD PTR [rsp+0x20]
	size += AddByteToBuffer( Buffer, 0x4C );
	size += AddByteToBuffer( Buffer, 0x8B );
	size += AddByteToBuffer( Buffer, 0x4C );
	size += AddByteToBuffer( Buffer, 0x24 );
	size += AddByteToBuffer( Buffer, 4 * sizeof( size_t ) );
	// ret
	size += AddByteToBuffer( Buffer, 0xC3 );
	return size;
}

LONG BeginCall32( IN PCODE_BUFFER Buffer )
{
	UNREFERENCED_PARAMETER( Buffer );

	return 0;
}

LONG EndCall32( IN PCODE_BUFFER Buffer, IN LONG RetSize )
{
	UNREFERENCED_PARAMETER( Buffer );
	UNREFERENCED_PARAMETER( RetSize );

	return 0;
}

#pragma warning(default : 4311 4302)
