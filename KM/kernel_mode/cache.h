namespace cache
{
	inline uintptr_t qword_address = NULL;
	inline __int64( __fastcall* o_hook )(void*) = nullptr;

	__int64 __fastcall f_hook( void* a1 );
}