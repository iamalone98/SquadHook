#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SQ_MouseCursor

#include "Basic.hpp"

#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass SQ_MouseCursor.SQ_MouseCursor_C
// 0x0000 (0x0260 - 0x0260)
class USQ_MouseCursor_C final : public UUserWidget
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"SQ_MouseCursor_C">();
	}
	static class USQ_MouseCursor_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<USQ_MouseCursor_C>();
	}
};
static_assert(alignof(USQ_MouseCursor_C) == 0x000008, "Wrong alignment on USQ_MouseCursor_C");
static_assert(sizeof(USQ_MouseCursor_C) == 0x000260, "Wrong size on USQ_MouseCursor_C");

}

