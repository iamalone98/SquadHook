#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: DrawChatWidget

#include "Basic.hpp"

#include "UMG_structs.hpp"


namespace SDK::Params
{

// Function DrawChatWidget.DrawChatWidget_C.OnPaint
// 0x0030 (0x0030 - 0x0000)
struct DrawChatWidget_C_OnPaint final
{
public:
	struct FPaintContext                          Context;                                           // 0x0000(0x0030)(BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, NoDestructor)
};
static_assert(alignof(DrawChatWidget_C_OnPaint) == 0x000008, "Wrong alignment on DrawChatWidget_C_OnPaint");
static_assert(sizeof(DrawChatWidget_C_OnPaint) == 0x000030, "Wrong size on DrawChatWidget_C_OnPaint");
static_assert(offsetof(DrawChatWidget_C_OnPaint, Context) == 0x000000, "Member 'DrawChatWidget_C_OnPaint::Context' has a wrong offset!");

}
