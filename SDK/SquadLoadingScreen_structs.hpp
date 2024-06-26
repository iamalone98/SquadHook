#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SquadLoadingScreen

#include "Basic.hpp"

#include "Engine_structs.hpp"


namespace SDK
{

// ScriptStruct SquadLoadingScreen.SquadTip
// 0x0018 (0x0020 - 0x0008)
struct FSquadTip final : public FTableRowBase
{
public:
	class FText                                   TipText;                                           // 0x0008(0x0018)(Edit, NativeAccessSpecifierPublic)
};
static_assert(alignof(FSquadTip) == 0x000008, "Wrong alignment on FSquadTip");
static_assert(sizeof(FSquadTip) == 0x000020, "Wrong size on FSquadTip");
static_assert(offsetof(FSquadTip, TipText) == 0x000008, "Member 'FSquadTip::TipText' has a wrong offset!");

}

