#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_NameTagFTL

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_NameTag_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_NameTagFTL.UMG_NameTagFTL_C
// 0x0008 (0x03B8 - 0x03B0)
class UUMG_NameTagFTL_C final : public UUMG_NameTag_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_UMG_NameTagFTL_C;                   // 0x03B0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_UMG_NameTagFTL(int32 EntryPoint);
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void Construct();
	void Refresh_Tag();
	void Find_Target();
	void FindBestTarget();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_NameTagFTL_C">();
	}
	static class UUMG_NameTagFTL_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_NameTagFTL_C>();
	}
};
static_assert(alignof(UUMG_NameTagFTL_C) == 0x000008, "Wrong alignment on UUMG_NameTagFTL_C");
static_assert(sizeof(UUMG_NameTagFTL_C) == 0x0003B8, "Wrong size on UUMG_NameTagFTL_C");
static_assert(offsetof(UUMG_NameTagFTL_C, UberGraphFrame_UMG_NameTagFTL_C) == 0x0003B0, "Member 'UUMG_NameTagFTL_C::UberGraphFrame_UMG_NameTagFTL_C' has a wrong offset!");

}
