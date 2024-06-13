#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: WBP_SetHeliLockFreeLook

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass WBP_SetHeliLockFreeLook.WBP_SetHeliLockFreeLook_C
// 0x0010 (0x0270 - 0x0260)
class UWBP_SetHeliLockFreeLook_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UCheckBox*                              AlwaysFreeLookBox;                                 // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_WBP_SetHeliLockFreeLook(int32 EntryPoint);
	void BndEvt__AlwaysFreeLookBox_K2Node_ComponentBoundEvent_0_OnCheckBoxComponentStateChanged__DelegateSignature(bool bIsChecked);
	void Construct();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"WBP_SetHeliLockFreeLook_C">();
	}
	static class UWBP_SetHeliLockFreeLook_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UWBP_SetHeliLockFreeLook_C>();
	}
};
static_assert(alignof(UWBP_SetHeliLockFreeLook_C) == 0x000008, "Wrong alignment on UWBP_SetHeliLockFreeLook_C");
static_assert(sizeof(UWBP_SetHeliLockFreeLook_C) == 0x000270, "Wrong size on UWBP_SetHeliLockFreeLook_C");
static_assert(offsetof(UWBP_SetHeliLockFreeLook_C, UberGraphFrame) == 0x000260, "Member 'UWBP_SetHeliLockFreeLook_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UWBP_SetHeliLockFreeLook_C, AlwaysFreeLookBox) == 0x000268, "Member 'UWBP_SetHeliLockFreeLook_C::AlwaysFreeLookBox' has a wrong offset!");

}

