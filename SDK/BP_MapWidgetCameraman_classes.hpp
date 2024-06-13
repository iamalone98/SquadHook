#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapWidgetCameraman

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass BP_MapWidgetCameraman.BP_MapWidgetCameraman_C
// 0x0028 (0x0310 - 0x02E8)
class UBP_MapWidgetCameraman_C final : public USQMapWidgetCameraman
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02E8(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 Player_Cone_Image;                                 // 0x02F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Player_Image;                                      // 0x02F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              ScaleBox_0;                                        // 0x0300(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               WidgetOverlay;                                     // 0x0308(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_MapWidgetCameraman(int32 EntryPoint);
	void OnScaleChanged(float UniformScale);
	void OnTintValueChanged();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_MapWidgetCameraman_C">();
	}
	static class UBP_MapWidgetCameraman_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_MapWidgetCameraman_C>();
	}
};
static_assert(alignof(UBP_MapWidgetCameraman_C) == 0x000008, "Wrong alignment on UBP_MapWidgetCameraman_C");
static_assert(sizeof(UBP_MapWidgetCameraman_C) == 0x000310, "Wrong size on UBP_MapWidgetCameraman_C");
static_assert(offsetof(UBP_MapWidgetCameraman_C, UberGraphFrame) == 0x0002E8, "Member 'UBP_MapWidgetCameraman_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetCameraman_C, Player_Cone_Image) == 0x0002F0, "Member 'UBP_MapWidgetCameraman_C::Player_Cone_Image' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetCameraman_C, Player_Image) == 0x0002F8, "Member 'UBP_MapWidgetCameraman_C::Player_Image' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetCameraman_C, ScaleBox_0) == 0x000300, "Member 'UBP_MapWidgetCameraman_C::ScaleBox_0' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetCameraman_C, WidgetOverlay) == 0x000308, "Member 'UBP_MapWidgetCameraman_C::WidgetOverlay' has a wrong offset!");

}

