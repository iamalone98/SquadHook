#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapWidgetMapMarkerObjective

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass BP_MapWidgetMapMarkerObjective.BP_MapWidgetMapMarkerObjective_C
// 0x0018 (0x0310 - 0x02F8)
class UBP_MapWidgetMapMarkerObjective_C final : public USQMapWidgetMapMarkerObjective
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02F8(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 MarkerImage;                                       // 0x0300(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              ScaleBox_0;                                        // 0x0308(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_MapWidgetMapMarkerObjective(int32 EntryPoint);
	void OnScaleChanged(float UniformScale);
	void OnTintChanged();
	void OnTextureChanged();
	void Construct();
	void Get_Owning_Player_Map_Widget(class USQMapWidgetSoldier** Local_Player_Soldier_Widget);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_MapWidgetMapMarkerObjective_C">();
	}
	static class UBP_MapWidgetMapMarkerObjective_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_MapWidgetMapMarkerObjective_C>();
	}
};
static_assert(alignof(UBP_MapWidgetMapMarkerObjective_C) == 0x000008, "Wrong alignment on UBP_MapWidgetMapMarkerObjective_C");
static_assert(sizeof(UBP_MapWidgetMapMarkerObjective_C) == 0x000310, "Wrong size on UBP_MapWidgetMapMarkerObjective_C");
static_assert(offsetof(UBP_MapWidgetMapMarkerObjective_C, UberGraphFrame) == 0x0002F8, "Member 'UBP_MapWidgetMapMarkerObjective_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetMapMarkerObjective_C, MarkerImage) == 0x000300, "Member 'UBP_MapWidgetMapMarkerObjective_C::MarkerImage' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetMapMarkerObjective_C, ScaleBox_0) == 0x000308, "Member 'UBP_MapWidgetMapMarkerObjective_C::ScaleBox_0' has a wrong offset!");

}

