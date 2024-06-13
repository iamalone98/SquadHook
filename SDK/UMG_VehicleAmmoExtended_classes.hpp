#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_VehicleAmmoExtended

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_VehicleAmmoExtended.UMG_VehicleAmmoExtended_C
// 0x0068 (0x02C8 - 0x0260)
class UUMG_VehicleAmmoExtended_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 AmmoAmount;                                        // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         AmmoParent;                                        // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 ConstructionAmount;                                // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         ConstructionParent;                                // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 EmptyAmount;                                       // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         Fill_HorizontalBox;                                // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_0;                                           // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_1;                                           // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               SizeBoxParent;                                     // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_AmmoAmount;                                     // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_ConstructionCount;                              // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Max;                                            // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_UMG_VehicleAmmoExtended(int32 EntryPoint);
	void Construct();
	void UpdateWidget();
	void ValueSizeBox(float InPoints, float TotalPoints, float* Size);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_VehicleAmmoExtended_C">();
	}
	static class UUMG_VehicleAmmoExtended_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_VehicleAmmoExtended_C>();
	}
};
static_assert(alignof(UUMG_VehicleAmmoExtended_C) == 0x000008, "Wrong alignment on UUMG_VehicleAmmoExtended_C");
static_assert(sizeof(UUMG_VehicleAmmoExtended_C) == 0x0002C8, "Wrong size on UUMG_VehicleAmmoExtended_C");
static_assert(offsetof(UUMG_VehicleAmmoExtended_C, UberGraphFrame) == 0x000260, "Member 'UUMG_VehicleAmmoExtended_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleAmmoExtended_C, AmmoAmount) == 0x000268, "Member 'UUMG_VehicleAmmoExtended_C::AmmoAmount' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleAmmoExtended_C, AmmoParent) == 0x000270, "Member 'UUMG_VehicleAmmoExtended_C::AmmoParent' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleAmmoExtended_C, ConstructionAmount) == 0x000278, "Member 'UUMG_VehicleAmmoExtended_C::ConstructionAmount' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleAmmoExtended_C, ConstructionParent) == 0x000280, "Member 'UUMG_VehicleAmmoExtended_C::ConstructionParent' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleAmmoExtended_C, EmptyAmount) == 0x000288, "Member 'UUMG_VehicleAmmoExtended_C::EmptyAmount' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleAmmoExtended_C, Fill_HorizontalBox) == 0x000290, "Member 'UUMG_VehicleAmmoExtended_C::Fill_HorizontalBox' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleAmmoExtended_C, Image_0) == 0x000298, "Member 'UUMG_VehicleAmmoExtended_C::Image_0' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleAmmoExtended_C, Image_1) == 0x0002A0, "Member 'UUMG_VehicleAmmoExtended_C::Image_1' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleAmmoExtended_C, SizeBoxParent) == 0x0002A8, "Member 'UUMG_VehicleAmmoExtended_C::SizeBoxParent' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleAmmoExtended_C, TB_AmmoAmount) == 0x0002B0, "Member 'UUMG_VehicleAmmoExtended_C::TB_AmmoAmount' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleAmmoExtended_C, TB_ConstructionCount) == 0x0002B8, "Member 'UUMG_VehicleAmmoExtended_C::TB_ConstructionCount' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleAmmoExtended_C, TB_Max) == 0x0002C0, "Member 'UUMG_VehicleAmmoExtended_C::TB_Max' has a wrong offset!");

}

