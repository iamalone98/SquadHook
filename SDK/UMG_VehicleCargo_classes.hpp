#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_VehicleCargo

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_VehicleCargo.UMG_VehicleCargo_C
// 0x0090 (0x02F0 - 0x0260)
class UUMG_VehicleCargo_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 AmmoAmount;                                        // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 ConstructionAmount;                                // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 EmptyAmount;                                       // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         H_Ammo;                                            // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         H_Construction;                                    // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_0;                                           // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_1;                                           // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               SizeBox_Parent;                                    // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_AmmoAmount;                                     // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_ConstructionAmount;                             // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Max;                                            // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             WeaponName;                                        // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	float                                         Ammo;                                              // 0x02C8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Construction;                                      // 0x02CC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Total_Points;                                      // 0x02D0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Has_Ammo_Weapon;                                   // 0x02D4(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Has_Construction_Weapon;                           // 0x02D5(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_35FC[0x2];                                     // 0x02D6(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    My_PC;                                             // 0x02D8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQVehicleSeatComponent*                Current_Seat;                                      // 0x02E0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQVehicleResourceWeaponInventoryComponent* VehicleResourceInventory;                          // 0x02E8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_UMG_VehicleCargo(int32 EntryPoint);
	void Destruct();
	void Construct();
	void Refresh_Info();
	void Set_Name();
	void SetupUI(class ASQVehicle* VehicleRef);
	void DisableUI();
	void ValueSizeBox(float InPoints, float* Size);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_VehicleCargo_C">();
	}
	static class UUMG_VehicleCargo_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_VehicleCargo_C>();
	}
};
static_assert(alignof(UUMG_VehicleCargo_C) == 0x000008, "Wrong alignment on UUMG_VehicleCargo_C");
static_assert(sizeof(UUMG_VehicleCargo_C) == 0x0002F0, "Wrong size on UUMG_VehicleCargo_C");
static_assert(offsetof(UUMG_VehicleCargo_C, UberGraphFrame) == 0x000260, "Member 'UUMG_VehicleCargo_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, AmmoAmount) == 0x000268, "Member 'UUMG_VehicleCargo_C::AmmoAmount' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, ConstructionAmount) == 0x000270, "Member 'UUMG_VehicleCargo_C::ConstructionAmount' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, EmptyAmount) == 0x000278, "Member 'UUMG_VehicleCargo_C::EmptyAmount' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, H_Ammo) == 0x000280, "Member 'UUMG_VehicleCargo_C::H_Ammo' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, H_Construction) == 0x000288, "Member 'UUMG_VehicleCargo_C::H_Construction' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, Image_0) == 0x000290, "Member 'UUMG_VehicleCargo_C::Image_0' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, Image_1) == 0x000298, "Member 'UUMG_VehicleCargo_C::Image_1' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, SizeBox_Parent) == 0x0002A0, "Member 'UUMG_VehicleCargo_C::SizeBox_Parent' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, TB_AmmoAmount) == 0x0002A8, "Member 'UUMG_VehicleCargo_C::TB_AmmoAmount' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, TB_ConstructionAmount) == 0x0002B0, "Member 'UUMG_VehicleCargo_C::TB_ConstructionAmount' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, TB_Max) == 0x0002B8, "Member 'UUMG_VehicleCargo_C::TB_Max' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, WeaponName) == 0x0002C0, "Member 'UUMG_VehicleCargo_C::WeaponName' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, Ammo) == 0x0002C8, "Member 'UUMG_VehicleCargo_C::Ammo' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, Construction) == 0x0002CC, "Member 'UUMG_VehicleCargo_C::Construction' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, Total_Points) == 0x0002D0, "Member 'UUMG_VehicleCargo_C::Total_Points' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, Has_Ammo_Weapon) == 0x0002D4, "Member 'UUMG_VehicleCargo_C::Has_Ammo_Weapon' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, Has_Construction_Weapon) == 0x0002D5, "Member 'UUMG_VehicleCargo_C::Has_Construction_Weapon' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, My_PC) == 0x0002D8, "Member 'UUMG_VehicleCargo_C::My_PC' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, Current_Seat) == 0x0002E0, "Member 'UUMG_VehicleCargo_C::Current_Seat' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleCargo_C, VehicleResourceInventory) == 0x0002E8, "Member 'UUMG_VehicleCargo_C::VehicleResourceInventory' has a wrong offset!");

}

