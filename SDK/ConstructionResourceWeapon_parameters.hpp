#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: ConstructionResourceWeapon

#include "Basic.hpp"


namespace SDK::Params
{

// Function ConstructionResourceWeapon.ConstructionResourceWeapon_C.ExecuteUbergraph_ConstructionResourceWeapon
// 0x0010 (0x0010 - 0x0000)
struct ConstructionResourceWeapon_C_ExecuteUbergraph_ConstructionResourceWeapon final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4E44[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UAudioComponent*                        CallFunc_SpawnSound2D_ReturnValue;                 // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(ConstructionResourceWeapon_C_ExecuteUbergraph_ConstructionResourceWeapon) == 0x000008, "Wrong alignment on ConstructionResourceWeapon_C_ExecuteUbergraph_ConstructionResourceWeapon");
static_assert(sizeof(ConstructionResourceWeapon_C_ExecuteUbergraph_ConstructionResourceWeapon) == 0x000010, "Wrong size on ConstructionResourceWeapon_C_ExecuteUbergraph_ConstructionResourceWeapon");
static_assert(offsetof(ConstructionResourceWeapon_C_ExecuteUbergraph_ConstructionResourceWeapon, EntryPoint) == 0x000000, "Member 'ConstructionResourceWeapon_C_ExecuteUbergraph_ConstructionResourceWeapon::EntryPoint' has a wrong offset!");
static_assert(offsetof(ConstructionResourceWeapon_C_ExecuteUbergraph_ConstructionResourceWeapon, CallFunc_SpawnSound2D_ReturnValue) == 0x000008, "Member 'ConstructionResourceWeapon_C_ExecuteUbergraph_ConstructionResourceWeapon::CallFunc_SpawnSound2D_ReturnValue' has a wrong offset!");

}
