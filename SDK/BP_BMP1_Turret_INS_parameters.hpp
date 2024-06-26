#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BMP1_Turret_INS

#include "Basic.hpp"


namespace SDK::Params
{

// Function BP_BMP1_Turret_INS.BP_BMP1_Turret_INS_C.ExecuteUbergraph_BP_BMP1_Turret_INS
// 0x0040 (0x0040 - 0x0000)
struct BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0004(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_3677[0x4];                                     // 0x0014(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQEquipableItem*                       CallFunc_FindValidWeaponByClass_ReturnValue;       // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_1;            // 0x0020(0x0010)(ZeroConstructor, NoDestructor)
	class ABP_BMP1_AT3_C*                         K2Node_DynamicCast_AsBP_BMP1_AT3;                  // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0039(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS) == 0x000008, "Wrong alignment on BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS");
static_assert(sizeof(BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS) == 0x000040, "Wrong size on BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS");
static_assert(offsetof(BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS, EntryPoint) == 0x000000, "Member 'BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS, K2Node_CreateDelegate_OutputDelegate) == 0x000004, "Member 'BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS, CallFunc_FindValidWeaponByClass_ReturnValue) == 0x000018, "Member 'BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS::CallFunc_FindValidWeaponByClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS, K2Node_CreateDelegate_OutputDelegate_1) == 0x000020, "Member 'BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS, K2Node_DynamicCast_AsBP_BMP1_AT3) == 0x000030, "Member 'BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS::K2Node_DynamicCast_AsBP_BMP1_AT3' has a wrong offset!");
static_assert(offsetof(BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS, K2Node_DynamicCast_bSuccess) == 0x000038, "Member 'BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS, CallFunc_IsValid_ReturnValue) == 0x000039, "Member 'BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS::CallFunc_IsValid_ReturnValue' has a wrong offset!");

// Function BP_BMP1_Turret_INS.BP_BMP1_Turret_INS_C.GetADSCameraLocationComponent
// 0x0018 (0x0018 - 0x0000)
struct BP_BMP1_Turret_INS_C_GetADSCameraLocationComponent final
{
public:
	class USceneComponent*                        ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0008(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsActive_ReturnValue;                     // 0x0009(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3678[0x6];                                     // 0x000A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UCameraComponent*                       K2Node_Select_Default;                             // 0x0010(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BMP1_Turret_INS_C_GetADSCameraLocationComponent) == 0x000008, "Wrong alignment on BP_BMP1_Turret_INS_C_GetADSCameraLocationComponent");
static_assert(sizeof(BP_BMP1_Turret_INS_C_GetADSCameraLocationComponent) == 0x000018, "Wrong size on BP_BMP1_Turret_INS_C_GetADSCameraLocationComponent");
static_assert(offsetof(BP_BMP1_Turret_INS_C_GetADSCameraLocationComponent, ReturnValue) == 0x000000, "Member 'BP_BMP1_Turret_INS_C_GetADSCameraLocationComponent::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_Turret_INS_C_GetADSCameraLocationComponent, Temp_bool_Variable) == 0x000008, "Member 'BP_BMP1_Turret_INS_C_GetADSCameraLocationComponent::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(BP_BMP1_Turret_INS_C_GetADSCameraLocationComponent, CallFunc_IsActive_ReturnValue) == 0x000009, "Member 'BP_BMP1_Turret_INS_C_GetADSCameraLocationComponent::CallFunc_IsActive_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_Turret_INS_C_GetADSCameraLocationComponent, K2Node_Select_Default) == 0x000010, "Member 'BP_BMP1_Turret_INS_C_GetADSCameraLocationComponent::K2Node_Select_Default' has a wrong offset!");

}

