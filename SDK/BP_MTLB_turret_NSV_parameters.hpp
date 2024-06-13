#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MTLB_turret_NSV

#include "Basic.hpp"

#include "InputCore_structs.hpp"


namespace SDK::Params
{

// Function BP_MTLB_turret_NSV.BP_MTLB_turret_NSV_C.ExecuteUbergraph_BP_MTLB_turret_NSV
// 0x0080 (0x0080 - 0x0000)
struct BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4EA4[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FKey                                   K2Node_InputActionEvent_Key_1;                     // 0x0008(0x0018)(HasGetValueTypeHash)
	struct FKey                                   K2Node_InputActionEvent_Key;                       // 0x0020(0x0018)(HasGetValueTypeHash)
	struct FKey                                   Temp_struct_Variable;                              // 0x0038(0x0018)(HasGetValueTypeHash)
	class USQVehicleInventoryComponent*           CallFunc_GetVehicleInventory_ReturnValue;          // 0x0050(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQGameUserSettings*                    CallFunc_GetSquadGameUserSettings_ReturnValue;     // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQGameUserSettings*                    CallFunc_GetSquadGameUserSettings_ReturnValue_1;   // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Array_Get_Item;                           // 0x0068(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x006C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Array_Get_Item_1;                         // 0x0070(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue_1;          // 0x0074(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Lerp_ReturnValue;                         // 0x0078(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV) == 0x000008, "Wrong alignment on BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV");
static_assert(sizeof(BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV) == 0x000080, "Wrong size on BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV");
static_assert(offsetof(BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV, EntryPoint) == 0x000000, "Member 'BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV, K2Node_InputActionEvent_Key_1) == 0x000008, "Member 'BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV::K2Node_InputActionEvent_Key_1' has a wrong offset!");
static_assert(offsetof(BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV, K2Node_InputActionEvent_Key) == 0x000020, "Member 'BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV::K2Node_InputActionEvent_Key' has a wrong offset!");
static_assert(offsetof(BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV, Temp_struct_Variable) == 0x000038, "Member 'BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV::Temp_struct_Variable' has a wrong offset!");
static_assert(offsetof(BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV, CallFunc_GetVehicleInventory_ReturnValue) == 0x000050, "Member 'BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV::CallFunc_GetVehicleInventory_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV, CallFunc_GetSquadGameUserSettings_ReturnValue) == 0x000058, "Member 'BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV::CallFunc_GetSquadGameUserSettings_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV, CallFunc_GetSquadGameUserSettings_ReturnValue_1) == 0x000060, "Member 'BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV::CallFunc_GetSquadGameUserSettings_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV, CallFunc_Array_Get_Item) == 0x000068, "Member 'BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV, CallFunc_Divide_FloatFloat_ReturnValue) == 0x00006C, "Member 'BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV, CallFunc_Array_Get_Item_1) == 0x000070, "Member 'BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV::CallFunc_Array_Get_Item_1' has a wrong offset!");
static_assert(offsetof(BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV, CallFunc_Divide_FloatFloat_ReturnValue_1) == 0x000074, "Member 'BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV::CallFunc_Divide_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV, CallFunc_Lerp_ReturnValue) == 0x000078, "Member 'BP_MTLB_turret_NSV_C_ExecuteUbergraph_BP_MTLB_turret_NSV::CallFunc_Lerp_ReturnValue' has a wrong offset!");

// Function BP_MTLB_turret_NSV.BP_MTLB_turret_NSV_C.InpActEvt_Fire_K2Node_InputActionEvent_0
// 0x0018 (0x0018 - 0x0000)
struct BP_MTLB_turret_NSV_C_InpActEvt_Fire_K2Node_InputActionEvent_0 final
{
public:
	struct FKey                                   Key;                                               // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
};
static_assert(alignof(BP_MTLB_turret_NSV_C_InpActEvt_Fire_K2Node_InputActionEvent_0) == 0x000008, "Wrong alignment on BP_MTLB_turret_NSV_C_InpActEvt_Fire_K2Node_InputActionEvent_0");
static_assert(sizeof(BP_MTLB_turret_NSV_C_InpActEvt_Fire_K2Node_InputActionEvent_0) == 0x000018, "Wrong size on BP_MTLB_turret_NSV_C_InpActEvt_Fire_K2Node_InputActionEvent_0");
static_assert(offsetof(BP_MTLB_turret_NSV_C_InpActEvt_Fire_K2Node_InputActionEvent_0, Key) == 0x000000, "Member 'BP_MTLB_turret_NSV_C_InpActEvt_Fire_K2Node_InputActionEvent_0::Key' has a wrong offset!");

// Function BP_MTLB_turret_NSV.BP_MTLB_turret_NSV_C.InpActEvt_Fire_K2Node_InputActionEvent_1
// 0x0018 (0x0018 - 0x0000)
struct BP_MTLB_turret_NSV_C_InpActEvt_Fire_K2Node_InputActionEvent_1 final
{
public:
	struct FKey                                   Key;                                               // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
};
static_assert(alignof(BP_MTLB_turret_NSV_C_InpActEvt_Fire_K2Node_InputActionEvent_1) == 0x000008, "Wrong alignment on BP_MTLB_turret_NSV_C_InpActEvt_Fire_K2Node_InputActionEvent_1");
static_assert(sizeof(BP_MTLB_turret_NSV_C_InpActEvt_Fire_K2Node_InputActionEvent_1) == 0x000018, "Wrong size on BP_MTLB_turret_NSV_C_InpActEvt_Fire_K2Node_InputActionEvent_1");
static_assert(offsetof(BP_MTLB_turret_NSV_C_InpActEvt_Fire_K2Node_InputActionEvent_1, Key) == 0x000000, "Member 'BP_MTLB_turret_NSV_C_InpActEvt_Fire_K2Node_InputActionEvent_1::Key' has a wrong offset!");

// Function BP_MTLB_turret_NSV.BP_MTLB_turret_NSV_C.Get3PAttachComponent
// 0x0008 (0x0008 - 0x0000)
struct BP_MTLB_turret_NSV_C_Get3PAttachComponent final
{
public:
	class USceneComponent*                        ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MTLB_turret_NSV_C_Get3PAttachComponent) == 0x000008, "Wrong alignment on BP_MTLB_turret_NSV_C_Get3PAttachComponent");
static_assert(sizeof(BP_MTLB_turret_NSV_C_Get3PAttachComponent) == 0x000008, "Wrong size on BP_MTLB_turret_NSV_C_Get3PAttachComponent");
static_assert(offsetof(BP_MTLB_turret_NSV_C_Get3PAttachComponent, ReturnValue) == 0x000000, "Member 'BP_MTLB_turret_NSV_C_Get3PAttachComponent::ReturnValue' has a wrong offset!");

// Function BP_MTLB_turret_NSV.BP_MTLB_turret_NSV_C.Get1PAttachComponent
// 0x0008 (0x0008 - 0x0000)
struct BP_MTLB_turret_NSV_C_Get1PAttachComponent final
{
public:
	class USceneComponent*                        ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MTLB_turret_NSV_C_Get1PAttachComponent) == 0x000008, "Wrong alignment on BP_MTLB_turret_NSV_C_Get1PAttachComponent");
static_assert(sizeof(BP_MTLB_turret_NSV_C_Get1PAttachComponent) == 0x000008, "Wrong size on BP_MTLB_turret_NSV_C_Get1PAttachComponent");
static_assert(offsetof(BP_MTLB_turret_NSV_C_Get1PAttachComponent, ReturnValue) == 0x000000, "Member 'BP_MTLB_turret_NSV_C_Get1PAttachComponent::ReturnValue' has a wrong offset!");

// Function BP_MTLB_turret_NSV.BP_MTLB_turret_NSV_C.GetMasterPoseComponent
// 0x0008 (0x0008 - 0x0000)
struct BP_MTLB_turret_NSV_C_GetMasterPoseComponent final
{
public:
	class USkinnedMeshComponent*                  ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MTLB_turret_NSV_C_GetMasterPoseComponent) == 0x000008, "Wrong alignment on BP_MTLB_turret_NSV_C_GetMasterPoseComponent");
static_assert(sizeof(BP_MTLB_turret_NSV_C_GetMasterPoseComponent) == 0x000008, "Wrong size on BP_MTLB_turret_NSV_C_GetMasterPoseComponent");
static_assert(offsetof(BP_MTLB_turret_NSV_C_GetMasterPoseComponent, ReturnValue) == 0x000000, "Member 'BP_MTLB_turret_NSV_C_GetMasterPoseComponent::ReturnValue' has a wrong offset!");

// Function BP_MTLB_turret_NSV.BP_MTLB_turret_NSV_C.GetWeaponAttachComponent
// 0x0008 (0x0008 - 0x0000)
struct BP_MTLB_turret_NSV_C_GetWeaponAttachComponent final
{
public:
	class USceneComponent*                        ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MTLB_turret_NSV_C_GetWeaponAttachComponent) == 0x000008, "Wrong alignment on BP_MTLB_turret_NSV_C_GetWeaponAttachComponent");
static_assert(sizeof(BP_MTLB_turret_NSV_C_GetWeaponAttachComponent) == 0x000008, "Wrong size on BP_MTLB_turret_NSV_C_GetWeaponAttachComponent");
static_assert(offsetof(BP_MTLB_turret_NSV_C_GetWeaponAttachComponent, ReturnValue) == 0x000000, "Member 'BP_MTLB_turret_NSV_C_GetWeaponAttachComponent::ReturnValue' has a wrong offset!");

}

