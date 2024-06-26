#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BRDMMinus2

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function BP_BRDM-2.BP_BRDM-2_C.ExecuteUbergraph_BP_BRDM-2
// 0x0048 (0x0048 - 0x0000)
struct BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2 final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4E81[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQDriveTrainComponent*                 K2Node_Event_DriveTrainComponent;                  // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQVehicleWheel*                        K2Node_DynamicCast_AsSQVehicle_Wheel;              // 0x0010(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4E82[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQDriveTrainComponent*                 K2Node_Event_DriveTrainComponent_1;                // 0x0020(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   CallFunc_GetBoneName_ReturnValue;                  // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQVehicleWheel*                        K2Node_DynamicCast_AsSQVehicle_Wheel_1;            // 0x0030(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4E83[0x3];                                     // 0x0039(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   CallFunc_GetBoneName_ReturnValue_1;                // 0x003C(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2) == 0x000008, "Wrong alignment on BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2");
static_assert(sizeof(BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2) == 0x000048, "Wrong size on BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2");
static_assert(offsetof(BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2, EntryPoint) == 0x000000, "Member 'BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2, K2Node_Event_DriveTrainComponent) == 0x000008, "Member 'BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2::K2Node_Event_DriveTrainComponent' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2, K2Node_DynamicCast_AsSQVehicle_Wheel) == 0x000010, "Member 'BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2::K2Node_DynamicCast_AsSQVehicle_Wheel' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2, K2Node_Event_DriveTrainComponent_1) == 0x000020, "Member 'BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2::K2Node_Event_DriveTrainComponent_1' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2, CallFunc_GetBoneName_ReturnValue) == 0x000028, "Member 'BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2::CallFunc_GetBoneName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2, K2Node_DynamicCast_AsSQVehicle_Wheel_1) == 0x000030, "Member 'BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2::K2Node_DynamicCast_AsSQVehicle_Wheel_1' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2, K2Node_DynamicCast_bSuccess_1) == 0x000038, "Member 'BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2, CallFunc_GetBoneName_ReturnValue_1) == 0x00003C, "Member 'BP_BRDMMinus2_C_ExecuteUbergraph_BP_BRDMMinus2::CallFunc_GetBoneName_ReturnValue_1' has a wrong offset!");

// Function BP_BRDM-2.BP_BRDM-2_C.DrivetrainComponentDestroyed
// 0x0008 (0x0008 - 0x0000)
struct BP_BRDMMinus2_C_DrivetrainComponentDestroyed final
{
public:
	class USQDriveTrainComponent*                 DriveTrainComponent;                               // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BRDMMinus2_C_DrivetrainComponentDestroyed) == 0x000008, "Wrong alignment on BP_BRDMMinus2_C_DrivetrainComponentDestroyed");
static_assert(sizeof(BP_BRDMMinus2_C_DrivetrainComponentDestroyed) == 0x000008, "Wrong size on BP_BRDMMinus2_C_DrivetrainComponentDestroyed");
static_assert(offsetof(BP_BRDMMinus2_C_DrivetrainComponentDestroyed, DriveTrainComponent) == 0x000000, "Member 'BP_BRDMMinus2_C_DrivetrainComponentDestroyed::DriveTrainComponent' has a wrong offset!");

// Function BP_BRDM-2.BP_BRDM-2_C.DrivetrainComponentRepaired
// 0x0008 (0x0008 - 0x0000)
struct BP_BRDMMinus2_C_DrivetrainComponentRepaired final
{
public:
	class USQDriveTrainComponent*                 DriveTrainComponent;                               // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BRDMMinus2_C_DrivetrainComponentRepaired) == 0x000008, "Wrong alignment on BP_BRDMMinus2_C_DrivetrainComponentRepaired");
static_assert(sizeof(BP_BRDMMinus2_C_DrivetrainComponentRepaired) == 0x000008, "Wrong size on BP_BRDMMinus2_C_DrivetrainComponentRepaired");
static_assert(offsetof(BP_BRDMMinus2_C_DrivetrainComponentRepaired, DriveTrainComponent) == 0x000000, "Member 'BP_BRDMMinus2_C_DrivetrainComponentRepaired::DriveTrainComponent' has a wrong offset!");

// Function BP_BRDM-2.BP_BRDM-2_C.Update Damaged Wheel Visual
// 0x0070 (0x0070 - 0x0000)
struct BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual final
{
public:
	class FName                                   Bone;                                              // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Destroyed;                                         // 0x0008(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4E84[0x7];                                     // 0x0009(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQVehicleWheel*                        Wheel;                                             // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Do_Effects;                                        // 0x0018(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4E85[0x3];                                     // 0x0019(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                L_Scale;                                           // 0x001C(0x000C)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                Temp_struct_Variable;                              // 0x0028(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_SwitchName_CmpSuccess;                      // 0x0034(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4E86[0x3];                                     // 0x0035(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                Temp_struct_Variable_1;                            // 0x0038(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0044(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4E87[0x3];                                     // 0x0045(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                K2Node_Select_Default;                             // 0x0048(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4E88[0x4];                                     // 0x0054(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UAnimInstance*                          CallFunc_GetAnimInstance_ReturnValue;              // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBRDM2__animBP_C*                       K2Node_DynamicCast_AsBRDM2__Anim_BP;               // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual) == 0x000008, "Wrong alignment on BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual");
static_assert(sizeof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual) == 0x000070, "Wrong size on BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual");
static_assert(offsetof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual, Bone) == 0x000000, "Member 'BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual::Bone' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual, Destroyed) == 0x000008, "Member 'BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual::Destroyed' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual, Wheel) == 0x000010, "Member 'BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual::Wheel' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual, Do_Effects) == 0x000018, "Member 'BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual::Do_Effects' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual, L_Scale) == 0x00001C, "Member 'BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual::L_Scale' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual, Temp_struct_Variable) == 0x000028, "Member 'BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual::Temp_struct_Variable' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual, K2Node_SwitchName_CmpSuccess) == 0x000034, "Member 'BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual::K2Node_SwitchName_CmpSuccess' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual, Temp_struct_Variable_1) == 0x000038, "Member 'BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual::Temp_struct_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual, Temp_bool_Variable) == 0x000044, "Member 'BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual, K2Node_Select_Default) == 0x000048, "Member 'BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual, CallFunc_GetAnimInstance_ReturnValue) == 0x000058, "Member 'BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual::CallFunc_GetAnimInstance_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual, K2Node_DynamicCast_AsBRDM2__Anim_BP) == 0x000060, "Member 'BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual::K2Node_DynamicCast_AsBRDM2__Anim_BP' has a wrong offset!");
static_assert(offsetof(BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual, K2Node_DynamicCast_bSuccess) == 0x000068, "Member 'BP_BRDMMinus2_C_Update_Damaged_Wheel_Visual::K2Node_DynamicCast_bSuccess' has a wrong offset!");

}

