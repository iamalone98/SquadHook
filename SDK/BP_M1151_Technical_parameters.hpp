#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_M1151_Technical

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function BP_M1151_Technical.BP_M1151_Technical_C.ExecuteUbergraph_BP_M1151_Technical
// 0x0048 (0x0048 - 0x0000)
struct BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4FDE[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQDriveTrainComponent*                 K2Node_Event_DriveTrainComponent;                  // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQVehicleWheel*                        K2Node_DynamicCast_AsSQVehicle_Wheel;              // 0x0010(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FDF[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQDriveTrainComponent*                 K2Node_Event_DriveTrainComponent_1;                // 0x0020(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   CallFunc_GetBoneName_ReturnValue;                  // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQVehicleWheel*                        K2Node_DynamicCast_AsSQVehicle_Wheel_1;            // 0x0030(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FE0[0x3];                                     // 0x0039(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   CallFunc_GetBoneName_ReturnValue_1;                // 0x003C(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical) == 0x000008, "Wrong alignment on BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical");
static_assert(sizeof(BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical) == 0x000048, "Wrong size on BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical");
static_assert(offsetof(BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical, EntryPoint) == 0x000000, "Member 'BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical, K2Node_Event_DriveTrainComponent) == 0x000008, "Member 'BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical::K2Node_Event_DriveTrainComponent' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical, K2Node_DynamicCast_AsSQVehicle_Wheel) == 0x000010, "Member 'BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical::K2Node_DynamicCast_AsSQVehicle_Wheel' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical, K2Node_Event_DriveTrainComponent_1) == 0x000020, "Member 'BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical::K2Node_Event_DriveTrainComponent_1' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical, CallFunc_GetBoneName_ReturnValue) == 0x000028, "Member 'BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical::CallFunc_GetBoneName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical, K2Node_DynamicCast_AsSQVehicle_Wheel_1) == 0x000030, "Member 'BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical::K2Node_DynamicCast_AsSQVehicle_Wheel_1' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical, K2Node_DynamicCast_bSuccess_1) == 0x000038, "Member 'BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical, CallFunc_GetBoneName_ReturnValue_1) == 0x00003C, "Member 'BP_M1151_Technical_C_ExecuteUbergraph_BP_M1151_Technical::CallFunc_GetBoneName_ReturnValue_1' has a wrong offset!");

// Function BP_M1151_Technical.BP_M1151_Technical_C.DrivetrainComponentRepaired
// 0x0008 (0x0008 - 0x0000)
struct BP_M1151_Technical_C_DrivetrainComponentRepaired final
{
public:
	class USQDriveTrainComponent*                 DriveTrainComponent;                               // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_M1151_Technical_C_DrivetrainComponentRepaired) == 0x000008, "Wrong alignment on BP_M1151_Technical_C_DrivetrainComponentRepaired");
static_assert(sizeof(BP_M1151_Technical_C_DrivetrainComponentRepaired) == 0x000008, "Wrong size on BP_M1151_Technical_C_DrivetrainComponentRepaired");
static_assert(offsetof(BP_M1151_Technical_C_DrivetrainComponentRepaired, DriveTrainComponent) == 0x000000, "Member 'BP_M1151_Technical_C_DrivetrainComponentRepaired::DriveTrainComponent' has a wrong offset!");

// Function BP_M1151_Technical.BP_M1151_Technical_C.DrivetrainComponentDestroyed
// 0x0008 (0x0008 - 0x0000)
struct BP_M1151_Technical_C_DrivetrainComponentDestroyed final
{
public:
	class USQDriveTrainComponent*                 DriveTrainComponent;                               // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_M1151_Technical_C_DrivetrainComponentDestroyed) == 0x000008, "Wrong alignment on BP_M1151_Technical_C_DrivetrainComponentDestroyed");
static_assert(sizeof(BP_M1151_Technical_C_DrivetrainComponentDestroyed) == 0x000008, "Wrong size on BP_M1151_Technical_C_DrivetrainComponentDestroyed");
static_assert(offsetof(BP_M1151_Technical_C_DrivetrainComponentDestroyed, DriveTrainComponent) == 0x000000, "Member 'BP_M1151_Technical_C_DrivetrainComponentDestroyed::DriveTrainComponent' has a wrong offset!");

// Function BP_M1151_Technical.BP_M1151_Technical_C.UpdateDamageWheelVisual
// 0x0058 (0x0058 - 0x0000)
struct BP_M1151_Technical_C_UpdateDamageWheelVisual final
{
public:
	class FName                                   Bone;                                              // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Destroyed;                                         // 0x0008(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FE1[0x7];                                     // 0x0009(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQVehicleWheel*                        Wheel;                                             // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Do_Effects;                                        // 0x0018(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          Temp_bool_Variable;                                // 0x0019(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_SwitchName_CmpSuccess;                      // 0x001A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FE2[0x1];                                     // 0x001B(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                Temp_struct_Variable;                              // 0x001C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                Temp_struct_Variable_1;                            // 0x0028(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                K2Node_Select_Default;                             // 0x0034(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimInstance*                          CallFunc_GetAnimInstance_ReturnValue;              // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UM1151_Skeleton_AnimBlueprint_C*        K2Node_DynamicCast_AsM1151_Skeleton_Anim_Blueprint; // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_M1151_Technical_C_UpdateDamageWheelVisual) == 0x000008, "Wrong alignment on BP_M1151_Technical_C_UpdateDamageWheelVisual");
static_assert(sizeof(BP_M1151_Technical_C_UpdateDamageWheelVisual) == 0x000058, "Wrong size on BP_M1151_Technical_C_UpdateDamageWheelVisual");
static_assert(offsetof(BP_M1151_Technical_C_UpdateDamageWheelVisual, Bone) == 0x000000, "Member 'BP_M1151_Technical_C_UpdateDamageWheelVisual::Bone' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_UpdateDamageWheelVisual, Destroyed) == 0x000008, "Member 'BP_M1151_Technical_C_UpdateDamageWheelVisual::Destroyed' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_UpdateDamageWheelVisual, Wheel) == 0x000010, "Member 'BP_M1151_Technical_C_UpdateDamageWheelVisual::Wheel' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_UpdateDamageWheelVisual, Do_Effects) == 0x000018, "Member 'BP_M1151_Technical_C_UpdateDamageWheelVisual::Do_Effects' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_UpdateDamageWheelVisual, Temp_bool_Variable) == 0x000019, "Member 'BP_M1151_Technical_C_UpdateDamageWheelVisual::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_UpdateDamageWheelVisual, K2Node_SwitchName_CmpSuccess) == 0x00001A, "Member 'BP_M1151_Technical_C_UpdateDamageWheelVisual::K2Node_SwitchName_CmpSuccess' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_UpdateDamageWheelVisual, Temp_struct_Variable) == 0x00001C, "Member 'BP_M1151_Technical_C_UpdateDamageWheelVisual::Temp_struct_Variable' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_UpdateDamageWheelVisual, Temp_struct_Variable_1) == 0x000028, "Member 'BP_M1151_Technical_C_UpdateDamageWheelVisual::Temp_struct_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_UpdateDamageWheelVisual, K2Node_Select_Default) == 0x000034, "Member 'BP_M1151_Technical_C_UpdateDamageWheelVisual::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_UpdateDamageWheelVisual, CallFunc_GetAnimInstance_ReturnValue) == 0x000040, "Member 'BP_M1151_Technical_C_UpdateDamageWheelVisual::CallFunc_GetAnimInstance_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_UpdateDamageWheelVisual, K2Node_DynamicCast_AsM1151_Skeleton_Anim_Blueprint) == 0x000048, "Member 'BP_M1151_Technical_C_UpdateDamageWheelVisual::K2Node_DynamicCast_AsM1151_Skeleton_Anim_Blueprint' has a wrong offset!");
static_assert(offsetof(BP_M1151_Technical_C_UpdateDamageWheelVisual, K2Node_DynamicCast_bSuccess) == 0x000050, "Member 'BP_M1151_Technical_C_UpdateDamageWheelVisual::K2Node_DynamicCast_bSuccess' has a wrong offset!");

}
