#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BMP1_INS

#include "Basic.hpp"


namespace SDK::Params
{

// Function BP_BMP1_INS.BP_BMP1_INS_C.ExecuteUbergraph_BP_BMP1_INS
// 0x0048 (0x0048 - 0x0000)
struct BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4FD7[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQDriveTrainComponent*                 K2Node_Event_DriveTrainComponent;                  // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_Event_DeltaSeconds;                         // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4FD8[0x4];                                     // 0x0014(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQTrackedVehicleMovementComponent*     K2Node_DynamicCast_AsSQTracked_Vehicle_Movement_Component; // 0x0018(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FD9[0x3];                                     // 0x0021(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_GetLeftTrackSpeed_ReturnValue;            // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetRightTrackSpeed_ReturnValue;           // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x002C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_1;        // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_UpdateTrackMaterial_NewUVOffset;          // 0x0034(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_UpdateTrackMaterial_NewUVOffset_1;        // 0x0038(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsDedicatedServer_ReturnValue;            // 0x003C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FDA[0x3];                                     // 0x003D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class USQDriveTrainComponent*                 K2Node_Event_DriveTrainComponent_1;                // 0x0040(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS) == 0x000008, "Wrong alignment on BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS");
static_assert(sizeof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS) == 0x000048, "Wrong size on BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS");
static_assert(offsetof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS, EntryPoint) == 0x000000, "Member 'BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS, K2Node_Event_DriveTrainComponent) == 0x000008, "Member 'BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS::K2Node_Event_DriveTrainComponent' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS, K2Node_Event_DeltaSeconds) == 0x000010, "Member 'BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS::K2Node_Event_DeltaSeconds' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS, K2Node_DynamicCast_AsSQTracked_Vehicle_Movement_Component) == 0x000018, "Member 'BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS::K2Node_DynamicCast_AsSQTracked_Vehicle_Movement_Component' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS, K2Node_DynamicCast_bSuccess) == 0x000020, "Member 'BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS, CallFunc_GetLeftTrackSpeed_ReturnValue) == 0x000024, "Member 'BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS::CallFunc_GetLeftTrackSpeed_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS, CallFunc_GetRightTrackSpeed_ReturnValue) == 0x000028, "Member 'BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS::CallFunc_GetRightTrackSpeed_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x00002C, "Member 'BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS, CallFunc_Multiply_FloatFloat_ReturnValue_1) == 0x000030, "Member 'BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS::CallFunc_Multiply_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS, CallFunc_UpdateTrackMaterial_NewUVOffset) == 0x000034, "Member 'BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS::CallFunc_UpdateTrackMaterial_NewUVOffset' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS, CallFunc_UpdateTrackMaterial_NewUVOffset_1) == 0x000038, "Member 'BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS::CallFunc_UpdateTrackMaterial_NewUVOffset_1' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS, CallFunc_IsDedicatedServer_ReturnValue) == 0x00003C, "Member 'BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS::CallFunc_IsDedicatedServer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS, K2Node_Event_DriveTrainComponent_1) == 0x000040, "Member 'BP_BMP1_INS_C_ExecuteUbergraph_BP_BMP1_INS::K2Node_Event_DriveTrainComponent_1' has a wrong offset!");

// Function BP_BMP1_INS.BP_BMP1_INS_C.DrivetrainComponentDestroyed
// 0x0008 (0x0008 - 0x0000)
struct BP_BMP1_INS_C_DrivetrainComponentDestroyed final
{
public:
	class USQDriveTrainComponent*                 DriveTrainComponent;                               // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BMP1_INS_C_DrivetrainComponentDestroyed) == 0x000008, "Wrong alignment on BP_BMP1_INS_C_DrivetrainComponentDestroyed");
static_assert(sizeof(BP_BMP1_INS_C_DrivetrainComponentDestroyed) == 0x000008, "Wrong size on BP_BMP1_INS_C_DrivetrainComponentDestroyed");
static_assert(offsetof(BP_BMP1_INS_C_DrivetrainComponentDestroyed, DriveTrainComponent) == 0x000000, "Member 'BP_BMP1_INS_C_DrivetrainComponentDestroyed::DriveTrainComponent' has a wrong offset!");

// Function BP_BMP1_INS.BP_BMP1_INS_C.DrivetrainComponentRepaired
// 0x0008 (0x0008 - 0x0000)
struct BP_BMP1_INS_C_DrivetrainComponentRepaired final
{
public:
	class USQDriveTrainComponent*                 DriveTrainComponent;                               // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BMP1_INS_C_DrivetrainComponentRepaired) == 0x000008, "Wrong alignment on BP_BMP1_INS_C_DrivetrainComponentRepaired");
static_assert(sizeof(BP_BMP1_INS_C_DrivetrainComponentRepaired) == 0x000008, "Wrong size on BP_BMP1_INS_C_DrivetrainComponentRepaired");
static_assert(offsetof(BP_BMP1_INS_C_DrivetrainComponentRepaired, DriveTrainComponent) == 0x000000, "Member 'BP_BMP1_INS_C_DrivetrainComponentRepaired::DriveTrainComponent' has a wrong offset!");

// Function BP_BMP1_INS.BP_BMP1_INS_C.ReceiveTick
// 0x0004 (0x0004 - 0x0000)
struct BP_BMP1_INS_C_ReceiveTick final
{
public:
	float                                         DeltaSeconds;                                      // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BMP1_INS_C_ReceiveTick) == 0x000004, "Wrong alignment on BP_BMP1_INS_C_ReceiveTick");
static_assert(sizeof(BP_BMP1_INS_C_ReceiveTick) == 0x000004, "Wrong size on BP_BMP1_INS_C_ReceiveTick");
static_assert(offsetof(BP_BMP1_INS_C_ReceiveTick, DeltaSeconds) == 0x000000, "Member 'BP_BMP1_INS_C_ReceiveTick::DeltaSeconds' has a wrong offset!");

// Function BP_BMP1_INS.BP_BMP1_INS_C.UserConstructionScript
// 0x0040 (0x0040 - 0x0000)
struct BP_BMP1_INS_C_UserConstructionScript final
{
public:
	TArray<class UMaterialInterface*>             CallFunc_GetMaterials_ReturnValue;                 // 0x0000(0x0010)(ReferenceParm)
	TArray<class UMaterialInterface*>             CallFunc_GetMaterials_ReturnValue_1;               // 0x0010(0x0010)(ReferenceParm)
	int32                                         CallFunc_GetMaterialIndex_ReturnValue;             // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GetMaterialIndex_ReturnValue_1;           // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               CallFunc_CreateDynamicMaterialInstance_ReturnValue; // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               CallFunc_CreateDynamicMaterialInstance_ReturnValue_1; // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Array_IsValidIndex_ReturnValue;           // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Array_IsValidIndex_ReturnValue_1;         // 0x0039(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_BMP1_INS_C_UserConstructionScript) == 0x000008, "Wrong alignment on BP_BMP1_INS_C_UserConstructionScript");
static_assert(sizeof(BP_BMP1_INS_C_UserConstructionScript) == 0x000040, "Wrong size on BP_BMP1_INS_C_UserConstructionScript");
static_assert(offsetof(BP_BMP1_INS_C_UserConstructionScript, CallFunc_GetMaterials_ReturnValue) == 0x000000, "Member 'BP_BMP1_INS_C_UserConstructionScript::CallFunc_GetMaterials_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UserConstructionScript, CallFunc_GetMaterials_ReturnValue_1) == 0x000010, "Member 'BP_BMP1_INS_C_UserConstructionScript::CallFunc_GetMaterials_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UserConstructionScript, CallFunc_GetMaterialIndex_ReturnValue) == 0x000020, "Member 'BP_BMP1_INS_C_UserConstructionScript::CallFunc_GetMaterialIndex_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UserConstructionScript, CallFunc_GetMaterialIndex_ReturnValue_1) == 0x000024, "Member 'BP_BMP1_INS_C_UserConstructionScript::CallFunc_GetMaterialIndex_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UserConstructionScript, CallFunc_CreateDynamicMaterialInstance_ReturnValue) == 0x000028, "Member 'BP_BMP1_INS_C_UserConstructionScript::CallFunc_CreateDynamicMaterialInstance_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UserConstructionScript, CallFunc_CreateDynamicMaterialInstance_ReturnValue_1) == 0x000030, "Member 'BP_BMP1_INS_C_UserConstructionScript::CallFunc_CreateDynamicMaterialInstance_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UserConstructionScript, CallFunc_Array_IsValidIndex_ReturnValue) == 0x000038, "Member 'BP_BMP1_INS_C_UserConstructionScript::CallFunc_Array_IsValidIndex_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UserConstructionScript, CallFunc_Array_IsValidIndex_ReturnValue_1) == 0x000039, "Member 'BP_BMP1_INS_C_UserConstructionScript::CallFunc_Array_IsValidIndex_ReturnValue_1' has a wrong offset!");

// Function BP_BMP1_INS.BP_BMP1_INS_C.UpdateTrackMaterial
// 0x0038 (0x0038 - 0x0000)
struct BP_BMP1_INS_C_UpdateTrackMaterial final
{
public:
	float                                         DeltaTime;                                         // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MovementSpeed;                                     // 0x0004(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               TrackMaterial;                                     // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         TrackOffset;                                       // 0x0010(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         NewUVOffset;                                       // 0x0014(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Abs_ReturnValue;                          // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_FloatFloat_ReturnValue;           // 0x001C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x001D(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FDB[0x2];                                     // 0x001E(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue_1;          // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x002C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Percent_FloatFloat_ReturnValue;           // 0x0034(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BMP1_INS_C_UpdateTrackMaterial) == 0x000008, "Wrong alignment on BP_BMP1_INS_C_UpdateTrackMaterial");
static_assert(sizeof(BP_BMP1_INS_C_UpdateTrackMaterial) == 0x000038, "Wrong size on BP_BMP1_INS_C_UpdateTrackMaterial");
static_assert(offsetof(BP_BMP1_INS_C_UpdateTrackMaterial, DeltaTime) == 0x000000, "Member 'BP_BMP1_INS_C_UpdateTrackMaterial::DeltaTime' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateTrackMaterial, MovementSpeed) == 0x000004, "Member 'BP_BMP1_INS_C_UpdateTrackMaterial::MovementSpeed' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateTrackMaterial, TrackMaterial) == 0x000008, "Member 'BP_BMP1_INS_C_UpdateTrackMaterial::TrackMaterial' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateTrackMaterial, TrackOffset) == 0x000010, "Member 'BP_BMP1_INS_C_UpdateTrackMaterial::TrackOffset' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateTrackMaterial, NewUVOffset) == 0x000014, "Member 'BP_BMP1_INS_C_UpdateTrackMaterial::NewUVOffset' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateTrackMaterial, CallFunc_Abs_ReturnValue) == 0x000018, "Member 'BP_BMP1_INS_C_UpdateTrackMaterial::CallFunc_Abs_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateTrackMaterial, CallFunc_Greater_FloatFloat_ReturnValue) == 0x00001C, "Member 'BP_BMP1_INS_C_UpdateTrackMaterial::CallFunc_Greater_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateTrackMaterial, CallFunc_IsValid_ReturnValue) == 0x00001D, "Member 'BP_BMP1_INS_C_UpdateTrackMaterial::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateTrackMaterial, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x000020, "Member 'BP_BMP1_INS_C_UpdateTrackMaterial::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateTrackMaterial, CallFunc_Divide_FloatFloat_ReturnValue) == 0x000024, "Member 'BP_BMP1_INS_C_UpdateTrackMaterial::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateTrackMaterial, CallFunc_Divide_FloatFloat_ReturnValue_1) == 0x000028, "Member 'BP_BMP1_INS_C_UpdateTrackMaterial::CallFunc_Divide_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateTrackMaterial, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x00002C, "Member 'BP_BMP1_INS_C_UpdateTrackMaterial::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateTrackMaterial, CallFunc_Add_FloatFloat_ReturnValue) == 0x000030, "Member 'BP_BMP1_INS_C_UpdateTrackMaterial::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateTrackMaterial, CallFunc_Percent_FloatFloat_ReturnValue) == 0x000034, "Member 'BP_BMP1_INS_C_UpdateTrackMaterial::CallFunc_Percent_FloatFloat_ReturnValue' has a wrong offset!");

// Function BP_BMP1_INS.BP_BMP1_INS_C.UpdateDamagedTrackVisual
// 0x0038 (0x0038 - 0x0000)
struct BP_BMP1_INS_C_UpdateDamagedTrackVisual final
{
public:
	class UObject*                                VehicleTrack;                                      // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          bIsTrackDestroyed;                                 // 0x0008(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          ShowOriginalTrack;                                 // 0x0009(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_ObjectObject_ReturnValue;      // 0x000A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FDC[0x5];                                     // 0x000B(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class UAnimInstance*                          CallFunc_GetAnimInstance_ReturnValue;              // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBMP1_AnimBlueprint_C*                  K2Node_DynamicCast_AsBMP1_Anim_Blueprint;          // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_ObjectObject_ReturnValue_1;    // 0x0021(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FDD[0x6];                                     // 0x0022(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UBMP1_AnimBlueprint_C*                  K2Node_DynamicCast_AsBMP1_Anim_Blueprint_1;        // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_BMP1_INS_C_UpdateDamagedTrackVisual) == 0x000008, "Wrong alignment on BP_BMP1_INS_C_UpdateDamagedTrackVisual");
static_assert(sizeof(BP_BMP1_INS_C_UpdateDamagedTrackVisual) == 0x000038, "Wrong size on BP_BMP1_INS_C_UpdateDamagedTrackVisual");
static_assert(offsetof(BP_BMP1_INS_C_UpdateDamagedTrackVisual, VehicleTrack) == 0x000000, "Member 'BP_BMP1_INS_C_UpdateDamagedTrackVisual::VehicleTrack' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateDamagedTrackVisual, bIsTrackDestroyed) == 0x000008, "Member 'BP_BMP1_INS_C_UpdateDamagedTrackVisual::bIsTrackDestroyed' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateDamagedTrackVisual, ShowOriginalTrack) == 0x000009, "Member 'BP_BMP1_INS_C_UpdateDamagedTrackVisual::ShowOriginalTrack' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateDamagedTrackVisual, CallFunc_EqualEqual_ObjectObject_ReturnValue) == 0x00000A, "Member 'BP_BMP1_INS_C_UpdateDamagedTrackVisual::CallFunc_EqualEqual_ObjectObject_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateDamagedTrackVisual, CallFunc_GetAnimInstance_ReturnValue) == 0x000010, "Member 'BP_BMP1_INS_C_UpdateDamagedTrackVisual::CallFunc_GetAnimInstance_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateDamagedTrackVisual, K2Node_DynamicCast_AsBMP1_Anim_Blueprint) == 0x000018, "Member 'BP_BMP1_INS_C_UpdateDamagedTrackVisual::K2Node_DynamicCast_AsBMP1_Anim_Blueprint' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateDamagedTrackVisual, K2Node_DynamicCast_bSuccess) == 0x000020, "Member 'BP_BMP1_INS_C_UpdateDamagedTrackVisual::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateDamagedTrackVisual, CallFunc_EqualEqual_ObjectObject_ReturnValue_1) == 0x000021, "Member 'BP_BMP1_INS_C_UpdateDamagedTrackVisual::CallFunc_EqualEqual_ObjectObject_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateDamagedTrackVisual, K2Node_DynamicCast_AsBMP1_Anim_Blueprint_1) == 0x000028, "Member 'BP_BMP1_INS_C_UpdateDamagedTrackVisual::K2Node_DynamicCast_AsBMP1_Anim_Blueprint_1' has a wrong offset!");
static_assert(offsetof(BP_BMP1_INS_C_UpdateDamagedTrackVisual, K2Node_DynamicCast_bSuccess_1) == 0x000030, "Member 'BP_BMP1_INS_C_UpdateDamagedTrackVisual::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");

}

