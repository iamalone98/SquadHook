#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_FV4034

#include "Basic.hpp"

#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function BP_FV4034.BP_FV4034_C.ExecuteUbergraph_BP_FV4034
// 0x0180 (0x0180 - 0x0000)
struct BP_FV4034_C_ExecuteUbergraph_BP_FV4034 final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4F4F[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class USQVehicleSeatComponent*>        CallFunc_GetSeats_ReturnValue;                     // 0x0008(0x0010)(ReferenceParm, ContainsInstancedReference)
	TArray<class USQVehicleSeatComponent*>        CallFunc_GetSeats_ReturnValue_1;                   // 0x0018(0x0010)(ReferenceParm, ContainsInstancedReference)
	class USQVehicleSeatComponent*                CallFunc_Array_Get_Item;                           // 0x0028(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQVehicleSeatComponent*                CallFunc_Array_Get_Item_1;                         // 0x0030(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0039(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F50[0x6];                                     // 0x003A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class USQVehicleSeatComponent*                CallFunc_Array_Get_Item_2;                         // 0x0040(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQVehicleSeatComponent*                CallFunc_Array_Get_Item_3;                         // 0x0048(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_3;                    // 0x0051(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F51[0x6];                                     // 0x0052(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQVehicleSeat*                         CallFunc_GetSeatPawn_ReturnValue;                  // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQVehicleSeat*                         CallFunc_GetSeatPawn_ReturnValue_1;                // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ABP_FV4034_Turret_C*                    K2Node_DynamicCast_AsBP_FV4034_Turret;             // 0x0068(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0070(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F52[0x7];                                     // 0x0071(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_FV4034_Turret_C*                    K2Node_DynamicCast_AsBP_FV4034_Turret_1;           // 0x0078(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0080(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_K2_AttachToComponent_ReturnValue;         // 0x0081(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_K2_AttachToComponent_ReturnValue_1;       // 0x0082(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_4;                    // 0x0083(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_5;                    // 0x0084(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F53[0x3];                                     // 0x0085(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class USQVehicleSeatComponent*>        CallFunc_GetSeats_ReturnValue_2;                   // 0x0088(0x0010)(ReferenceParm, ContainsInstancedReference)
	TArray<class USQVehicleSeatComponent*>        CallFunc_GetSeats_ReturnValue_3;                   // 0x0098(0x0010)(ReferenceParm, ContainsInstancedReference)
	class USQVehicleSeatComponent*                CallFunc_Array_Get_Item_4;                         // 0x00A8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQVehicleSeatComponent*                CallFunc_Array_Get_Item_5;                         // 0x00B0(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQVehicleSeat*                         CallFunc_GetSeatPawn_ReturnValue_2;                // 0x00B8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQVehicleSeat*                         CallFunc_GetSeatPawn_ReturnValue_3;                // 0x00C0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ABP_FV4034_Turret_C*                    K2Node_DynamicCast_AsBP_FV4034_Turret_2;           // 0x00C8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x00D0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F54[0x7];                                     // 0x00D1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_FV4034_Commander_Periscope_C*       K2Node_DynamicCast_AsBP_FV4034_Commander_Periscope; // 0x00D8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_3;                     // 0x00E0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F55[0x7];                                     // 0x00E1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class USQVehicleSeatComponent*>        CallFunc_GetSeats_ReturnValue_4;                   // 0x00E8(0x0010)(ReferenceParm, ContainsInstancedReference)
	class USQVehicleSeatComponent*                CallFunc_Array_Get_Item_6;                         // 0x00F8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQDriveTrainComponent*                 K2Node_Event_DriveTrainComponent_1;                // 0x0100(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQVehicleSeat*                         CallFunc_GetSeatPawn_ReturnValue_4;                // 0x0108(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ABP_EnforcerRWS_Turret_L37A2_C*         K2Node_DynamicCast_AsBP_Enforcer_RWS_Turret_L37A2; // 0x0110(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_4;                     // 0x0118(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F56[0x7];                                     // 0x0119(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQDriveTrainComponent*                 K2Node_Event_DriveTrainComponent;                  // 0x0120(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0128(0x0010)(ZeroConstructor, NoDestructor)
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue;          // 0x0138(0x0008)(NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_1;            // 0x0140(0x0010)(ZeroConstructor, NoDestructor)
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue_1;        // 0x0150(0x0008)(NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsDedicatedServer_ReturnValue;            // 0x0158(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F57[0x3];                                     // 0x0159(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         K2Node_Event_DeltaSeconds;                         // 0x015C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQTrackedVehicleMovementComponent*     K2Node_DynamicCast_AsSQTracked_Vehicle_Movement_Component; // 0x0160(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_5;                     // 0x0168(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F58[0x3];                                     // 0x0169(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_GetLeftTrackSpeed_ReturnValue;            // 0x016C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetRightTrackSpeed_ReturnValue;           // 0x0170(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_UpdateTrackMaterial_NewUVOffset;          // 0x0174(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_UpdateTrackMaterial_NewUVOffset_1;        // 0x0178(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034) == 0x000008, "Wrong alignment on BP_FV4034_C_ExecuteUbergraph_BP_FV4034");
static_assert(sizeof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034) == 0x000180, "Wrong size on BP_FV4034_C_ExecuteUbergraph_BP_FV4034");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, EntryPoint) == 0x000000, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_GetSeats_ReturnValue) == 0x000008, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_GetSeats_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_GetSeats_ReturnValue_1) == 0x000018, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_GetSeats_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_Array_Get_Item) == 0x000028, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_Array_Get_Item_1) == 0x000030, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_Array_Get_Item_1' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_IsValid_ReturnValue) == 0x000038, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_IsValid_ReturnValue_1) == 0x000039, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_Array_Get_Item_2) == 0x000040, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_Array_Get_Item_2' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_Array_Get_Item_3) == 0x000048, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_Array_Get_Item_3' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_IsValid_ReturnValue_2) == 0x000050, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_IsValid_ReturnValue_3) == 0x000051, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_IsValid_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_GetSeatPawn_ReturnValue) == 0x000058, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_GetSeatPawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_GetSeatPawn_ReturnValue_1) == 0x000060, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_GetSeatPawn_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_DynamicCast_AsBP_FV4034_Turret) == 0x000068, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_DynamicCast_AsBP_FV4034_Turret' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_DynamicCast_bSuccess) == 0x000070, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_DynamicCast_AsBP_FV4034_Turret_1) == 0x000078, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_DynamicCast_AsBP_FV4034_Turret_1' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_DynamicCast_bSuccess_1) == 0x000080, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_K2_AttachToComponent_ReturnValue) == 0x000081, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_K2_AttachToComponent_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_K2_AttachToComponent_ReturnValue_1) == 0x000082, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_K2_AttachToComponent_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_IsValid_ReturnValue_4) == 0x000083, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_IsValid_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_IsValid_ReturnValue_5) == 0x000084, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_IsValid_ReturnValue_5' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_GetSeats_ReturnValue_2) == 0x000088, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_GetSeats_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_GetSeats_ReturnValue_3) == 0x000098, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_GetSeats_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_Array_Get_Item_4) == 0x0000A8, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_Array_Get_Item_4' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_Array_Get_Item_5) == 0x0000B0, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_Array_Get_Item_5' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_GetSeatPawn_ReturnValue_2) == 0x0000B8, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_GetSeatPawn_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_GetSeatPawn_ReturnValue_3) == 0x0000C0, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_GetSeatPawn_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_DynamicCast_AsBP_FV4034_Turret_2) == 0x0000C8, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_DynamicCast_AsBP_FV4034_Turret_2' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_DynamicCast_bSuccess_2) == 0x0000D0, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_DynamicCast_AsBP_FV4034_Commander_Periscope) == 0x0000D8, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_DynamicCast_AsBP_FV4034_Commander_Periscope' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_DynamicCast_bSuccess_3) == 0x0000E0, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_DynamicCast_bSuccess_3' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_GetSeats_ReturnValue_4) == 0x0000E8, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_GetSeats_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_Array_Get_Item_6) == 0x0000F8, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_Array_Get_Item_6' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_Event_DriveTrainComponent_1) == 0x000100, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_Event_DriveTrainComponent_1' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_GetSeatPawn_ReturnValue_4) == 0x000108, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_GetSeatPawn_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_DynamicCast_AsBP_Enforcer_RWS_Turret_L37A2) == 0x000110, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_DynamicCast_AsBP_Enforcer_RWS_Turret_L37A2' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_DynamicCast_bSuccess_4) == 0x000118, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_DynamicCast_bSuccess_4' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_Event_DriveTrainComponent) == 0x000120, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_Event_DriveTrainComponent' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_CreateDelegate_OutputDelegate) == 0x000128, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_K2_SetTimerDelegate_ReturnValue) == 0x000138, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_K2_SetTimerDelegate_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_CreateDelegate_OutputDelegate_1) == 0x000140, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_K2_SetTimerDelegate_ReturnValue_1) == 0x000150, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_K2_SetTimerDelegate_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_IsDedicatedServer_ReturnValue) == 0x000158, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_IsDedicatedServer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_Event_DeltaSeconds) == 0x00015C, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_Event_DeltaSeconds' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_DynamicCast_AsSQTracked_Vehicle_Movement_Component) == 0x000160, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_DynamicCast_AsSQTracked_Vehicle_Movement_Component' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, K2Node_DynamicCast_bSuccess_5) == 0x000168, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::K2Node_DynamicCast_bSuccess_5' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_GetLeftTrackSpeed_ReturnValue) == 0x00016C, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_GetLeftTrackSpeed_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_GetRightTrackSpeed_ReturnValue) == 0x000170, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_GetRightTrackSpeed_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_UpdateTrackMaterial_NewUVOffset) == 0x000174, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_UpdateTrackMaterial_NewUVOffset' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_ExecuteUbergraph_BP_FV4034, CallFunc_UpdateTrackMaterial_NewUVOffset_1) == 0x000178, "Member 'BP_FV4034_C_ExecuteUbergraph_BP_FV4034::CallFunc_UpdateTrackMaterial_NewUVOffset_1' has a wrong offset!");

// Function BP_FV4034.BP_FV4034_C.DrivetrainComponentDestroyed
// 0x0008 (0x0008 - 0x0000)
struct BP_FV4034_C_DrivetrainComponentDestroyed final
{
public:
	class USQDriveTrainComponent*                 DriveTrainComponent;                               // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_FV4034_C_DrivetrainComponentDestroyed) == 0x000008, "Wrong alignment on BP_FV4034_C_DrivetrainComponentDestroyed");
static_assert(sizeof(BP_FV4034_C_DrivetrainComponentDestroyed) == 0x000008, "Wrong size on BP_FV4034_C_DrivetrainComponentDestroyed");
static_assert(offsetof(BP_FV4034_C_DrivetrainComponentDestroyed, DriveTrainComponent) == 0x000000, "Member 'BP_FV4034_C_DrivetrainComponentDestroyed::DriveTrainComponent' has a wrong offset!");

// Function BP_FV4034.BP_FV4034_C.DrivetrainComponentRepaired
// 0x0008 (0x0008 - 0x0000)
struct BP_FV4034_C_DrivetrainComponentRepaired final
{
public:
	class USQDriveTrainComponent*                 DriveTrainComponent;                               // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_FV4034_C_DrivetrainComponentRepaired) == 0x000008, "Wrong alignment on BP_FV4034_C_DrivetrainComponentRepaired");
static_assert(sizeof(BP_FV4034_C_DrivetrainComponentRepaired) == 0x000008, "Wrong size on BP_FV4034_C_DrivetrainComponentRepaired");
static_assert(offsetof(BP_FV4034_C_DrivetrainComponentRepaired, DriveTrainComponent) == 0x000000, "Member 'BP_FV4034_C_DrivetrainComponentRepaired::DriveTrainComponent' has a wrong offset!");

// Function BP_FV4034.BP_FV4034_C.ReceiveTick
// 0x0004 (0x0004 - 0x0000)
struct BP_FV4034_C_ReceiveTick final
{
public:
	float                                         DeltaSeconds;                                      // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_FV4034_C_ReceiveTick) == 0x000004, "Wrong alignment on BP_FV4034_C_ReceiveTick");
static_assert(sizeof(BP_FV4034_C_ReceiveTick) == 0x000004, "Wrong size on BP_FV4034_C_ReceiveTick");
static_assert(offsetof(BP_FV4034_C_ReceiveTick, DeltaSeconds) == 0x000000, "Member 'BP_FV4034_C_ReceiveTick::DeltaSeconds' has a wrong offset!");

// Function BP_FV4034.BP_FV4034_C.UserConstructionScript
// 0x0010 (0x0010 - 0x0000)
struct BP_FV4034_C_UserConstructionScript final
{
public:
	class UMaterialInstanceDynamic*               CallFunc_CreateDynamicMaterialInstance_ReturnValue; // 0x0000(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               CallFunc_CreateDynamicMaterialInstance_ReturnValue_1; // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_FV4034_C_UserConstructionScript) == 0x000008, "Wrong alignment on BP_FV4034_C_UserConstructionScript");
static_assert(sizeof(BP_FV4034_C_UserConstructionScript) == 0x000010, "Wrong size on BP_FV4034_C_UserConstructionScript");
static_assert(offsetof(BP_FV4034_C_UserConstructionScript, CallFunc_CreateDynamicMaterialInstance_ReturnValue) == 0x000000, "Member 'BP_FV4034_C_UserConstructionScript::CallFunc_CreateDynamicMaterialInstance_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UserConstructionScript, CallFunc_CreateDynamicMaterialInstance_ReturnValue_1) == 0x000008, "Member 'BP_FV4034_C_UserConstructionScript::CallFunc_CreateDynamicMaterialInstance_ReturnValue_1' has a wrong offset!");

// Function BP_FV4034.BP_FV4034_C.UpdateTrackMaterial
// 0x0038 (0x0038 - 0x0000)
struct BP_FV4034_C_UpdateTrackMaterial final
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
	uint8                                         Pad_4F59[0x2];                                     // 0x001E(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue_1;          // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x002C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Percent_FloatFloat_ReturnValue;           // 0x0034(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_FV4034_C_UpdateTrackMaterial) == 0x000008, "Wrong alignment on BP_FV4034_C_UpdateTrackMaterial");
static_assert(sizeof(BP_FV4034_C_UpdateTrackMaterial) == 0x000038, "Wrong size on BP_FV4034_C_UpdateTrackMaterial");
static_assert(offsetof(BP_FV4034_C_UpdateTrackMaterial, DeltaTime) == 0x000000, "Member 'BP_FV4034_C_UpdateTrackMaterial::DeltaTime' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateTrackMaterial, MovementSpeed) == 0x000004, "Member 'BP_FV4034_C_UpdateTrackMaterial::MovementSpeed' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateTrackMaterial, TrackMaterial) == 0x000008, "Member 'BP_FV4034_C_UpdateTrackMaterial::TrackMaterial' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateTrackMaterial, TrackOffset) == 0x000010, "Member 'BP_FV4034_C_UpdateTrackMaterial::TrackOffset' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateTrackMaterial, NewUVOffset) == 0x000014, "Member 'BP_FV4034_C_UpdateTrackMaterial::NewUVOffset' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateTrackMaterial, CallFunc_Abs_ReturnValue) == 0x000018, "Member 'BP_FV4034_C_UpdateTrackMaterial::CallFunc_Abs_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateTrackMaterial, CallFunc_Greater_FloatFloat_ReturnValue) == 0x00001C, "Member 'BP_FV4034_C_UpdateTrackMaterial::CallFunc_Greater_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateTrackMaterial, CallFunc_IsValid_ReturnValue) == 0x00001D, "Member 'BP_FV4034_C_UpdateTrackMaterial::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateTrackMaterial, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x000020, "Member 'BP_FV4034_C_UpdateTrackMaterial::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateTrackMaterial, CallFunc_Divide_FloatFloat_ReturnValue) == 0x000024, "Member 'BP_FV4034_C_UpdateTrackMaterial::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateTrackMaterial, CallFunc_Divide_FloatFloat_ReturnValue_1) == 0x000028, "Member 'BP_FV4034_C_UpdateTrackMaterial::CallFunc_Divide_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateTrackMaterial, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x00002C, "Member 'BP_FV4034_C_UpdateTrackMaterial::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateTrackMaterial, CallFunc_Add_FloatFloat_ReturnValue) == 0x000030, "Member 'BP_FV4034_C_UpdateTrackMaterial::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateTrackMaterial, CallFunc_Percent_FloatFloat_ReturnValue) == 0x000034, "Member 'BP_FV4034_C_UpdateTrackMaterial::CallFunc_Percent_FloatFloat_ReturnValue' has a wrong offset!");

// Function BP_FV4034.BP_FV4034_C.UpdateDamagedTrackVisual
// 0x0038 (0x0038 - 0x0000)
struct BP_FV4034_C_UpdateDamagedTrackVisual final
{
public:
	class UObject*                                VehicleTrack;                                      // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          bIsTrackDestroyed;                                 // 0x0008(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          ShowOriginalTrack;                                 // 0x0009(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_ObjectObject_ReturnValue;      // 0x000A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F5A[0x5];                                     // 0x000B(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class UAnimInstance*                          CallFunc_GetAnimInstance_ReturnValue;              // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UFv4034_Skeleton_AnimBlueprint_C*       K2Node_DynamicCast_AsFv_4034_Skeleton_Anim_Blueprint; // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_ObjectObject_ReturnValue_1;    // 0x0021(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F5B[0x6];                                     // 0x0022(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UFv4034_Skeleton_AnimBlueprint_C*       K2Node_DynamicCast_AsFv_4034_Skeleton_Anim_Blueprint_1; // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_FV4034_C_UpdateDamagedTrackVisual) == 0x000008, "Wrong alignment on BP_FV4034_C_UpdateDamagedTrackVisual");
static_assert(sizeof(BP_FV4034_C_UpdateDamagedTrackVisual) == 0x000038, "Wrong size on BP_FV4034_C_UpdateDamagedTrackVisual");
static_assert(offsetof(BP_FV4034_C_UpdateDamagedTrackVisual, VehicleTrack) == 0x000000, "Member 'BP_FV4034_C_UpdateDamagedTrackVisual::VehicleTrack' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateDamagedTrackVisual, bIsTrackDestroyed) == 0x000008, "Member 'BP_FV4034_C_UpdateDamagedTrackVisual::bIsTrackDestroyed' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateDamagedTrackVisual, ShowOriginalTrack) == 0x000009, "Member 'BP_FV4034_C_UpdateDamagedTrackVisual::ShowOriginalTrack' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateDamagedTrackVisual, CallFunc_EqualEqual_ObjectObject_ReturnValue) == 0x00000A, "Member 'BP_FV4034_C_UpdateDamagedTrackVisual::CallFunc_EqualEqual_ObjectObject_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateDamagedTrackVisual, CallFunc_GetAnimInstance_ReturnValue) == 0x000010, "Member 'BP_FV4034_C_UpdateDamagedTrackVisual::CallFunc_GetAnimInstance_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateDamagedTrackVisual, K2Node_DynamicCast_AsFv_4034_Skeleton_Anim_Blueprint) == 0x000018, "Member 'BP_FV4034_C_UpdateDamagedTrackVisual::K2Node_DynamicCast_AsFv_4034_Skeleton_Anim_Blueprint' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateDamagedTrackVisual, K2Node_DynamicCast_bSuccess) == 0x000020, "Member 'BP_FV4034_C_UpdateDamagedTrackVisual::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateDamagedTrackVisual, CallFunc_EqualEqual_ObjectObject_ReturnValue_1) == 0x000021, "Member 'BP_FV4034_C_UpdateDamagedTrackVisual::CallFunc_EqualEqual_ObjectObject_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateDamagedTrackVisual, K2Node_DynamicCast_AsFv_4034_Skeleton_Anim_Blueprint_1) == 0x000028, "Member 'BP_FV4034_C_UpdateDamagedTrackVisual::K2Node_DynamicCast_AsFv_4034_Skeleton_Anim_Blueprint_1' has a wrong offset!");
static_assert(offsetof(BP_FV4034_C_UpdateDamagedTrackVisual, K2Node_DynamicCast_bSuccess_1) == 0x000030, "Member 'BP_FV4034_C_UpdateDamagedTrackVisual::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");

}

