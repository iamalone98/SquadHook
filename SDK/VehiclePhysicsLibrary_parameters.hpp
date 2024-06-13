#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: VehiclePhysicsLibrary

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function VehiclePhysicsLibrary.VehiclePhysicsLibrary_C.ApplyPhysicsFeedback
// 0x0088 (0x0088 - 0x0000)
struct VehiclePhysicsLibrary_C_ApplyPhysicsFeedback final
{
public:
	class AActor*                                 Target;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ForceToApply;                                      // 0x0008(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4F7C[0x4];                                     // 0x000C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UObject*                                __WorldContext;                                    // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 CallFunc_GetOwner_ReturnValue;                     // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4F7D[0x4];                                     // 0x0024(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQVehicleSeat*                         K2Node_DynamicCast_AsSQVehicle_Seat;               // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F7E[0x3];                                     // 0x0031(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                CallFunc_GetActorForwardVector_ReturnValue;        // 0x0034(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQVehicle*                             CallFunc_GetVehicle_ReturnValue;                   // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_Multiply_VectorFloat_ReturnValue;         // 0x0048(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4F7F[0x4];                                     // 0x0054(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQWheeledVehicle*                      K2Node_DynamicCast_AsSQWheeled_Vehicle;            // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F80[0x7];                                     // 0x0061(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQNWheeledVehicle*                     K2Node_DynamicCast_AsSQNWheeled_Vehicle;           // 0x0068(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0070(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F81[0x7];                                     // 0x0071(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQTrackedVehicle*                      K2Node_DynamicCast_AsSQTracked_Vehicle;            // 0x0078(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_3;                     // 0x0080(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback) == 0x000008, "Wrong alignment on VehiclePhysicsLibrary_C_ApplyPhysicsFeedback");
static_assert(sizeof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback) == 0x000088, "Wrong size on VehiclePhysicsLibrary_C_ApplyPhysicsFeedback");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, Target) == 0x000000, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::Target' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, ForceToApply) == 0x000008, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::ForceToApply' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, __WorldContext) == 0x000010, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::__WorldContext' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, CallFunc_GetOwner_ReturnValue) == 0x000018, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::CallFunc_GetOwner_ReturnValue' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x000020, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, K2Node_DynamicCast_AsSQVehicle_Seat) == 0x000028, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::K2Node_DynamicCast_AsSQVehicle_Seat' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, K2Node_DynamicCast_bSuccess) == 0x000030, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, CallFunc_GetActorForwardVector_ReturnValue) == 0x000034, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::CallFunc_GetActorForwardVector_ReturnValue' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, CallFunc_GetVehicle_ReturnValue) == 0x000040, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::CallFunc_GetVehicle_ReturnValue' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, CallFunc_Multiply_VectorFloat_ReturnValue) == 0x000048, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::CallFunc_Multiply_VectorFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, K2Node_DynamicCast_AsSQWheeled_Vehicle) == 0x000058, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::K2Node_DynamicCast_AsSQWheeled_Vehicle' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, K2Node_DynamicCast_bSuccess_1) == 0x000060, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, K2Node_DynamicCast_AsSQNWheeled_Vehicle) == 0x000068, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::K2Node_DynamicCast_AsSQNWheeled_Vehicle' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, K2Node_DynamicCast_bSuccess_2) == 0x000070, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, K2Node_DynamicCast_AsSQTracked_Vehicle) == 0x000078, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::K2Node_DynamicCast_AsSQTracked_Vehicle' has a wrong offset!");
static_assert(offsetof(VehiclePhysicsLibrary_C_ApplyPhysicsFeedback, K2Node_DynamicCast_bSuccess_3) == 0x000080, "Member 'VehiclePhysicsLibrary_C_ApplyPhysicsFeedback::K2Node_DynamicCast_bSuccess_3' has a wrong offset!");

}
