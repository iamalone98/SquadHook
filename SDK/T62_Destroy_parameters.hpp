#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: T62_Destroy

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function T62_Destroy.T62_Destroy_C.ExecuteUbergraph_T62_Destroy
// 0x0170 (0x0170 - 0x0000)
struct T62_Destroy_C_ExecuteUbergraph_T62_Destroy final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3635[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UPrimitiveComponent*                    K2Node_ComponentBoundEvent_HitComponent;           // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 K2Node_ComponentBoundEvent_OtherActor;             // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPrimitiveComponent*                    K2Node_ComponentBoundEvent_OtherComp;              // 0x0018(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                K2Node_ComponentBoundEvent_NormalImpulse;          // 0x0020(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FHitResult                             K2Node_ComponentBoundEvent_Hit;                    // 0x002C(0x0088)(ConstParm, IsPlainOldData, NoDestructor, ContainsInstancedReference)
	bool                                          CallFunc_BreakHitResult_bBlockingHit;              // 0x00B4(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BreakHitResult_bInitialOverlap;           // 0x00B5(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3636[0x2];                                     // 0x00B6(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_BreakHitResult_Time;                      // 0x00B8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakHitResult_Distance;                  // 0x00BC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_BreakHitResult_Location;                  // 0x00C0(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_BreakHitResult_ImpactPoint;               // 0x00CC(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_BreakHitResult_Normal;                    // 0x00D8(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_BreakHitResult_ImpactNormal;              // 0x00E4(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPhysicalMaterial*                      CallFunc_BreakHitResult_PhysMat;                   // 0x00F0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 CallFunc_BreakHitResult_HitActor;                  // 0x00F8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPrimitiveComponent*                    CallFunc_BreakHitResult_HitComponent;              // 0x0100(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   CallFunc_BreakHitResult_HitBoneName;               // 0x0108(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakHitResult_HitItem;                   // 0x0110(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakHitResult_ElementIndex;              // 0x0114(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakHitResult_FaceIndex;                 // 0x0118(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_BreakHitResult_TraceStart;                // 0x011C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_BreakHitResult_TraceEnd;                  // 0x0128(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_IsClosed_Variable;                       // 0x0134(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          Temp_bool_Has_Been_Initd_Variable;                 // 0x0135(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3637[0x2];                                     // 0x0136(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_RandomFloatInRange_ReturnValue;           // 0x0138(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_GetComponentVelocity_ReturnValue;         // 0x013C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_X;                            // 0x0148(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y;                            // 0x014C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z;                            // 0x0150(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_Conv_FloatToVector_ReturnValue;           // 0x0154(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_VSize_ReturnValue;                        // 0x0160(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x0164(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_FClamp_ReturnValue;                       // 0x0168(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy) == 0x000008, "Wrong alignment on T62_Destroy_C_ExecuteUbergraph_T62_Destroy");
static_assert(sizeof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy) == 0x000170, "Wrong size on T62_Destroy_C_ExecuteUbergraph_T62_Destroy");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, EntryPoint) == 0x000000, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::EntryPoint' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, K2Node_ComponentBoundEvent_HitComponent) == 0x000008, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::K2Node_ComponentBoundEvent_HitComponent' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, K2Node_ComponentBoundEvent_OtherActor) == 0x000010, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::K2Node_ComponentBoundEvent_OtherActor' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, K2Node_ComponentBoundEvent_OtherComp) == 0x000018, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::K2Node_ComponentBoundEvent_OtherComp' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, K2Node_ComponentBoundEvent_NormalImpulse) == 0x000020, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::K2Node_ComponentBoundEvent_NormalImpulse' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, K2Node_ComponentBoundEvent_Hit) == 0x00002C, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::K2Node_ComponentBoundEvent_Hit' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_bBlockingHit) == 0x0000B4, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_bBlockingHit' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_bInitialOverlap) == 0x0000B5, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_bInitialOverlap' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_Time) == 0x0000B8, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_Time' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_Distance) == 0x0000BC, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_Distance' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_Location) == 0x0000C0, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_Location' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_ImpactPoint) == 0x0000CC, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_ImpactPoint' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_Normal) == 0x0000D8, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_Normal' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_ImpactNormal) == 0x0000E4, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_ImpactNormal' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_PhysMat) == 0x0000F0, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_PhysMat' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_HitActor) == 0x0000F8, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_HitActor' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_HitComponent) == 0x000100, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_HitComponent' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_HitBoneName) == 0x000108, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_HitBoneName' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_HitItem) == 0x000110, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_HitItem' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_ElementIndex) == 0x000114, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_ElementIndex' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_FaceIndex) == 0x000118, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_FaceIndex' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_TraceStart) == 0x00011C, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_TraceStart' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakHitResult_TraceEnd) == 0x000128, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakHitResult_TraceEnd' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, Temp_bool_IsClosed_Variable) == 0x000134, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::Temp_bool_IsClosed_Variable' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, Temp_bool_Has_Been_Initd_Variable) == 0x000135, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::Temp_bool_Has_Been_Initd_Variable' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_RandomFloatInRange_ReturnValue) == 0x000138, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_RandomFloatInRange_ReturnValue' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_GetComponentVelocity_ReturnValue) == 0x00013C, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_GetComponentVelocity_ReturnValue' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakVector_X) == 0x000148, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakVector_X' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakVector_Y) == 0x00014C, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakVector_Y' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_BreakVector_Z) == 0x000150, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_BreakVector_Z' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_Conv_FloatToVector_ReturnValue) == 0x000154, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_Conv_FloatToVector_ReturnValue' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_VSize_ReturnValue) == 0x000160, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_VSize_ReturnValue' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_Divide_FloatFloat_ReturnValue) == 0x000164, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_ExecuteUbergraph_T62_Destroy, CallFunc_FClamp_ReturnValue) == 0x000168, "Member 'T62_Destroy_C_ExecuteUbergraph_T62_Destroy::CallFunc_FClamp_ReturnValue' has a wrong offset!");

// Function T62_Destroy.T62_Destroy_C.BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature
// 0x00B0 (0x00B0 - 0x0000)
struct T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature final
{
public:
	class UPrimitiveComponent*                    HitComponent;                                      // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 OtherActor;                                        // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPrimitiveComponent*                    OtherComp;                                         // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                NormalImpulse;                                     // 0x0018(0x000C)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FHitResult                             Hit;                                               // 0x0024(0x0088)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, IsPlainOldData, NoDestructor, ContainsInstancedReference)
};
static_assert(alignof(T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature) == 0x000008, "Wrong alignment on T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature");
static_assert(sizeof(T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature) == 0x0000B0, "Wrong size on T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature");
static_assert(offsetof(T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature, HitComponent) == 0x000000, "Member 'T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature::HitComponent' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature, OtherActor) == 0x000008, "Member 'T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature::OtherActor' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature, OtherComp) == 0x000010, "Member 'T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature::OtherComp' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature, NormalImpulse) == 0x000018, "Member 'T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature::NormalImpulse' has a wrong offset!");
static_assert(offsetof(T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature, Hit) == 0x000024, "Member 'T62_Destroy_C_BndEvt__T62_Destroy_SQVehicleWreckTurret_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature::Hit' has a wrong offset!");

}

