#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: FV4034_Ammocook

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function FV4034_Ammocook.FV4034_Ammocook_C.ExecuteUbergraph_FV4034_Ammocook
// 0x0170 (0x0170 - 0x0000)
struct FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_GetComponentVelocity_ReturnValue;         // 0x0004(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_X;                            // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y;                            // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z;                            // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_IsClosed_Variable;                       // 0x001C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_403F[0x3];                                     // 0x001D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                CallFunc_Conv_FloatToVector_ReturnValue;           // 0x0020(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_VSize_ReturnValue;                        // 0x002C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_FClamp_ReturnValue;                       // 0x0034(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Has_Been_Initd_Variable;                 // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4040[0x3];                                     // 0x0039(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_RandomFloatInRange_ReturnValue;           // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPrimitiveComponent*                    K2Node_ComponentBoundEvent_HitComponent;           // 0x0040(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 K2Node_ComponentBoundEvent_OtherActor;             // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPrimitiveComponent*                    K2Node_ComponentBoundEvent_OtherComp;              // 0x0050(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                K2Node_ComponentBoundEvent_NormalImpulse;          // 0x0058(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FHitResult                             K2Node_ComponentBoundEvent_Hit;                    // 0x0064(0x0088)(ConstParm, IsPlainOldData, NoDestructor, ContainsInstancedReference)
	bool                                          CallFunc_BreakHitResult_bBlockingHit;              // 0x00EC(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BreakHitResult_bInitialOverlap;           // 0x00ED(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4041[0x2];                                     // 0x00EE(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_BreakHitResult_Time;                      // 0x00F0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakHitResult_Distance;                  // 0x00F4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_BreakHitResult_Location;                  // 0x00F8(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_BreakHitResult_ImpactPoint;               // 0x0104(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_BreakHitResult_Normal;                    // 0x0110(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_BreakHitResult_ImpactNormal;              // 0x011C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPhysicalMaterial*                      CallFunc_BreakHitResult_PhysMat;                   // 0x0128(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 CallFunc_BreakHitResult_HitActor;                  // 0x0130(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPrimitiveComponent*                    CallFunc_BreakHitResult_HitComponent;              // 0x0138(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   CallFunc_BreakHitResult_HitBoneName;               // 0x0140(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakHitResult_HitItem;                   // 0x0148(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakHitResult_ElementIndex;              // 0x014C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakHitResult_FaceIndex;                 // 0x0150(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_BreakHitResult_TraceStart;                // 0x0154(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_BreakHitResult_TraceEnd;                  // 0x0160(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook) == 0x000008, "Wrong alignment on FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook");
static_assert(sizeof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook) == 0x000170, "Wrong size on FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, EntryPoint) == 0x000000, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::EntryPoint' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_GetComponentVelocity_ReturnValue) == 0x000004, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_GetComponentVelocity_ReturnValue' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakVector_X) == 0x000010, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakVector_X' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakVector_Y) == 0x000014, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakVector_Y' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakVector_Z) == 0x000018, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakVector_Z' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, Temp_bool_IsClosed_Variable) == 0x00001C, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::Temp_bool_IsClosed_Variable' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_Conv_FloatToVector_ReturnValue) == 0x000020, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_Conv_FloatToVector_ReturnValue' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_VSize_ReturnValue) == 0x00002C, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_VSize_ReturnValue' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_Divide_FloatFloat_ReturnValue) == 0x000030, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_FClamp_ReturnValue) == 0x000034, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_FClamp_ReturnValue' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, Temp_bool_Has_Been_Initd_Variable) == 0x000038, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::Temp_bool_Has_Been_Initd_Variable' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_RandomFloatInRange_ReturnValue) == 0x00003C, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_RandomFloatInRange_ReturnValue' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, K2Node_ComponentBoundEvent_HitComponent) == 0x000040, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::K2Node_ComponentBoundEvent_HitComponent' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, K2Node_ComponentBoundEvent_OtherActor) == 0x000048, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::K2Node_ComponentBoundEvent_OtherActor' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, K2Node_ComponentBoundEvent_OtherComp) == 0x000050, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::K2Node_ComponentBoundEvent_OtherComp' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, K2Node_ComponentBoundEvent_NormalImpulse) == 0x000058, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::K2Node_ComponentBoundEvent_NormalImpulse' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, K2Node_ComponentBoundEvent_Hit) == 0x000064, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::K2Node_ComponentBoundEvent_Hit' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_bBlockingHit) == 0x0000EC, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_bBlockingHit' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_bInitialOverlap) == 0x0000ED, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_bInitialOverlap' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_Time) == 0x0000F0, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_Time' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_Distance) == 0x0000F4, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_Distance' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_Location) == 0x0000F8, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_Location' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_ImpactPoint) == 0x000104, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_ImpactPoint' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_Normal) == 0x000110, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_Normal' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_ImpactNormal) == 0x00011C, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_ImpactNormal' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_PhysMat) == 0x000128, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_PhysMat' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_HitActor) == 0x000130, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_HitActor' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_HitComponent) == 0x000138, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_HitComponent' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_HitBoneName) == 0x000140, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_HitBoneName' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_HitItem) == 0x000148, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_HitItem' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_ElementIndex) == 0x00014C, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_ElementIndex' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_FaceIndex) == 0x000150, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_FaceIndex' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_TraceStart) == 0x000154, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_TraceStart' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook, CallFunc_BreakHitResult_TraceEnd) == 0x000160, "Member 'FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook::CallFunc_BreakHitResult_TraceEnd' has a wrong offset!");

// Function FV4034_Ammocook.FV4034_Ammocook_C.BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature
// 0x00B0 (0x00B0 - 0x0000)
struct FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature final
{
public:
	class UPrimitiveComponent*                    HitComponent;                                      // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 OtherActor;                                        // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPrimitiveComponent*                    OtherComp;                                         // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                NormalImpulse;                                     // 0x0018(0x000C)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FHitResult                             Hit;                                               // 0x0024(0x0088)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, IsPlainOldData, NoDestructor, ContainsInstancedReference)
};
static_assert(alignof(FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature) == 0x000008, "Wrong alignment on FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature");
static_assert(sizeof(FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature) == 0x0000B0, "Wrong size on FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature");
static_assert(offsetof(FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature, HitComponent) == 0x000000, "Member 'FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature::HitComponent' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature, OtherActor) == 0x000008, "Member 'FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature::OtherActor' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature, OtherComp) == 0x000010, "Member 'FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature::OtherComp' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature, NormalImpulse) == 0x000018, "Member 'FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature::NormalImpulse' has a wrong offset!");
static_assert(offsetof(FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature, Hit) == 0x000024, "Member 'FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature::Hit' has a wrong offset!");

}

