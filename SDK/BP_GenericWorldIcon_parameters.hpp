#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericWorldIcon

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function BP_GenericWorldIcon.BP_GenericWorldIcon_C.ExecuteUbergraph_BP_GenericWorldIcon
// 0x0090 (0x0090 - 0x0000)
struct BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void(class AActor* DestroyedActor)> K2Node_CreateDelegate_OutputDelegate;              // 0x0004(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_2D74[0x4];                                     // 0x0014(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UUserWidget*                            CallFunc_GetUserWidgetObject_ReturnValue;          // 0x0018(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_WorldIcon_C*                         K2Node_DynamicCast_AsW_World_Icon;                 // 0x0020(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D75[0x3];                                     // 0x0029(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_1;            // 0x002C(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_2D76[0x4];                                     // 0x003C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue;          // 0x0040(0x0008)(NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Should_Be_Visible_ReturnValue;            // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_NotEqual_BoolBool_ReturnValue;            // 0x0049(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D77[0x6];                                     // 0x004A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 CallFunc_GetAttachParentActor_ReturnValue;         // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D78[0x7];                                     // 0x0059(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 K2Node_CustomEvent_DestroyedActor;                 // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FString                                 CallFunc_GetDisplayName_ReturnValue;               // 0x0068(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FString                                 CallFunc_Concat_StrStr_ReturnValue;                // 0x0078(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	bool                                          K2Node_CustomEvent_Fade_In;                        // 0x0088(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon) == 0x000008, "Wrong alignment on BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon");
static_assert(sizeof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon) == 0x000090, "Wrong size on BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, EntryPoint) == 0x000000, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, K2Node_CreateDelegate_OutputDelegate) == 0x000004, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, CallFunc_GetUserWidgetObject_ReturnValue) == 0x000018, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::CallFunc_GetUserWidgetObject_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, K2Node_DynamicCast_AsW_World_Icon) == 0x000020, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::K2Node_DynamicCast_AsW_World_Icon' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, K2Node_DynamicCast_bSuccess) == 0x000028, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, K2Node_CreateDelegate_OutputDelegate_1) == 0x00002C, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, CallFunc_K2_SetTimerDelegate_ReturnValue) == 0x000040, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::CallFunc_K2_SetTimerDelegate_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, CallFunc_Should_Be_Visible_ReturnValue) == 0x000048, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::CallFunc_Should_Be_Visible_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, CallFunc_NotEqual_BoolBool_ReturnValue) == 0x000049, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::CallFunc_NotEqual_BoolBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, CallFunc_GetAttachParentActor_ReturnValue) == 0x000050, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::CallFunc_GetAttachParentActor_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, CallFunc_IsValid_ReturnValue) == 0x000058, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, K2Node_CustomEvent_DestroyedActor) == 0x000060, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::K2Node_CustomEvent_DestroyedActor' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, CallFunc_GetDisplayName_ReturnValue) == 0x000068, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::CallFunc_GetDisplayName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, CallFunc_Concat_StrStr_ReturnValue) == 0x000078, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::CallFunc_Concat_StrStr_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon, K2Node_CustomEvent_Fade_In) == 0x000088, "Member 'BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon::K2Node_CustomEvent_Fade_In' has a wrong offset!");

// Function BP_GenericWorldIcon.BP_GenericWorldIcon_C.OverrideDoFade
// 0x0001 (0x0001 - 0x0000)
struct BP_GenericWorldIcon_C_OverrideDoFade final
{
public:
	bool                                          Fade_In;                                           // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_GenericWorldIcon_C_OverrideDoFade) == 0x000001, "Wrong alignment on BP_GenericWorldIcon_C_OverrideDoFade");
static_assert(sizeof(BP_GenericWorldIcon_C_OverrideDoFade) == 0x000001, "Wrong size on BP_GenericWorldIcon_C_OverrideDoFade");
static_assert(offsetof(BP_GenericWorldIcon_C_OverrideDoFade, Fade_In) == 0x000000, "Member 'BP_GenericWorldIcon_C_OverrideDoFade::Fade_In' has a wrong offset!");

// Function BP_GenericWorldIcon.BP_GenericWorldIcon_C.OnDestroyed_Event_0
// 0x0008 (0x0008 - 0x0000)
struct BP_GenericWorldIcon_C_OnDestroyed_Event_0 final
{
public:
	class AActor*                                 DestroyedActor;                                    // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericWorldIcon_C_OnDestroyed_Event_0) == 0x000008, "Wrong alignment on BP_GenericWorldIcon_C_OnDestroyed_Event_0");
static_assert(sizeof(BP_GenericWorldIcon_C_OnDestroyed_Event_0) == 0x000008, "Wrong size on BP_GenericWorldIcon_C_OnDestroyed_Event_0");
static_assert(offsetof(BP_GenericWorldIcon_C_OnDestroyed_Event_0, DestroyedActor) == 0x000000, "Member 'BP_GenericWorldIcon_C_OnDestroyed_Event_0::DestroyedActor' has a wrong offset!");

// Function BP_GenericWorldIcon.BP_GenericWorldIcon_C.Should Be Visible
// 0x00F0 (0x00F0 - 0x0000)
struct BP_GenericWorldIcon_C_Should_Be_Visible final
{
public:
	bool                                          ReturnValue;                                       // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D79[0x3];                                     // 0x0001(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Variable;                                 // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x0008(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x0009(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D7A[0x2];                                     // 0x000A(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Variable_1;                               // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetPlayerController_ReturnValue;          // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue_1;          // 0x0019(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanOR_ReturnValue;                    // 0x001A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D7B[0x5];                                     // 0x001B(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class USQGameUserSettings*                    CallFunc_GetSquadGameUserSettings_ReturnValue;     // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Is_Player_Aiming_Down_Sights_ReturnValue; // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue_1;                // 0x0029(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D7C[0x6];                                     // 0x002A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 CallFunc_GetAttachParentActor_ReturnValue;         // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetPlayerController_ReturnValue_1;        // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TScriptInterface<class ISQTeamInterface>      K2Node_DynamicCast_AsSQTeam_Interface;             // 0x0040(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D7D[0x7];                                     // 0x0051(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APawn*                                  CallFunc_K2_GetPawn_ReturnValue;                   // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GetTeamId_ReturnValue;                    // 0x0060(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0064(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D7E[0x3];                                     // 0x0065(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                CallFunc_K2_GetActorLocation_ReturnValue;          // 0x0068(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2D7F[0x4];                                     // 0x0074(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetPlayerController_ReturnValue_2;        // 0x0078(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TScriptInterface<class ISQTeamInterface>      K2Node_DynamicCast_AsSQTeam_Interface_1;           // 0x0080(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0090(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D80[0x3];                                     // 0x0091(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_GetTeamId_ReturnValue_1;                  // 0x0094(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_GetForwardVector_ReturnValue;             // 0x0098(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_K2_GetComponentLocation_ReturnValue;      // 0x00A4(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_Subtract_VectorVector_ReturnValue;        // 0x00B0(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_VSize_ReturnValue;                        // 0x00BC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_Normal_ReturnValue;                       // 0x00C0(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_GreaterEqual_FloatFloat_ReturnValue;      // 0x00CC(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D81[0x3];                                     // 0x00CD(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Dot_VectorVector_ReturnValue;             // 0x00D0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_LessEqual_FloatFloat_ReturnValue;         // 0x00D4(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D82[0x3];                                     // 0x00D5(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_DegAcos_ReturnValue;                      // 0x00D8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x00DC(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D83[0x3];                                     // 0x00DD(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Abs_ReturnValue;                          // 0x00E0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_BooleanAND_ReturnValue_1;                 // 0x00E4(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Less_FloatFloat_ReturnValue;              // 0x00E5(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue_2;                 // 0x00E6(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue_3;                 // 0x00E7(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue_4;                 // 0x00E8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue_5;                 // 0x00E9(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue_6;                 // 0x00EA(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue_7;                 // 0x00EB(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_GenericWorldIcon_C_Should_Be_Visible) == 0x000008, "Wrong alignment on BP_GenericWorldIcon_C_Should_Be_Visible");
static_assert(sizeof(BP_GenericWorldIcon_C_Should_Be_Visible) == 0x0000F0, "Wrong size on BP_GenericWorldIcon_C_Should_Be_Visible");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, ReturnValue) == 0x000000, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, Temp_int_Variable) == 0x000004, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_Not_PreBool_ReturnValue) == 0x000008, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x000009, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, Temp_int_Variable_1) == 0x00000C, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::Temp_int_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_GetPlayerController_ReturnValue) == 0x000010, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_GetPlayerController_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_IsValid_ReturnValue) == 0x000018, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_EqualEqual_IntInt_ReturnValue_1) == 0x000019, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_EqualEqual_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_BooleanOR_ReturnValue) == 0x00001A, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_BooleanOR_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_GetSquadGameUserSettings_ReturnValue) == 0x000020, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_GetSquadGameUserSettings_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_Is_Player_Aiming_Down_Sights_ReturnValue) == 0x000028, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_Is_Player_Aiming_Down_Sights_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_Not_PreBool_ReturnValue_1) == 0x000029, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_Not_PreBool_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_GetAttachParentActor_ReturnValue) == 0x000030, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_GetAttachParentActor_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_GetPlayerController_ReturnValue_1) == 0x000038, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_GetPlayerController_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, K2Node_DynamicCast_AsSQTeam_Interface) == 0x000040, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::K2Node_DynamicCast_AsSQTeam_Interface' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, K2Node_DynamicCast_bSuccess) == 0x000050, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_K2_GetPawn_ReturnValue) == 0x000058, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_K2_GetPawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_GetTeamId_ReturnValue) == 0x000060, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_GetTeamId_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_IsValid_ReturnValue_1) == 0x000064, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_K2_GetActorLocation_ReturnValue) == 0x000068, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_K2_GetActorLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_GetPlayerController_ReturnValue_2) == 0x000078, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_GetPlayerController_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, K2Node_DynamicCast_AsSQTeam_Interface_1) == 0x000080, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::K2Node_DynamicCast_AsSQTeam_Interface_1' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, K2Node_DynamicCast_bSuccess_1) == 0x000090, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_GetTeamId_ReturnValue_1) == 0x000094, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_GetTeamId_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_GetForwardVector_ReturnValue) == 0x000098, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_GetForwardVector_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_K2_GetComponentLocation_ReturnValue) == 0x0000A4, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_K2_GetComponentLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_Subtract_VectorVector_ReturnValue) == 0x0000B0, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_Subtract_VectorVector_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_VSize_ReturnValue) == 0x0000BC, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_VSize_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_Normal_ReturnValue) == 0x0000C0, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_Normal_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_GreaterEqual_FloatFloat_ReturnValue) == 0x0000CC, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_GreaterEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_Dot_VectorVector_ReturnValue) == 0x0000D0, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_Dot_VectorVector_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_LessEqual_FloatFloat_ReturnValue) == 0x0000D4, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_LessEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_DegAcos_ReturnValue) == 0x0000D8, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_DegAcos_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_BooleanAND_ReturnValue) == 0x0000DC, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_Abs_ReturnValue) == 0x0000E0, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_Abs_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_BooleanAND_ReturnValue_1) == 0x0000E4, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_BooleanAND_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_Less_FloatFloat_ReturnValue) == 0x0000E5, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_Less_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_BooleanAND_ReturnValue_2) == 0x0000E6, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_BooleanAND_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_BooleanAND_ReturnValue_3) == 0x0000E7, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_BooleanAND_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_BooleanAND_ReturnValue_4) == 0x0000E8, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_BooleanAND_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_BooleanAND_ReturnValue_5) == 0x0000E9, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_BooleanAND_ReturnValue_5' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_BooleanAND_ReturnValue_6) == 0x0000EA, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_BooleanAND_ReturnValue_6' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Should_Be_Visible, CallFunc_BooleanAND_ReturnValue_7) == 0x0000EB, "Member 'BP_GenericWorldIcon_C_Should_Be_Visible::CallFunc_BooleanAND_ReturnValue_7' has a wrong offset!");

// Function BP_GenericWorldIcon.BP_GenericWorldIcon_C.Is Player Aiming Down Sights
// 0x0028 (0x0028 - 0x0000)
struct BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights final
{
public:
	bool                                          ReturnValue;                                       // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D84[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetPlayerController_ReturnValue;          // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APawn*                                  CallFunc_K2_GetPawn_ReturnValue;                   // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQSoldier*                             K2Node_DynamicCast_AsSQSoldier;                    // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsAimingDownSights_ReturnValue;           // 0x0021(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights) == 0x000008, "Wrong alignment on BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights");
static_assert(sizeof(BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights) == 0x000028, "Wrong size on BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights");
static_assert(offsetof(BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights, ReturnValue) == 0x000000, "Member 'BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights, CallFunc_GetPlayerController_ReturnValue) == 0x000008, "Member 'BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights::CallFunc_GetPlayerController_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights, CallFunc_K2_GetPawn_ReturnValue) == 0x000010, "Member 'BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights::CallFunc_K2_GetPawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights, K2Node_DynamicCast_AsSQSoldier) == 0x000018, "Member 'BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights::K2Node_DynamicCast_AsSQSoldier' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights, K2Node_DynamicCast_bSuccess) == 0x000020, "Member 'BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights, CallFunc_IsAimingDownSights_ReturnValue) == 0x000021, "Member 'BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights::CallFunc_IsAimingDownSights_ReturnValue' has a wrong offset!");

}
