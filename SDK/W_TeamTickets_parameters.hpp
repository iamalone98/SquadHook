#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_TeamTickets

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "SQFactionEntry_structs.hpp"


namespace SDK::Params
{

// Function W_TeamTickets.W_TeamTickets_C.ExecuteUbergraph_W_TeamTickets
// 0x00C8 (0x00C8 - 0x0000)
struct W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2CD3[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue;                // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsAnimationPlaying_ReturnValue;           // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Array_IsValidIndex_ReturnValue;           // 0x0011(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_NotEqual_IntInt_ReturnValue;              // 0x0012(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2CD4[0x1];                                     // 0x0013(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Abs_Int_ReturnValue;                      // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0018(0x0040)(HasGetValueTypeHash)
	class ASQPlayerState*                         CallFunc_TryGetLocalPlayerState_OutPlayerState;    // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetLocalPlayerState_ReturnValue;       // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2CD5[0x7];                                     // 0x0061(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0068(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x0078(0x0018)()
	bool                                          CallFunc_UpdateCurrentTeam_TeamChanged;            // 0x0090(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2CD6[0x3];                                     // 0x0091(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0094(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_2CD7[0x4];                                     // 0x00A4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue;          // 0x00A8(0x0008)(NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_GetBleedComponent_IsValid;                // 0x00B0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2CD8[0x7];                                     // 0x00B1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UGraphNodeBasedBleedComponent_C*        CallFunc_GetBleedComponent_BleedComponent;         // 0x00B8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x00C0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x00C1(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x00C2(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue_1;                 // 0x00C3(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets) == 0x000008, "Wrong alignment on W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets");
static_assert(sizeof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets) == 0x0000C8, "Wrong size on W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, EntryPoint) == 0x000000, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_PlayAnimation_ReturnValue) == 0x000008, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_PlayAnimation_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_IsAnimationPlaying_ReturnValue) == 0x000010, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_IsAnimationPlaying_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_Array_IsValidIndex_ReturnValue) == 0x000011, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_Array_IsValidIndex_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_NotEqual_IntInt_ReturnValue) == 0x000012, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_NotEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_Abs_Int_ReturnValue) == 0x000014, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_Abs_Int_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, K2Node_MakeStruct_FormatArgumentData) == 0x000018, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_TryGetLocalPlayerState_OutPlayerState) == 0x000058, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_TryGetLocalPlayerState_OutPlayerState' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_TryGetLocalPlayerState_ReturnValue) == 0x000060, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_TryGetLocalPlayerState_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, K2Node_MakeArray_Array) == 0x000068, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_Format_ReturnValue) == 0x000078, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_UpdateCurrentTeam_TeamChanged) == 0x000090, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_UpdateCurrentTeam_TeamChanged' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, K2Node_CreateDelegate_OutputDelegate) == 0x000094, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_K2_SetTimerDelegate_ReturnValue) == 0x0000A8, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_K2_SetTimerDelegate_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_GetBleedComponent_IsValid) == 0x0000B0, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_GetBleedComponent_IsValid' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_GetBleedComponent_BleedComponent) == 0x0000B8, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_GetBleedComponent_BleedComponent' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_IsValid_ReturnValue) == 0x0000C0, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_IsValid_ReturnValue_1) == 0x0000C1, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_BooleanAND_ReturnValue) == 0x0000C2, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets, CallFunc_BooleanAND_ReturnValue_1) == 0x0000C3, "Member 'W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets::CallFunc_BooleanAND_ReturnValue_1' has a wrong offset!");

// Function W_TeamTickets.W_TeamTickets_C.GetBleedComponent
// 0x0048 (0x0048 - 0x0000)
struct W_TeamTickets_C_GetBleedComponent final
{
public:
	bool                                          IsValid;                                           // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2CD9[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UGraphNodeBasedBleedComponent_C*        BleedComponent;                                    // 0x0008(0x0008)(Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2CDA[0x7];                                     // 0x0011(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class ASQAASGraph*>                    CallFunc_GetAllActorsOfClass_OutActors;            // 0x0018(0x0010)(ReferenceParm)
	bool                                          CallFunc_Array_IsValidIndex_ReturnValue;           // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2CDB[0x7];                                     // 0x0029(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQAASGraph*                            CallFunc_Array_Get_Item;                           // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UGraphNodeBasedBleedComponent_C*        CallFunc_GetComponentByClass_ReturnValue;          // 0x0038(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_TeamTickets_C_GetBleedComponent) == 0x000008, "Wrong alignment on W_TeamTickets_C_GetBleedComponent");
static_assert(sizeof(W_TeamTickets_C_GetBleedComponent) == 0x000048, "Wrong size on W_TeamTickets_C_GetBleedComponent");
static_assert(offsetof(W_TeamTickets_C_GetBleedComponent, IsValid) == 0x000000, "Member 'W_TeamTickets_C_GetBleedComponent::IsValid' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_GetBleedComponent, BleedComponent) == 0x000008, "Member 'W_TeamTickets_C_GetBleedComponent::BleedComponent' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_GetBleedComponent, CallFunc_IsValid_ReturnValue) == 0x000010, "Member 'W_TeamTickets_C_GetBleedComponent::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_GetBleedComponent, CallFunc_GetAllActorsOfClass_OutActors) == 0x000018, "Member 'W_TeamTickets_C_GetBleedComponent::CallFunc_GetAllActorsOfClass_OutActors' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_GetBleedComponent, CallFunc_Array_IsValidIndex_ReturnValue) == 0x000028, "Member 'W_TeamTickets_C_GetBleedComponent::CallFunc_Array_IsValidIndex_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_GetBleedComponent, CallFunc_Array_Get_Item) == 0x000030, "Member 'W_TeamTickets_C_GetBleedComponent::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_GetBleedComponent, CallFunc_GetComponentByClass_ReturnValue) == 0x000038, "Member 'W_TeamTickets_C_GetBleedComponent::CallFunc_GetComponentByClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_GetBleedComponent, CallFunc_IsValid_ReturnValue_1) == 0x000040, "Member 'W_TeamTickets_C_GetBleedComponent::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");

// Function W_TeamTickets.W_TeamTickets_C.UpdateCurrentTeam
// 0x0018 (0x0018 - 0x0000)
struct W_TeamTickets_C_UpdateCurrentTeam final
{
public:
	bool                                          TeamChanged;                                       // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0001(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2CDC[0x6];                                     // 0x0002(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQTeamState*                           CallFunc_GetTeamState_ReturnValue;                 // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsConfigured_ReturnValue;                 // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_NotEqual_ObjectObject_ReturnValue;        // 0x0011(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0012(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x0013(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_TeamTickets_C_UpdateCurrentTeam) == 0x000008, "Wrong alignment on W_TeamTickets_C_UpdateCurrentTeam");
static_assert(sizeof(W_TeamTickets_C_UpdateCurrentTeam) == 0x000018, "Wrong size on W_TeamTickets_C_UpdateCurrentTeam");
static_assert(offsetof(W_TeamTickets_C_UpdateCurrentTeam, TeamChanged) == 0x000000, "Member 'W_TeamTickets_C_UpdateCurrentTeam::TeamChanged' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_UpdateCurrentTeam, CallFunc_IsValid_ReturnValue) == 0x000001, "Member 'W_TeamTickets_C_UpdateCurrentTeam::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_UpdateCurrentTeam, CallFunc_GetTeamState_ReturnValue) == 0x000008, "Member 'W_TeamTickets_C_UpdateCurrentTeam::CallFunc_GetTeamState_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_UpdateCurrentTeam, CallFunc_IsConfigured_ReturnValue) == 0x000010, "Member 'W_TeamTickets_C_UpdateCurrentTeam::CallFunc_IsConfigured_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_UpdateCurrentTeam, CallFunc_NotEqual_ObjectObject_ReturnValue) == 0x000011, "Member 'W_TeamTickets_C_UpdateCurrentTeam::CallFunc_NotEqual_ObjectObject_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_UpdateCurrentTeam, CallFunc_IsValid_ReturnValue_1) == 0x000012, "Member 'W_TeamTickets_C_UpdateCurrentTeam::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_UpdateCurrentTeam, CallFunc_BooleanAND_ReturnValue) == 0x000013, "Member 'W_TeamTickets_C_UpdateCurrentTeam::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");

// Function W_TeamTickets.W_TeamTickets_C.UpdateTickets
// 0x0020 (0x0020 - 0x0000)
struct W_TeamTickets_C_UpdateTickets final
{
public:
	int32                                         CallFunc_GetTickets_ReturnValue;                   // 0x0000(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2CDD[0x3];                                     // 0x0005(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_IntToText_ReturnValue;               // 0x0008(0x0018)()
};
static_assert(alignof(W_TeamTickets_C_UpdateTickets) == 0x000008, "Wrong alignment on W_TeamTickets_C_UpdateTickets");
static_assert(sizeof(W_TeamTickets_C_UpdateTickets) == 0x000020, "Wrong size on W_TeamTickets_C_UpdateTickets");
static_assert(offsetof(W_TeamTickets_C_UpdateTickets, CallFunc_GetTickets_ReturnValue) == 0x000000, "Member 'W_TeamTickets_C_UpdateTickets::CallFunc_GetTickets_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_UpdateTickets, CallFunc_IsValid_ReturnValue) == 0x000004, "Member 'W_TeamTickets_C_UpdateTickets::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_UpdateTickets, CallFunc_Conv_IntToText_ReturnValue) == 0x000008, "Member 'W_TeamTickets_C_UpdateTickets::CallFunc_Conv_IntToText_ReturnValue' has a wrong offset!");

// Function W_TeamTickets.W_TeamTickets_C.UpdateFlag
// 0x0590 (0x0590 - 0x0000)
struct W_TeamTickets_C_UpdateFlag final
{
public:
	class UBP_SQFaction_C*                        CallFunc_TryGetLocalPlayerFaction_OutFaction;      // 0x0000(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetLocalPlayerFaction_ReturnValue;     // 0x0008(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_TryGetFactionEntry_Success;               // 0x0009(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2CDE[0x6];                                     // 0x000A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQFactionEntry                        CallFunc_TryGetFactionEntry_FactionEntry;          // 0x0010(0x0580)(HasGetValueTypeHash)
};
static_assert(alignof(W_TeamTickets_C_UpdateFlag) == 0x000008, "Wrong alignment on W_TeamTickets_C_UpdateFlag");
static_assert(sizeof(W_TeamTickets_C_UpdateFlag) == 0x000590, "Wrong size on W_TeamTickets_C_UpdateFlag");
static_assert(offsetof(W_TeamTickets_C_UpdateFlag, CallFunc_TryGetLocalPlayerFaction_OutFaction) == 0x000000, "Member 'W_TeamTickets_C_UpdateFlag::CallFunc_TryGetLocalPlayerFaction_OutFaction' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_UpdateFlag, CallFunc_TryGetLocalPlayerFaction_ReturnValue) == 0x000008, "Member 'W_TeamTickets_C_UpdateFlag::CallFunc_TryGetLocalPlayerFaction_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_UpdateFlag, CallFunc_TryGetFactionEntry_Success) == 0x000009, "Member 'W_TeamTickets_C_UpdateFlag::CallFunc_TryGetFactionEntry_Success' has a wrong offset!");
static_assert(offsetof(W_TeamTickets_C_UpdateFlag, CallFunc_TryGetFactionEntry_FactionEntry) == 0x000010, "Member 'W_TeamTickets_C_UpdateFlag::CallFunc_TryGetFactionEntry_FactionEntry' has a wrong offset!");

}

