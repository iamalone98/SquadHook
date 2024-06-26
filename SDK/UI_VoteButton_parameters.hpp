#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UI_VoteButton

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function UI_VoteButton.UI_VoteButton_C.VoteSelected__DelegateSignature
// 0x0008 (0x0008 - 0x0000)
struct UI_VoteButton_C_VoteSelected__DelegateSignature final
{
public:
	class FName                                   Param_VoteId;                                      // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(UI_VoteButton_C_VoteSelected__DelegateSignature) == 0x000004, "Wrong alignment on UI_VoteButton_C_VoteSelected__DelegateSignature");
static_assert(sizeof(UI_VoteButton_C_VoteSelected__DelegateSignature) == 0x000008, "Wrong size on UI_VoteButton_C_VoteSelected__DelegateSignature");
static_assert(offsetof(UI_VoteButton_C_VoteSelected__DelegateSignature, Param_VoteId) == 0x000000, "Member 'UI_VoteButton_C_VoteSelected__DelegateSignature::Param_VoteId' has a wrong offset!");

// Function UI_VoteButton.UI_VoteButton_C.ExecuteUbergraph_UI_VoteButton
// 0x0090 (0x0090 - 0x0000)
struct UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3C07[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQVotingComponent*                     CallFunc_GetComponentByClass_ReturnValue;          // 0x0010(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0019(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3C08[0x2];                                     // 0x001A(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   CallFunc_GetPlayerIdentifier_ReturnValue;          // 0x001C(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_ComponentBoundEvent_bSelected;              // 0x0024(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3C09[0x3];                                     // 0x0025(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_MainMenuButton_C*                    K2Node_ComponentBoundEvent_Button;                 // 0x0028(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_NameName_ReturnValue;            // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_ComponentBoundEvent_bHovered;               // 0x0031(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3C0A[0x2];                                     // 0x0032(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	struct FLinearColor                           CallFunc_SelectColor_ReturnValue;                  // 0x0034(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           CallFunc_SelectColor_ReturnValue_1;                // 0x0044(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           K2Node_Select_Default;                             // 0x0054(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3C0B[0x4];                                     // 0x0064(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSlateColor                            K2Node_MakeStruct_SlateColor;                      // 0x0068(0x0028)()
};
static_assert(alignof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton) == 0x000008, "Wrong alignment on UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton");
static_assert(sizeof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton) == 0x000090, "Wrong size on UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton");
static_assert(offsetof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton, EntryPoint) == 0x000000, "Member 'UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton::EntryPoint' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton, CallFunc_GetOwningPlayer_ReturnValue) == 0x000008, "Member 'UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton, CallFunc_GetComponentByClass_ReturnValue) == 0x000010, "Member 'UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton::CallFunc_GetComponentByClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton, Temp_bool_Variable) == 0x000018, "Member 'UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton, CallFunc_IsValid_ReturnValue) == 0x000019, "Member 'UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton, CallFunc_GetPlayerIdentifier_ReturnValue) == 0x00001C, "Member 'UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton::CallFunc_GetPlayerIdentifier_ReturnValue' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton, K2Node_ComponentBoundEvent_bSelected) == 0x000024, "Member 'UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton::K2Node_ComponentBoundEvent_bSelected' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton, K2Node_ComponentBoundEvent_Button) == 0x000028, "Member 'UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton::K2Node_ComponentBoundEvent_Button' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton, CallFunc_NotEqual_NameName_ReturnValue) == 0x000030, "Member 'UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton::CallFunc_NotEqual_NameName_ReturnValue' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton, K2Node_ComponentBoundEvent_bHovered) == 0x000031, "Member 'UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton::K2Node_ComponentBoundEvent_bHovered' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton, CallFunc_SelectColor_ReturnValue) == 0x000034, "Member 'UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton::CallFunc_SelectColor_ReturnValue' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton, CallFunc_SelectColor_ReturnValue_1) == 0x000044, "Member 'UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton::CallFunc_SelectColor_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton, K2Node_Select_Default) == 0x000054, "Member 'UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton, K2Node_MakeStruct_SlateColor) == 0x000068, "Member 'UI_VoteButton_C_ExecuteUbergraph_UI_VoteButton::K2Node_MakeStruct_SlateColor' has a wrong offset!");

// Function UI_VoteButton.UI_VoteButton_C.BndEvt__UI_VoteButton_VoteNone_K2Node_ComponentBoundEvent_0_OnHover__DelegateSignature
// 0x0001 (0x0001 - 0x0000)
struct UI_VoteButton_C_BndEvt__UI_VoteButton_VoteNone_K2Node_ComponentBoundEvent_0_OnHover__DelegateSignature final
{
public:
	bool                                          bHovered;                                          // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(UI_VoteButton_C_BndEvt__UI_VoteButton_VoteNone_K2Node_ComponentBoundEvent_0_OnHover__DelegateSignature) == 0x000001, "Wrong alignment on UI_VoteButton_C_BndEvt__UI_VoteButton_VoteNone_K2Node_ComponentBoundEvent_0_OnHover__DelegateSignature");
static_assert(sizeof(UI_VoteButton_C_BndEvt__UI_VoteButton_VoteNone_K2Node_ComponentBoundEvent_0_OnHover__DelegateSignature) == 0x000001, "Wrong size on UI_VoteButton_C_BndEvt__UI_VoteButton_VoteNone_K2Node_ComponentBoundEvent_0_OnHover__DelegateSignature");
static_assert(offsetof(UI_VoteButton_C_BndEvt__UI_VoteButton_VoteNone_K2Node_ComponentBoundEvent_0_OnHover__DelegateSignature, bHovered) == 0x000000, "Member 'UI_VoteButton_C_BndEvt__UI_VoteButton_VoteNone_K2Node_ComponentBoundEvent_0_OnHover__DelegateSignature::bHovered' has a wrong offset!");

// Function UI_VoteButton.UI_VoteButton_C.BndEvt__UI_VoteNone_VoteNone_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature
// 0x0010 (0x0010 - 0x0000)
struct UI_VoteButton_C_BndEvt__UI_VoteNone_VoteNone_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature final
{
public:
	bool                                          bSelected;                                         // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3C0C[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_MainMenuButton_C*                    Button;                                            // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(UI_VoteButton_C_BndEvt__UI_VoteNone_VoteNone_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature) == 0x000008, "Wrong alignment on UI_VoteButton_C_BndEvt__UI_VoteNone_VoteNone_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature");
static_assert(sizeof(UI_VoteButton_C_BndEvt__UI_VoteNone_VoteNone_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature) == 0x000010, "Wrong size on UI_VoteButton_C_BndEvt__UI_VoteNone_VoteNone_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature");
static_assert(offsetof(UI_VoteButton_C_BndEvt__UI_VoteNone_VoteNone_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature, bSelected) == 0x000000, "Member 'UI_VoteButton_C_BndEvt__UI_VoteNone_VoteNone_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature::bSelected' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_BndEvt__UI_VoteNone_VoteNone_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature, Button) == 0x000008, "Member 'UI_VoteButton_C_BndEvt__UI_VoteNone_VoteNone_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature::Button' has a wrong offset!");

// Function UI_VoteButton.UI_VoteButton_C.OnVoteUpdated
// 0x0010 (0x0010 - 0x0000)
struct UI_VoteButton_C_OnVoteUpdated final
{
public:
	class USQVoteSessionClient*                   VoteSession;                                       // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         PlayerCurrentVotes;                                // 0x0008(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_NameName_ReturnValue;          // 0x000C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(UI_VoteButton_C_OnVoteUpdated) == 0x000008, "Wrong alignment on UI_VoteButton_C_OnVoteUpdated");
static_assert(sizeof(UI_VoteButton_C_OnVoteUpdated) == 0x000010, "Wrong size on UI_VoteButton_C_OnVoteUpdated");
static_assert(offsetof(UI_VoteButton_C_OnVoteUpdated, VoteSession) == 0x000000, "Member 'UI_VoteButton_C_OnVoteUpdated::VoteSession' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_OnVoteUpdated, PlayerCurrentVotes) == 0x000008, "Member 'UI_VoteButton_C_OnVoteUpdated::PlayerCurrentVotes' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_OnVoteUpdated, CallFunc_EqualEqual_NameName_ReturnValue) == 0x00000C, "Member 'UI_VoteButton_C_OnVoteUpdated::CallFunc_EqualEqual_NameName_ReturnValue' has a wrong offset!");

// Function UI_VoteButton.UI_VoteButton_C.MarkSelected
// 0x0040 (0x0040 - 0x0000)
struct UI_VoteButton_C_MarkSelected final
{
public:
	bool                                          Selected;                                          // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          WasSelected;                                       // 0x0001(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3C0D[0x2];                                     // 0x0002(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	struct FLinearColor                           CallFunc_SelectColor_ReturnValue;                  // 0x0004(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3C0E[0x4];                                     // 0x0014(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSlateColor                            K2Node_MakeStruct_SlateColor;                      // 0x0018(0x0028)()
};
static_assert(alignof(UI_VoteButton_C_MarkSelected) == 0x000008, "Wrong alignment on UI_VoteButton_C_MarkSelected");
static_assert(sizeof(UI_VoteButton_C_MarkSelected) == 0x000040, "Wrong size on UI_VoteButton_C_MarkSelected");
static_assert(offsetof(UI_VoteButton_C_MarkSelected, Selected) == 0x000000, "Member 'UI_VoteButton_C_MarkSelected::Selected' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_MarkSelected, WasSelected) == 0x000001, "Member 'UI_VoteButton_C_MarkSelected::WasSelected' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_MarkSelected, CallFunc_SelectColor_ReturnValue) == 0x000004, "Member 'UI_VoteButton_C_MarkSelected::CallFunc_SelectColor_ReturnValue' has a wrong offset!");
static_assert(offsetof(UI_VoteButton_C_MarkSelected, K2Node_MakeStruct_SlateColor) == 0x000018, "Member 'UI_VoteButton_C_MarkSelected::K2Node_MakeStruct_SlateColor' has a wrong offset!");

// Function UI_VoteButton.UI_VoteButton_C.SetDisplayText
// 0x0018 (0x0018 - 0x0000)
struct UI_VoteButton_C_SetDisplayText final
{
public:
	class FText                                   NewText;                                           // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm)
};
static_assert(alignof(UI_VoteButton_C_SetDisplayText) == 0x000008, "Wrong alignment on UI_VoteButton_C_SetDisplayText");
static_assert(sizeof(UI_VoteButton_C_SetDisplayText) == 0x000018, "Wrong size on UI_VoteButton_C_SetDisplayText");
static_assert(offsetof(UI_VoteButton_C_SetDisplayText, NewText) == 0x000000, "Member 'UI_VoteButton_C_SetDisplayText::NewText' has a wrong offset!");

// Function UI_VoteButton.UI_VoteButton_C.SetVotesCount
// 0x0018 (0x0018 - 0x0000)
struct UI_VoteButton_C_SetVotesCount final
{
public:
	class FText                                   VotesText;                                         // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm)
};
static_assert(alignof(UI_VoteButton_C_SetVotesCount) == 0x000008, "Wrong alignment on UI_VoteButton_C_SetVotesCount");
static_assert(sizeof(UI_VoteButton_C_SetVotesCount) == 0x000018, "Wrong size on UI_VoteButton_C_SetVotesCount");
static_assert(offsetof(UI_VoteButton_C_SetVotesCount, VotesText) == 0x000000, "Member 'UI_VoteButton_C_SetVotesCount::VotesText' has a wrong offset!");

}

