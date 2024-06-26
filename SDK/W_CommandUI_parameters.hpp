#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_CommandUI

#include "Basic.hpp"

#include "Squad_structs.hpp"
#include "Engine_structs.hpp"
#include "UMG_structs.hpp"


namespace SDK::Params
{

// Function W_CommandUI.W_CommandUI_C.ExecuteUbergraph_W_CommandUI
// 0x0130 (0x0130 - 0x0000)
struct W_CommandUI_C_ExecuteUbergraph_W_CommandUI final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsAnimationPlayingForward_ReturnValue;    // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_36F9[0x3];                                     // 0x0005(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0008(0x0010)(ZeroConstructor, NoDestructor)
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue;          // 0x0018(0x0008)(NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_36FA[0x3];                                     // 0x0021(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void(class ASQPlayerState* OldCommander, class ASQPlayerState* NewCommander)> K2Node_CreateDelegate_OutputDelegate_1;            // 0x0024(0x0010)(ZeroConstructor, NoDestructor)
	float                                         Temp_float_Variable;                               // 0x0034(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Temp_float_Variable_1;                             // 0x0038(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable_1;                              // 0x003C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESlateVisibility                              Temp_byte_Variable;                                // 0x003D(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              Temp_byte_Variable_1;                              // 0x003E(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_Event_IsDesignTime;                         // 0x003F(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	class USaveData_UI_C*                         CallFunc_Get_UI_Save_Data_UI_Save_Data;            // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESQChat                                       K2Node_CustomEvent_Channel;                        // 0x0059(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_36FB[0x6];                                     // 0x005A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_CommandActionList_C*                 K2Node_DynamicCast_AsW_Command_Action_List;        // 0x0060(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_36FC[0x7];                                     // 0x0069(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_ChatBox_C*                           K2Node_DynamicCast_AsW_Chat_Box;                   // 0x0070(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0078(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_36FD[0x3];                                     // 0x0079(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void(ESQChat Channel)>              K2Node_CreateDelegate_OutputDelegate_2;            // 0x007C(0x0010)(ZeroConstructor, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x008C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x008D(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_36FE[0x2];                                     // 0x008E(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerState*                         K2Node_CustomEvent_OldCommander;                   // 0x0090(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerState*                         K2Node_CustomEvent_NewCommander;                   // 0x0098(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsVisible_ReturnValue;                    // 0x00A0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_36FF[0x3];                                     // 0x00A1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         K2Node_Select_Default;                             // 0x00A4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              K2Node_Select_Default_1;                           // 0x00A8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3700[0x7];                                     // 0x00A9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue_1;            // 0x00B0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPanelWidget*                           CallFunc_Get_Squad_List_Roots_Squad_Panel;         // 0x00B8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPanelWidget*                           CallFunc_Get_Squad_List_Roots_Unassigned_Panel;    // 0x00C0(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPanelWidget*                           CallFunc_Get_Squad_List_Roots_Commander_Panel;     // 0x00C8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AHUD*                                   CallFunc_GetHUD_ReturnValue;                       // 0x00D0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ABP_HUD_C*                              K2Node_DynamicCast_AsBP_HUD;                       // 0x00D8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_3;                     // 0x00E0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3701[0x7];                                     // 0x00E1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    CallFunc_GetSquadPlayerController_Return_Value;    // 0x00E8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APawn*                                  CallFunc_K2_GetPawn_ReturnValue;                   // 0x00F0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AHUD*                                   CallFunc_GetHUD_ReturnValue_1;                     // 0x00F8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x0100(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3702[0x7];                                     // 0x0101(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TScriptInterface<class IBPI_HUD_C>            K2Node_DynamicCast_AsBPI_HUD;                      // 0x0108(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess_4;                     // 0x0118(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3703[0x7];                                     // 0x0119(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_PlayerController_C*                 K2Node_DynamicCast_AsBP_Player_Controller;         // 0x0120(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_5;                     // 0x0128(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x0129(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI) == 0x000008, "Wrong alignment on W_CommandUI_C_ExecuteUbergraph_W_CommandUI");
static_assert(sizeof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI) == 0x000130, "Wrong size on W_CommandUI_C_ExecuteUbergraph_W_CommandUI");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, EntryPoint) == 0x000000, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_IsAnimationPlayingForward_ReturnValue) == 0x000004, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_IsAnimationPlayingForward_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_CreateDelegate_OutputDelegate) == 0x000008, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_K2_SetTimerDelegate_ReturnValue) == 0x000018, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_K2_SetTimerDelegate_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, Temp_bool_Variable) == 0x000020, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_CreateDelegate_OutputDelegate_1) == 0x000024, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, Temp_float_Variable) == 0x000034, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::Temp_float_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, Temp_float_Variable_1) == 0x000038, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::Temp_float_Variable_1' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, Temp_bool_Variable_1) == 0x00003C, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::Temp_bool_Variable_1' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, Temp_byte_Variable) == 0x00003D, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, Temp_byte_Variable_1) == 0x00003E, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::Temp_byte_Variable_1' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_Event_IsDesignTime) == 0x00003F, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_Event_IsDesignTime' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_Get_UI_Save_Data_UI_Save_Data) == 0x000040, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_Get_UI_Save_Data_UI_Save_Data' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_GetOwningPlayer_ReturnValue) == 0x000048, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000050, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_DynamicCast_bSuccess) == 0x000058, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_CustomEvent_Channel) == 0x000059, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_CustomEvent_Channel' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_DynamicCast_AsW_Command_Action_List) == 0x000060, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_DynamicCast_AsW_Command_Action_List' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_DynamicCast_bSuccess_1) == 0x000068, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_DynamicCast_AsW_Chat_Box) == 0x000070, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_DynamicCast_AsW_Chat_Box' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_DynamicCast_bSuccess_2) == 0x000078, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_CreateDelegate_OutputDelegate_2) == 0x00007C, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_CreateDelegate_OutputDelegate_2' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_IsValid_ReturnValue) == 0x00008C, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_IsValid_ReturnValue_1) == 0x00008D, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_CustomEvent_OldCommander) == 0x000090, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_CustomEvent_OldCommander' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_CustomEvent_NewCommander) == 0x000098, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_CustomEvent_NewCommander' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_IsVisible_ReturnValue) == 0x0000A0, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_IsVisible_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_Select_Default) == 0x0000A4, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_Select_Default_1) == 0x0000A8, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_Select_Default_1' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_GetOwningPlayer_ReturnValue_1) == 0x0000B0, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_GetOwningPlayer_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_Get_Squad_List_Roots_Squad_Panel) == 0x0000B8, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_Get_Squad_List_Roots_Squad_Panel' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_Get_Squad_List_Roots_Unassigned_Panel) == 0x0000C0, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_Get_Squad_List_Roots_Unassigned_Panel' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_Get_Squad_List_Roots_Commander_Panel) == 0x0000C8, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_Get_Squad_List_Roots_Commander_Panel' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_GetHUD_ReturnValue) == 0x0000D0, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_GetHUD_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_DynamicCast_AsBP_HUD) == 0x0000D8, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_DynamicCast_AsBP_HUD' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_DynamicCast_bSuccess_3) == 0x0000E0, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_DynamicCast_bSuccess_3' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_GetSquadPlayerController_Return_Value) == 0x0000E8, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_GetSquadPlayerController_Return_Value' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_K2_GetPawn_ReturnValue) == 0x0000F0, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_K2_GetPawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_GetHUD_ReturnValue_1) == 0x0000F8, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_GetHUD_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_IsValid_ReturnValue_2) == 0x000100, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_DynamicCast_AsBPI_HUD) == 0x000108, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_DynamicCast_AsBPI_HUD' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_DynamicCast_bSuccess_4) == 0x000118, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_DynamicCast_bSuccess_4' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_DynamicCast_AsBP_Player_Controller) == 0x000120, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_DynamicCast_AsBP_Player_Controller' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, K2Node_DynamicCast_bSuccess_5) == 0x000128, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::K2Node_DynamicCast_bSuccess_5' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_ExecuteUbergraph_W_CommandUI, CallFunc_BooleanAND_ReturnValue) == 0x000129, "Member 'W_CommandUI_C_ExecuteUbergraph_W_CommandUI::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");

// Function W_CommandUI.W_CommandUI_C.Command Changed
// 0x0010 (0x0010 - 0x0000)
struct W_CommandUI_C_Command_Changed final
{
public:
	class ASQPlayerState*                         OldCommander;                                      // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerState*                         NewCommander;                                      // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_CommandUI_C_Command_Changed) == 0x000008, "Wrong alignment on W_CommandUI_C_Command_Changed");
static_assert(sizeof(W_CommandUI_C_Command_Changed) == 0x000010, "Wrong size on W_CommandUI_C_Command_Changed");
static_assert(offsetof(W_CommandUI_C_Command_Changed, OldCommander) == 0x000000, "Member 'W_CommandUI_C_Command_Changed::OldCommander' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_Command_Changed, NewCommander) == 0x000008, "Member 'W_CommandUI_C_Command_Changed::NewCommander' has a wrong offset!");

// Function W_CommandUI.W_CommandUI_C.Open Chat Slide
// 0x0001 (0x0001 - 0x0000)
struct W_CommandUI_C_Open_Chat_Slide final
{
public:
	ESQChat                                       Channel;                                           // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_CommandUI_C_Open_Chat_Slide) == 0x000001, "Wrong alignment on W_CommandUI_C_Open_Chat_Slide");
static_assert(sizeof(W_CommandUI_C_Open_Chat_Slide) == 0x000001, "Wrong size on W_CommandUI_C_Open_Chat_Slide");
static_assert(offsetof(W_CommandUI_C_Open_Chat_Slide, Channel) == 0x000000, "Member 'W_CommandUI_C_Open_Chat_Slide::Channel' has a wrong offset!");

// Function W_CommandUI.W_CommandUI_C.PreConstruct
// 0x0001 (0x0001 - 0x0000)
struct W_CommandUI_C_PreConstruct final
{
public:
	bool                                          IsDesignTime;                                      // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_CommandUI_C_PreConstruct) == 0x000001, "Wrong alignment on W_CommandUI_C_PreConstruct");
static_assert(sizeof(W_CommandUI_C_PreConstruct) == 0x000001, "Wrong size on W_CommandUI_C_PreConstruct");
static_assert(offsetof(W_CommandUI_C_PreConstruct, IsDesignTime) == 0x000000, "Member 'W_CommandUI_C_PreConstruct::IsDesignTime' has a wrong offset!");

// Function W_CommandUI.W_CommandUI_C.Set Command Slide Visibility
// 0x0010 (0x0010 - 0x0000)
struct W_CommandUI_C_Set_Command_Slide_Visibility final
{
public:
	class ASQPlayerController*                    CallFunc_GetSquadPlayerController_Return_Value;    // 0x0000(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsCommander_ReturnValue;                  // 0x0008(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_CommandUI_C_Set_Command_Slide_Visibility) == 0x000008, "Wrong alignment on W_CommandUI_C_Set_Command_Slide_Visibility");
static_assert(sizeof(W_CommandUI_C_Set_Command_Slide_Visibility) == 0x000010, "Wrong size on W_CommandUI_C_Set_Command_Slide_Visibility");
static_assert(offsetof(W_CommandUI_C_Set_Command_Slide_Visibility, CallFunc_GetSquadPlayerController_Return_Value) == 0x000000, "Member 'W_CommandUI_C_Set_Command_Slide_Visibility::CallFunc_GetSquadPlayerController_Return_Value' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_Set_Command_Slide_Visibility, CallFunc_IsCommander_ReturnValue) == 0x000008, "Member 'W_CommandUI_C_Set_Command_Slide_Visibility::CallFunc_IsCommander_ReturnValue' has a wrong offset!");

// Function W_CommandUI.W_CommandUI_C.Get Squad List Roots
// 0x0018 (0x0018 - 0x0000)
struct W_CommandUI_C_Get_Squad_List_Roots final
{
public:
	class UPanelWidget*                           Squad_Panel;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPanelWidget*                           Unassigned_Panel;                                  // 0x0008(0x0008)(Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPanelWidget*                           Commander_Panel;                                   // 0x0010(0x0008)(Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_CommandUI_C_Get_Squad_List_Roots) == 0x000008, "Wrong alignment on W_CommandUI_C_Get_Squad_List_Roots");
static_assert(sizeof(W_CommandUI_C_Get_Squad_List_Roots) == 0x000018, "Wrong size on W_CommandUI_C_Get_Squad_List_Roots");
static_assert(offsetof(W_CommandUI_C_Get_Squad_List_Roots, Squad_Panel) == 0x000000, "Member 'W_CommandUI_C_Get_Squad_List_Roots::Squad_Panel' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_Get_Squad_List_Roots, Unassigned_Panel) == 0x000008, "Member 'W_CommandUI_C_Get_Squad_List_Roots::Unassigned_Panel' has a wrong offset!");
static_assert(offsetof(W_CommandUI_C_Get_Squad_List_Roots, Commander_Panel) == 0x000010, "Member 'W_CommandUI_C_Get_Squad_List_Roots::Commander_Panel' has a wrong offset!");

// Function W_CommandUI.W_CommandUI_C.Get Voting Widget
// 0x0008 (0x0008 - 0x0000)
struct W_CommandUI_C_Get_Voting_Widget final
{
public:
	class UUserWidget*                            Voting_Widget;                                     // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_CommandUI_C_Get_Voting_Widget) == 0x000008, "Wrong alignment on W_CommandUI_C_Get_Voting_Widget");
static_assert(sizeof(W_CommandUI_C_Get_Voting_Widget) == 0x000008, "Wrong size on W_CommandUI_C_Get_Voting_Widget");
static_assert(offsetof(W_CommandUI_C_Get_Voting_Widget, Voting_Widget) == 0x000000, "Member 'W_CommandUI_C_Get_Voting_Widget::Voting_Widget' has a wrong offset!");

}

