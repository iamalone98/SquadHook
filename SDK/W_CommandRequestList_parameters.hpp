#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_CommandRequestList

#include "Basic.hpp"

#include "Squad_structs.hpp"


namespace SDK::Params
{

// Function W_CommandRequestList.W_CommandRequestList_C.ExecuteUbergraph_W_CommandRequestList
// 0x0110 (0x0110 - 0x0000)
struct W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4591[0x3];                                     // 0x0005(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0008(0x0010)(ZeroConstructor, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4592[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TScriptInterface<class IBPI_PlayerController_C> K2Node_DynamicCast_AsBPI_Player_Controller;        // 0x0028(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4593[0x7];                                     // 0x0039(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TScriptInterface<class IBPI_PlayerController_C> K2Node_DynamicCast_AsBPI_Player_Controller_1;      // 0x0040(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4594[0x7];                                     // 0x0051(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TScriptInterface<class IBPI_PlayerController_C> K2Node_DynamicCast_AsBPI_Player_Controller_2;      // 0x0058(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4595[0x7];                                     // 0x0069(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0070(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_3;                     // 0x0078(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsCommander_ReturnValue;                  // 0x0079(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_ComponentBoundEvent_bSelected_1;            // 0x007A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4596[0x5];                                     // 0x007B(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class UMainMenu_Button_C*                     K2Node_ComponentBoundEvent_Button_1;               // 0x0080(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_ComponentBoundEvent_bSelected;              // 0x0088(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4597[0x7];                                     // 0x0089(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UMainMenu_Button_C*                     K2Node_ComponentBoundEvent_Button;                 // 0x0090(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue_1;            // 0x0098(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller_1;        // 0x00A0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_4;                     // 0x00A8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4598[0x7];                                     // 0x00A9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue_2;            // 0x00B0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_Command_ActionControl_C*             K2Node_CustomEvent_Widget;                         // 0x00B8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TScriptInterface<class IBPI_PlayerController_C> K2Node_DynamicCast_AsBPI_Player_Controller_3;      // 0x00C0(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess_5;                     // 0x00D0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4599[0x7];                                     // 0x00D1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TScriptInterface<class IBPI_PlayerController_C> K2Node_DynamicCast_AsBPI_Player_Controller_4;      // 0x00D8(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess_6;                     // 0x00E8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_459A[0x7];                                     // 0x00E9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue_3;            // 0x00F0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TScriptInterface<class IBPI_PlayerController_C> K2Node_DynamicCast_AsBPI_Player_Controller_5;      // 0x00F8(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess_7;                     // 0x0108(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList) == 0x000008, "Wrong alignment on W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList");
static_assert(sizeof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList) == 0x000110, "Wrong size on W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, EntryPoint) == 0x000000, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, CallFunc_IsValid_ReturnValue) == 0x000004, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_CreateDelegate_OutputDelegate) == 0x000008, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, CallFunc_IsValid_ReturnValue_1) == 0x000018, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, CallFunc_GetOwningPlayer_ReturnValue) == 0x000020, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_AsBPI_Player_Controller) == 0x000028, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_AsBPI_Player_Controller' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_bSuccess) == 0x000038, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_AsBPI_Player_Controller_1) == 0x000040, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_AsBPI_Player_Controller_1' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_bSuccess_1) == 0x000050, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_AsBPI_Player_Controller_2) == 0x000058, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_AsBPI_Player_Controller_2' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_bSuccess_2) == 0x000068, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000070, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_bSuccess_3) == 0x000078, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_bSuccess_3' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, CallFunc_IsCommander_ReturnValue) == 0x000079, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::CallFunc_IsCommander_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_ComponentBoundEvent_bSelected_1) == 0x00007A, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_ComponentBoundEvent_bSelected_1' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_ComponentBoundEvent_Button_1) == 0x000080, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_ComponentBoundEvent_Button_1' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_ComponentBoundEvent_bSelected) == 0x000088, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_ComponentBoundEvent_bSelected' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_ComponentBoundEvent_Button) == 0x000090, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_ComponentBoundEvent_Button' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, CallFunc_GetOwningPlayer_ReturnValue_1) == 0x000098, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::CallFunc_GetOwningPlayer_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_AsSQPlayer_Controller_1) == 0x0000A0, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_AsSQPlayer_Controller_1' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_bSuccess_4) == 0x0000A8, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_bSuccess_4' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, CallFunc_GetOwningPlayer_ReturnValue_2) == 0x0000B0, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::CallFunc_GetOwningPlayer_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_CustomEvent_Widget) == 0x0000B8, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_CustomEvent_Widget' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_AsBPI_Player_Controller_3) == 0x0000C0, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_AsBPI_Player_Controller_3' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_bSuccess_5) == 0x0000D0, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_bSuccess_5' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_AsBPI_Player_Controller_4) == 0x0000D8, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_AsBPI_Player_Controller_4' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_bSuccess_6) == 0x0000E8, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_bSuccess_6' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, CallFunc_GetOwningPlayer_ReturnValue_3) == 0x0000F0, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::CallFunc_GetOwningPlayer_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_AsBPI_Player_Controller_5) == 0x0000F8, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_AsBPI_Player_Controller_5' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList, K2Node_DynamicCast_bSuccess_7) == 0x000108, "Member 'W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList::K2Node_DynamicCast_bSuccess_7' has a wrong offset!");

// Function W_CommandRequestList.W_CommandRequestList_C.Control Widget Created
// 0x0008 (0x0008 - 0x0000)
struct W_CommandRequestList_C_Control_Widget_Created final
{
public:
	class UW_Command_ActionControl_C*             Widget;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_CommandRequestList_C_Control_Widget_Created) == 0x000008, "Wrong alignment on W_CommandRequestList_C_Control_Widget_Created");
static_assert(sizeof(W_CommandRequestList_C_Control_Widget_Created) == 0x000008, "Wrong size on W_CommandRequestList_C_Control_Widget_Created");
static_assert(offsetof(W_CommandRequestList_C_Control_Widget_Created, Widget) == 0x000000, "Member 'W_CommandRequestList_C_Control_Widget_Created::Widget' has a wrong offset!");

// Function W_CommandRequestList.W_CommandRequestList_C.BndEvt__Button_Deny_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature
// 0x0010 (0x0010 - 0x0000)
struct W_CommandRequestList_C_BndEvt__Button_Deny_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature final
{
public:
	bool                                          bSelected;                                         // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_459B[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UMainMenu_Button_C*                     Button;                                            // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_CommandRequestList_C_BndEvt__Button_Deny_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature) == 0x000008, "Wrong alignment on W_CommandRequestList_C_BndEvt__Button_Deny_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature");
static_assert(sizeof(W_CommandRequestList_C_BndEvt__Button_Deny_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature) == 0x000010, "Wrong size on W_CommandRequestList_C_BndEvt__Button_Deny_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature");
static_assert(offsetof(W_CommandRequestList_C_BndEvt__Button_Deny_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature, bSelected) == 0x000000, "Member 'W_CommandRequestList_C_BndEvt__Button_Deny_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature::bSelected' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_BndEvt__Button_Deny_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature, Button) == 0x000008, "Member 'W_CommandRequestList_C_BndEvt__Button_Deny_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature::Button' has a wrong offset!");

// Function W_CommandRequestList.W_CommandRequestList_C.BndEvt__Button_Accept_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature
// 0x0010 (0x0010 - 0x0000)
struct W_CommandRequestList_C_BndEvt__Button_Accept_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature final
{
public:
	bool                                          bSelected;                                         // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_459C[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UMainMenu_Button_C*                     Button;                                            // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_CommandRequestList_C_BndEvt__Button_Accept_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature) == 0x000008, "Wrong alignment on W_CommandRequestList_C_BndEvt__Button_Accept_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature");
static_assert(sizeof(W_CommandRequestList_C_BndEvt__Button_Accept_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature) == 0x000010, "Wrong size on W_CommandRequestList_C_BndEvt__Button_Accept_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature");
static_assert(offsetof(W_CommandRequestList_C_BndEvt__Button_Accept_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature, bSelected) == 0x000000, "Member 'W_CommandRequestList_C_BndEvt__Button_Accept_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature::bSelected' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_BndEvt__Button_Accept_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature, Button) == 0x000008, "Member 'W_CommandRequestList_C_BndEvt__Button_Accept_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature::Button' has a wrong offset!");

// Function W_CommandRequestList.W_CommandRequestList_C.Remove Other Request Lists
// 0x0038 (0x0038 - 0x0000)
struct W_CommandRequestList_C_Remove_Other_Request_Lists final
{
public:
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0000(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_459D[0x4];                                     // 0x000C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class UW_FloatingWidget_C*>            CallFunc_GetAllWidgetsOfClass_FoundWidgets;        // 0x0010(0x0010)(ReferenceParm, ContainsInstancedReference)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_459E[0x4];                                     // 0x0024(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_FloatingWidget_C*                    CallFunc_Array_Get_Item;                           // 0x0028(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_NotEqual_ObjectObject_ReturnValue;        // 0x0031(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_CommandRequestList_C_Remove_Other_Request_Lists) == 0x000008, "Wrong alignment on W_CommandRequestList_C_Remove_Other_Request_Lists");
static_assert(sizeof(W_CommandRequestList_C_Remove_Other_Request_Lists) == 0x000038, "Wrong size on W_CommandRequestList_C_Remove_Other_Request_Lists");
static_assert(offsetof(W_CommandRequestList_C_Remove_Other_Request_Lists, Temp_int_Array_Index_Variable) == 0x000000, "Member 'W_CommandRequestList_C_Remove_Other_Request_Lists::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Remove_Other_Request_Lists, Temp_int_Loop_Counter_Variable) == 0x000004, "Member 'W_CommandRequestList_C_Remove_Other_Request_Lists::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Remove_Other_Request_Lists, CallFunc_Add_IntInt_ReturnValue) == 0x000008, "Member 'W_CommandRequestList_C_Remove_Other_Request_Lists::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Remove_Other_Request_Lists, CallFunc_GetAllWidgetsOfClass_FoundWidgets) == 0x000010, "Member 'W_CommandRequestList_C_Remove_Other_Request_Lists::CallFunc_GetAllWidgetsOfClass_FoundWidgets' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Remove_Other_Request_Lists, CallFunc_Array_Length_ReturnValue) == 0x000020, "Member 'W_CommandRequestList_C_Remove_Other_Request_Lists::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Remove_Other_Request_Lists, CallFunc_Array_Get_Item) == 0x000028, "Member 'W_CommandRequestList_C_Remove_Other_Request_Lists::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Remove_Other_Request_Lists, CallFunc_Less_IntInt_ReturnValue) == 0x000030, "Member 'W_CommandRequestList_C_Remove_Other_Request_Lists::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Remove_Other_Request_Lists, CallFunc_NotEqual_ObjectObject_ReturnValue) == 0x000031, "Member 'W_CommandRequestList_C_Remove_Other_Request_Lists::CallFunc_NotEqual_ObjectObject_ReturnValue' has a wrong offset!");

// Function W_CommandRequestList.W_CommandRequestList_C.Init Action List
// 0x00A0 (0x00A0 - 0x0000)
struct W_CommandRequestList_C_Init_Action_List final
{
public:
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0000(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable_1;                   // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         CallFunc_Conv_IntToByte_ReturnValue;               // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x0011(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_459F[0x2];                                     // 0x0012(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void(class UW_Command_ActionControl_C* Widget)> K2Node_CreateDelegate_OutputDelegate;              // 0x0014(0x0010)(ZeroConstructor, NoDestructor)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_1;            // 0x0024(0x0010)(ZeroConstructor, NoDestructor)
	int32                                         Temp_int_Loop_Counter_Variable_1;                  // 0x0034(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x0038(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_IntInt_ReturnValue;              // 0x003C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_45A0[0x3];                                     // 0x003D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerState*                         CallFunc_GetCurrentCommander_ReturnValue;          // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_CommandActionCategory_C*             CallFunc_Create_ReturnValue;                       // 0x0050(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UVerticalBoxSlot*                       CallFunc_AddChildToVerticalBox_ReturnValue;        // 0x0058(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_CommandActionItem_C*                 CallFunc_Array_Get_Item;                           // 0x0060(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0068(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x006C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_NotEqual_ObjectObject_ReturnValue;        // 0x006D(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_45A1[0x2];                                     // 0x006E(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Array_Length_ReturnValue_1;               // 0x0070(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_45A2[0x4];                                     // 0x0074(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FCommanderCategory                     CallFunc_Array_Get_Item_1;                         // 0x0078(0x0020)()
	bool                                          CallFunc_Less_IntInt_ReturnValue_1;                // 0x0098(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_CommandRequestList_C_Init_Action_List) == 0x000008, "Wrong alignment on W_CommandRequestList_C_Init_Action_List");
static_assert(sizeof(W_CommandRequestList_C_Init_Action_List) == 0x0000A0, "Wrong size on W_CommandRequestList_C_Init_Action_List");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, Temp_int_Loop_Counter_Variable) == 0x000000, "Member 'W_CommandRequestList_C_Init_Action_List::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_Add_IntInt_ReturnValue) == 0x000004, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, Temp_int_Array_Index_Variable) == 0x000008, "Member 'W_CommandRequestList_C_Init_Action_List::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, Temp_int_Array_Index_Variable_1) == 0x00000C, "Member 'W_CommandRequestList_C_Init_Action_List::Temp_int_Array_Index_Variable_1' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_Conv_IntToByte_ReturnValue) == 0x000010, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_Conv_IntToByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x000011, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, K2Node_CreateDelegate_OutputDelegate) == 0x000014, "Member 'W_CommandRequestList_C_Init_Action_List::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, K2Node_CreateDelegate_OutputDelegate_1) == 0x000024, "Member 'W_CommandRequestList_C_Init_Action_List::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, Temp_int_Loop_Counter_Variable_1) == 0x000034, "Member 'W_CommandRequestList_C_Init_Action_List::Temp_int_Loop_Counter_Variable_1' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_Add_IntInt_ReturnValue_1) == 0x000038, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_NotEqual_IntInt_ReturnValue) == 0x00003C, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_NotEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_GetOwningPlayer_ReturnValue) == 0x000040, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_GetCurrentCommander_ReturnValue) == 0x000048, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_GetCurrentCommander_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_Create_ReturnValue) == 0x000050, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_Create_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_AddChildToVerticalBox_ReturnValue) == 0x000058, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_AddChildToVerticalBox_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_Array_Get_Item) == 0x000060, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_Array_Length_ReturnValue) == 0x000068, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_Less_IntInt_ReturnValue) == 0x00006C, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_NotEqual_ObjectObject_ReturnValue) == 0x00006D, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_NotEqual_ObjectObject_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_Array_Length_ReturnValue_1) == 0x000070, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_Array_Length_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_Array_Get_Item_1) == 0x000078, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_Array_Get_Item_1' has a wrong offset!");
static_assert(offsetof(W_CommandRequestList_C_Init_Action_List, CallFunc_Less_IntInt_ReturnValue_1) == 0x000098, "Member 'W_CommandRequestList_C_Init_Action_List::CallFunc_Less_IntInt_ReturnValue_1' has a wrong offset!");

}

