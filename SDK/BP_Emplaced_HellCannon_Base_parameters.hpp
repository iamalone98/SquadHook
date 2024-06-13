#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Emplaced_HellCannon_Base

#include "Basic.hpp"

#include "InputCore_structs.hpp"


namespace SDK::Params
{

// Function BP_Emplaced_HellCannon_Base.BP_Emplaced_HellCannon_Base_C.ExecuteUbergraph_BP_Emplaced_HellCannon_Base
// 0x00F8 (0x00F8 - 0x0000)
struct BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4FC5[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQVehicle*                             K2Node_CustomEvent_Vehicle;                        // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      K2Node_CustomEvent_Player;                         // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         K2Node_CustomEvent_Seat;                           // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4FC6[0x4];                                     // 0x001C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FKey                                   K2Node_InputActionEvent_Key;                       // 0x0020(0x0018)(HasGetValueTypeHash)
	class ABP_PlayerController_C*                 K2Node_DynamicCast_AsBP_Player_Controller;         // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FC7[0x7];                                     // 0x0041(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FKey                                   Temp_struct_Variable;                              // 0x0048(0x0018)(HasGetValueTypeHash)
	TDelegate<void(class ASQVehicle* Vehicle, class APlayerController* Player, int32 Seat)> K2Node_CreateDelegate_OutputDelegate;              // 0x0060(0x0010)(ZeroConstructor, NoDestructor)
	TDelegate<void(class ASQVehicle* Vehicle, class APlayerController* Player, int32 Seat)> K2Node_CreateDelegate_OutputDelegate_1;            // 0x0070(0x0010)(ZeroConstructor, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0080(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValidClass_ReturnValue;                 // 0x0081(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FC8[0x6];                                     // 0x0082(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class AController*                            K2Node_Event_NewController;                        // 0x0088(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AController*                            K2Node_Event_OldController;                        // 0x0090(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0098(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x00A0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FC9[0x7];                                     // 0x00A1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller_1;        // 0x00A8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x00B0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FCA[0x7];                                     // 0x00B1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FKey                                   K2Node_InputActionEvent_Key_1;                     // 0x00B8(0x0018)(HasGetValueTypeHash)
	class ASQVehicle*                             K2Node_CustomEvent_Vehicle_1;                      // 0x00D0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      K2Node_CustomEvent_Player_1;                       // 0x00D8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         K2Node_CustomEvent_Seat_1;                         // 0x00E0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4FCB[0x4];                                     // 0x00E4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_PlayerController_C*                 K2Node_DynamicCast_AsBP_Player_Controller_1;       // 0x00E8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_3;                     // 0x00F0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base) == 0x000008, "Wrong alignment on BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base");
static_assert(sizeof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base) == 0x0000F8, "Wrong size on BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, EntryPoint) == 0x000000, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_CustomEvent_Vehicle) == 0x000008, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_CustomEvent_Vehicle' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_CustomEvent_Player) == 0x000010, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_CustomEvent_Player' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_CustomEvent_Seat) == 0x000018, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_CustomEvent_Seat' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_InputActionEvent_Key) == 0x000020, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_InputActionEvent_Key' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_DynamicCast_AsBP_Player_Controller) == 0x000038, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_DynamicCast_AsBP_Player_Controller' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_DynamicCast_bSuccess) == 0x000040, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, Temp_struct_Variable) == 0x000048, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::Temp_struct_Variable' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_CreateDelegate_OutputDelegate) == 0x000060, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_CreateDelegate_OutputDelegate_1) == 0x000070, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, CallFunc_IsValid_ReturnValue) == 0x000080, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, CallFunc_IsValidClass_ReturnValue) == 0x000081, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::CallFunc_IsValidClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_Event_NewController) == 0x000088, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_Event_NewController' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_Event_OldController) == 0x000090, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_Event_OldController' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000098, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_DynamicCast_bSuccess_1) == 0x0000A0, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_DynamicCast_AsSQPlayer_Controller_1) == 0x0000A8, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_DynamicCast_AsSQPlayer_Controller_1' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_DynamicCast_bSuccess_2) == 0x0000B0, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_InputActionEvent_Key_1) == 0x0000B8, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_InputActionEvent_Key_1' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_CustomEvent_Vehicle_1) == 0x0000D0, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_CustomEvent_Vehicle_1' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_CustomEvent_Player_1) == 0x0000D8, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_CustomEvent_Player_1' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_CustomEvent_Seat_1) == 0x0000E0, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_CustomEvent_Seat_1' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_DynamicCast_AsBP_Player_Controller_1) == 0x0000E8, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_DynamicCast_AsBP_Player_Controller_1' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base, K2Node_DynamicCast_bSuccess_3) == 0x0000F0, "Member 'BP_Emplaced_HellCannon_Base_C_ExecuteUbergraph_BP_Emplaced_HellCannon_Base::K2Node_DynamicCast_bSuccess_3' has a wrong offset!");

// Function BP_Emplaced_HellCannon_Base.BP_Emplaced_HellCannon_Base_C.TurnOffDecimalBearing
// 0x0018 (0x0018 - 0x0000)
struct BP_Emplaced_HellCannon_Base_C_TurnOffDecimalBearing final
{
public:
	class ASQVehicle*                             Vehicle;                                           // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      Player;                                            // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Seat;                                              // 0x0010(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Emplaced_HellCannon_Base_C_TurnOffDecimalBearing) == 0x000008, "Wrong alignment on BP_Emplaced_HellCannon_Base_C_TurnOffDecimalBearing");
static_assert(sizeof(BP_Emplaced_HellCannon_Base_C_TurnOffDecimalBearing) == 0x000018, "Wrong size on BP_Emplaced_HellCannon_Base_C_TurnOffDecimalBearing");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_TurnOffDecimalBearing, Vehicle) == 0x000000, "Member 'BP_Emplaced_HellCannon_Base_C_TurnOffDecimalBearing::Vehicle' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_TurnOffDecimalBearing, Player) == 0x000008, "Member 'BP_Emplaced_HellCannon_Base_C_TurnOffDecimalBearing::Player' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_TurnOffDecimalBearing, Seat) == 0x000010, "Member 'BP_Emplaced_HellCannon_Base_C_TurnOffDecimalBearing::Seat' has a wrong offset!");

// Function BP_Emplaced_HellCannon_Base.BP_Emplaced_HellCannon_Base_C.TurnOnDecimalBearing
// 0x0018 (0x0018 - 0x0000)
struct BP_Emplaced_HellCannon_Base_C_TurnOnDecimalBearing final
{
public:
	class ASQVehicle*                             Vehicle;                                           // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      Player;                                            // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Seat;                                              // 0x0010(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Emplaced_HellCannon_Base_C_TurnOnDecimalBearing) == 0x000008, "Wrong alignment on BP_Emplaced_HellCannon_Base_C_TurnOnDecimalBearing");
static_assert(sizeof(BP_Emplaced_HellCannon_Base_C_TurnOnDecimalBearing) == 0x000018, "Wrong size on BP_Emplaced_HellCannon_Base_C_TurnOnDecimalBearing");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_TurnOnDecimalBearing, Vehicle) == 0x000000, "Member 'BP_Emplaced_HellCannon_Base_C_TurnOnDecimalBearing::Vehicle' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_TurnOnDecimalBearing, Player) == 0x000008, "Member 'BP_Emplaced_HellCannon_Base_C_TurnOnDecimalBearing::Player' has a wrong offset!");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_TurnOnDecimalBearing, Seat) == 0x000010, "Member 'BP_Emplaced_HellCannon_Base_C_TurnOnDecimalBearing::Seat' has a wrong offset!");

// Function BP_Emplaced_HellCannon_Base.BP_Emplaced_HellCannon_Base_C.ReceiveUnpossessed
// 0x0008 (0x0008 - 0x0000)
struct BP_Emplaced_HellCannon_Base_C_ReceiveUnpossessed final
{
public:
	class AController*                            OldController;                                     // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Emplaced_HellCannon_Base_C_ReceiveUnpossessed) == 0x000008, "Wrong alignment on BP_Emplaced_HellCannon_Base_C_ReceiveUnpossessed");
static_assert(sizeof(BP_Emplaced_HellCannon_Base_C_ReceiveUnpossessed) == 0x000008, "Wrong size on BP_Emplaced_HellCannon_Base_C_ReceiveUnpossessed");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ReceiveUnpossessed, OldController) == 0x000000, "Member 'BP_Emplaced_HellCannon_Base_C_ReceiveUnpossessed::OldController' has a wrong offset!");

// Function BP_Emplaced_HellCannon_Base.BP_Emplaced_HellCannon_Base_C.ReceivePossessed
// 0x0008 (0x0008 - 0x0000)
struct BP_Emplaced_HellCannon_Base_C_ReceivePossessed final
{
public:
	class AController*                            NewController;                                     // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Emplaced_HellCannon_Base_C_ReceivePossessed) == 0x000008, "Wrong alignment on BP_Emplaced_HellCannon_Base_C_ReceivePossessed");
static_assert(sizeof(BP_Emplaced_HellCannon_Base_C_ReceivePossessed) == 0x000008, "Wrong size on BP_Emplaced_HellCannon_Base_C_ReceivePossessed");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_ReceivePossessed, NewController) == 0x000000, "Member 'BP_Emplaced_HellCannon_Base_C_ReceivePossessed::NewController' has a wrong offset!");

// Function BP_Emplaced_HellCannon_Base.BP_Emplaced_HellCannon_Base_C.InpActEvt_Focus_K2Node_InputActionEvent_0
// 0x0018 (0x0018 - 0x0000)
struct BP_Emplaced_HellCannon_Base_C_InpActEvt_Focus_K2Node_InputActionEvent_0 final
{
public:
	struct FKey                                   Key;                                               // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
};
static_assert(alignof(BP_Emplaced_HellCannon_Base_C_InpActEvt_Focus_K2Node_InputActionEvent_0) == 0x000008, "Wrong alignment on BP_Emplaced_HellCannon_Base_C_InpActEvt_Focus_K2Node_InputActionEvent_0");
static_assert(sizeof(BP_Emplaced_HellCannon_Base_C_InpActEvt_Focus_K2Node_InputActionEvent_0) == 0x000018, "Wrong size on BP_Emplaced_HellCannon_Base_C_InpActEvt_Focus_K2Node_InputActionEvent_0");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_InpActEvt_Focus_K2Node_InputActionEvent_0, Key) == 0x000000, "Member 'BP_Emplaced_HellCannon_Base_C_InpActEvt_Focus_K2Node_InputActionEvent_0::Key' has a wrong offset!");

// Function BP_Emplaced_HellCannon_Base.BP_Emplaced_HellCannon_Base_C.InpActEvt_Focus_K2Node_InputActionEvent_1
// 0x0018 (0x0018 - 0x0000)
struct BP_Emplaced_HellCannon_Base_C_InpActEvt_Focus_K2Node_InputActionEvent_1 final
{
public:
	struct FKey                                   Key;                                               // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
};
static_assert(alignof(BP_Emplaced_HellCannon_Base_C_InpActEvt_Focus_K2Node_InputActionEvent_1) == 0x000008, "Wrong alignment on BP_Emplaced_HellCannon_Base_C_InpActEvt_Focus_K2Node_InputActionEvent_1");
static_assert(sizeof(BP_Emplaced_HellCannon_Base_C_InpActEvt_Focus_K2Node_InputActionEvent_1) == 0x000018, "Wrong size on BP_Emplaced_HellCannon_Base_C_InpActEvt_Focus_K2Node_InputActionEvent_1");
static_assert(offsetof(BP_Emplaced_HellCannon_Base_C_InpActEvt_Focus_K2Node_InputActionEvent_1, Key) == 0x000000, "Member 'BP_Emplaced_HellCannon_Base_C_InpActEvt_Focus_K2Node_InputActionEvent_1::Key' has a wrong offset!");

}
