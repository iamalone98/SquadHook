#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_VehicleAmmoExtended

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"
#include "UMG_structs.hpp"
#include "SlateCore_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function UMG_VehicleAmmoExtended.UMG_VehicleAmmoExtended_C.ExecuteUbergraph_UMG_VehicleAmmoExtended
// 0x0020 (0x0020 - 0x0000)
struct UMG_VehicleAmmoExtended_C_ExecuteUbergraph_UMG_VehicleAmmoExtended final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0004(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_362B[0x4];                                     // 0x0014(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue;          // 0x0018(0x0008)(NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(UMG_VehicleAmmoExtended_C_ExecuteUbergraph_UMG_VehicleAmmoExtended) == 0x000008, "Wrong alignment on UMG_VehicleAmmoExtended_C_ExecuteUbergraph_UMG_VehicleAmmoExtended");
static_assert(sizeof(UMG_VehicleAmmoExtended_C_ExecuteUbergraph_UMG_VehicleAmmoExtended) == 0x000020, "Wrong size on UMG_VehicleAmmoExtended_C_ExecuteUbergraph_UMG_VehicleAmmoExtended");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_ExecuteUbergraph_UMG_VehicleAmmoExtended, EntryPoint) == 0x000000, "Member 'UMG_VehicleAmmoExtended_C_ExecuteUbergraph_UMG_VehicleAmmoExtended::EntryPoint' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_ExecuteUbergraph_UMG_VehicleAmmoExtended, K2Node_CreateDelegate_OutputDelegate) == 0x000004, "Member 'UMG_VehicleAmmoExtended_C_ExecuteUbergraph_UMG_VehicleAmmoExtended::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_ExecuteUbergraph_UMG_VehicleAmmoExtended, CallFunc_K2_SetTimerDelegate_ReturnValue) == 0x000018, "Member 'UMG_VehicleAmmoExtended_C_ExecuteUbergraph_UMG_VehicleAmmoExtended::CallFunc_K2_SetTimerDelegate_ReturnValue' has a wrong offset!");

// Function UMG_VehicleAmmoExtended.UMG_VehicleAmmoExtended_C.UpdateWidget
// 0x0278 (0x0278 - 0x0000)
struct UMG_VehicleAmmoExtended_C_UpdateWidget final
{
public:
	float                                         Construction;                                      // 0x0000(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Ammo;                                              // 0x0004(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Total_Points;                                      // 0x0008(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_362C[0x4];                                     // 0x000C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQVehicleResourceWeaponInventoryComponent* Vehicle_Resource_Inventory;                        // 0x0010(0x0008)(Edit, BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          FoundResources;                                    // 0x0018(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          Temp_bool_Variable;                                // 0x0019(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESlateVisibility                              Temp_byte_Variable;                                // 0x001A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              Temp_byte_Variable_1;                              // 0x001B(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable_1;                              // 0x001C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESlateVisibility                              Temp_byte_Variable_2;                              // 0x001D(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              Temp_byte_Variable_3;                              // 0x001E(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_362D[0x1];                                     // 0x001F(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_ValueSizeBox_Size;                        // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue;                 // 0x0024(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_ValueSizeBox_Size_1;                      // 0x002C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue_1;               // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_FloatToText_ReturnValue;             // 0x0038(0x0018)()
	float                                         CallFunc_Conv_IntToFloat_ReturnValue;              // 0x0050(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Conv_IntToFloat_ReturnValue_1;            // 0x0054(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GetTotalSharedResourceAmount_ReturnValue; // 0x0058(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Conv_IntToFloat_ReturnValue_2;            // 0x005C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSlateColor                            K2Node_MakeStruct_SlateColor;                      // 0x0060(0x0028)()
	struct FSlateBrush                            K2Node_MakeStruct_SlateBrush;                      // 0x0088(0x0088)()
	class ASQVehicleResource*                     CallFunc_FindConstructionWeapon_ReturnValue;       // 0x0110(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0118(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_362E[0x7];                                     // 0x0119(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQVehicleResource*                     CallFunc_FindAmmoWeapon_ReturnValue;               // 0x0120(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              K2Node_Select_Default;                             // 0x0128(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0129(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESlateVisibility                              K2Node_Select_Default_1;                           // 0x012A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_362F[0x5];                                     // 0x012B(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_IntToText_ReturnValue;               // 0x0130(0x0018)()
	class FText                                   CallFunc_Conv_IntToText_ReturnValue_1;             // 0x0148(0x0018)()
	struct FSlateColor                            K2Node_MakeStruct_SlateColor_1;                    // 0x0160(0x0028)()
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0188(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSlateBrush                            K2Node_MakeStruct_SlateBrush_1;                    // 0x0190(0x0088)()
	class AHUD*                                   CallFunc_GetHUD_ReturnValue;                       // 0x0218(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TScriptInterface<class IBPI_HUD_C>            K2Node_DynamicCast_AsBPI_HUD;                      // 0x0220(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0230(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3630[0x7];                                     // 0x0231(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UBaseRadialMenu_C*                      CallFunc_Get_Radial_Menu_Radial_Menu;              // 0x0238(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x0240(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3631[0x7];                                     // 0x0241(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQVehicle*                             K2Node_DynamicCast_AsSQVehicle;                    // 0x0248(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0250(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3632[0x7];                                     // 0x0251(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQVehicleInventoryComponent*           CallFunc_GetVehicleInventory_ReturnValue;          // 0x0258(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_3;                    // 0x0260(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_4;                    // 0x0261(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3633[0x6];                                     // 0x0262(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class USQVehicleResourceWeaponInventoryComponent* K2Node_DynamicCast_AsSQVehicle_Resource_Weapon_Inventory_Component; // 0x0268(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0270(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(UMG_VehicleAmmoExtended_C_UpdateWidget) == 0x000008, "Wrong alignment on UMG_VehicleAmmoExtended_C_UpdateWidget");
static_assert(sizeof(UMG_VehicleAmmoExtended_C_UpdateWidget) == 0x000278, "Wrong size on UMG_VehicleAmmoExtended_C_UpdateWidget");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, Construction) == 0x000000, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::Construction' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, Ammo) == 0x000004, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::Ammo' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, Total_Points) == 0x000008, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::Total_Points' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, Vehicle_Resource_Inventory) == 0x000010, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::Vehicle_Resource_Inventory' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, FoundResources) == 0x000018, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::FoundResources' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, Temp_bool_Variable) == 0x000019, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, Temp_byte_Variable) == 0x00001A, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, Temp_byte_Variable_1) == 0x00001B, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::Temp_byte_Variable_1' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, Temp_bool_Variable_1) == 0x00001C, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::Temp_bool_Variable_1' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, Temp_byte_Variable_2) == 0x00001D, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::Temp_byte_Variable_2' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, Temp_byte_Variable_3) == 0x00001E, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::Temp_byte_Variable_3' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_ValueSizeBox_Size) == 0x000020, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_ValueSizeBox_Size' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_MakeVector2D_ReturnValue) == 0x000024, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_MakeVector2D_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_ValueSizeBox_Size_1) == 0x00002C, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_ValueSizeBox_Size_1' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_MakeVector2D_ReturnValue_1) == 0x000030, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_MakeVector2D_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_Conv_FloatToText_ReturnValue) == 0x000038, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_Conv_FloatToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_Conv_IntToFloat_ReturnValue) == 0x000050, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_Conv_IntToFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_Conv_IntToFloat_ReturnValue_1) == 0x000054, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_Conv_IntToFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_GetTotalSharedResourceAmount_ReturnValue) == 0x000058, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_GetTotalSharedResourceAmount_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_Conv_IntToFloat_ReturnValue_2) == 0x00005C, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_Conv_IntToFloat_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, K2Node_MakeStruct_SlateColor) == 0x000060, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::K2Node_MakeStruct_SlateColor' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, K2Node_MakeStruct_SlateBrush) == 0x000088, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::K2Node_MakeStruct_SlateBrush' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_FindConstructionWeapon_ReturnValue) == 0x000110, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_FindConstructionWeapon_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_IsValid_ReturnValue) == 0x000118, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_FindAmmoWeapon_ReturnValue) == 0x000120, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_FindAmmoWeapon_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, K2Node_Select_Default) == 0x000128, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_IsValid_ReturnValue_1) == 0x000129, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, K2Node_Select_Default_1) == 0x00012A, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::K2Node_Select_Default_1' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_Conv_IntToText_ReturnValue) == 0x000130, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_Conv_IntToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_Conv_IntToText_ReturnValue_1) == 0x000148, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_Conv_IntToText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, K2Node_MakeStruct_SlateColor_1) == 0x000160, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::K2Node_MakeStruct_SlateColor_1' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_GetOwningPlayer_ReturnValue) == 0x000188, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, K2Node_MakeStruct_SlateBrush_1) == 0x000190, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::K2Node_MakeStruct_SlateBrush_1' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_GetHUD_ReturnValue) == 0x000218, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_GetHUD_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, K2Node_DynamicCast_AsBPI_HUD) == 0x000220, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::K2Node_DynamicCast_AsBPI_HUD' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, K2Node_DynamicCast_bSuccess) == 0x000230, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_Get_Radial_Menu_Radial_Menu) == 0x000238, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_Get_Radial_Menu_Radial_Menu' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_IsValid_ReturnValue_2) == 0x000240, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, K2Node_DynamicCast_AsSQVehicle) == 0x000248, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::K2Node_DynamicCast_AsSQVehicle' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, K2Node_DynamicCast_bSuccess_1) == 0x000250, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_GetVehicleInventory_ReturnValue) == 0x000258, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_GetVehicleInventory_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_IsValid_ReturnValue_3) == 0x000260, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_IsValid_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, CallFunc_IsValid_ReturnValue_4) == 0x000261, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::CallFunc_IsValid_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, K2Node_DynamicCast_AsSQVehicle_Resource_Weapon_Inventory_Component) == 0x000268, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::K2Node_DynamicCast_AsSQVehicle_Resource_Weapon_Inventory_Component' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_UpdateWidget, K2Node_DynamicCast_bSuccess_2) == 0x000270, "Member 'UMG_VehicleAmmoExtended_C_UpdateWidget::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");

// Function UMG_VehicleAmmoExtended.UMG_VehicleAmmoExtended_C.ValueSizeBox
// 0x001C (0x001C - 0x0000)
struct UMG_VehicleAmmoExtended_C_ValueSizeBox final
{
public:
	float                                         InPoints;                                          // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         TotalPoints;                                       // 0x0004(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Size;                                              // 0x0008(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_FloatFloat_ReturnValue;        // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3634[0x3];                                     // 0x0011(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(UMG_VehicleAmmoExtended_C_ValueSizeBox) == 0x000004, "Wrong alignment on UMG_VehicleAmmoExtended_C_ValueSizeBox");
static_assert(sizeof(UMG_VehicleAmmoExtended_C_ValueSizeBox) == 0x00001C, "Wrong size on UMG_VehicleAmmoExtended_C_ValueSizeBox");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_ValueSizeBox, InPoints) == 0x000000, "Member 'UMG_VehicleAmmoExtended_C_ValueSizeBox::InPoints' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_ValueSizeBox, TotalPoints) == 0x000004, "Member 'UMG_VehicleAmmoExtended_C_ValueSizeBox::TotalPoints' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_ValueSizeBox, Size) == 0x000008, "Member 'UMG_VehicleAmmoExtended_C_ValueSizeBox::Size' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_ValueSizeBox, CallFunc_Divide_FloatFloat_ReturnValue) == 0x00000C, "Member 'UMG_VehicleAmmoExtended_C_ValueSizeBox::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_ValueSizeBox, CallFunc_EqualEqual_FloatFloat_ReturnValue) == 0x000010, "Member 'UMG_VehicleAmmoExtended_C_ValueSizeBox::CallFunc_EqualEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_ValueSizeBox, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x000014, "Member 'UMG_VehicleAmmoExtended_C_ValueSizeBox::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_VehicleAmmoExtended_C_ValueSizeBox, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x000018, "Member 'UMG_VehicleAmmoExtended_C_ValueSizeBox::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");

}
