#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_PromoNewsWidget

#include "Basic.hpp"

#include "Squad_structs.hpp"
#include "Engine_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function W_PromoNewsWidget.W_PromoNewsWidget_C.ExecuteUbergraph_W_PromoNewsWidget
// 0x0168 (0x0168 - 0x0000)
struct W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3354[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQCloudServicesSubsystem*              CallFunc_GetGameInstanceSubsystem_ReturnValue;     // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FPointerEvent                          K2Node_Event_MouseEvent_1;                         // 0x0010(0x0070)(ConstParm)
	TDelegate<void(struct FCrossPromotionData& PromotionData)> K2Node_CreateDelegate_OutputDelegate;              // 0x0080(0x0010)(ZeroConstructor, NoDestructor)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0090(0x0038)(IsPlainOldData, NoDestructor)
	struct FPointerEvent                          K2Node_Event_MouseEvent;                           // 0x00C8(0x0070)(ConstParm)
	class FString                                 K2Node_ComponentBoundEvent_Url_1;                  // 0x0138(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FString                                 K2Node_ComponentBoundEvent_Url;                    // 0x0148(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class UUMGSequencePlayer*                     CallFunc_PlayAnimationReverse_ReturnValue;         // 0x0158(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UUMGSequencePlayer*                     CallFunc_PlayAnimationForward_ReturnValue;         // 0x0160(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget) == 0x000008, "Wrong alignment on W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget");
static_assert(sizeof(W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget) == 0x000168, "Wrong size on W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget");
static_assert(offsetof(W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget, EntryPoint) == 0x000000, "Member 'W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget, CallFunc_GetGameInstanceSubsystem_ReturnValue) == 0x000008, "Member 'W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget::CallFunc_GetGameInstanceSubsystem_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget, K2Node_Event_MouseEvent_1) == 0x000010, "Member 'W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget::K2Node_Event_MouseEvent_1' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget, K2Node_CreateDelegate_OutputDelegate) == 0x000080, "Member 'W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget, K2Node_Event_MyGeometry) == 0x000090, "Member 'W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget, K2Node_Event_MouseEvent) == 0x0000C8, "Member 'W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget::K2Node_Event_MouseEvent' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget, K2Node_ComponentBoundEvent_Url_1) == 0x000138, "Member 'W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget::K2Node_ComponentBoundEvent_Url_1' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget, K2Node_ComponentBoundEvent_Url) == 0x000148, "Member 'W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget::K2Node_ComponentBoundEvent_Url' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget, CallFunc_PlayAnimationReverse_ReturnValue) == 0x000158, "Member 'W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget::CallFunc_PlayAnimationReverse_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget, CallFunc_PlayAnimationForward_ReturnValue) == 0x000160, "Member 'W_PromoNewsWidget_C_ExecuteUbergraph_W_PromoNewsWidget::CallFunc_PlayAnimationForward_ReturnValue' has a wrong offset!");

// Function W_PromoNewsWidget.W_PromoNewsWidget_C.BndEvt__Hyperlink2_K2Node_ComponentBoundEvent_1_Delegate_OnHyperLinkClicked__DelegateSignature
// 0x0010 (0x0010 - 0x0000)
struct W_PromoNewsWidget_C_BndEvt__Hyperlink2_K2Node_ComponentBoundEvent_1_Delegate_OnHyperLinkClicked__DelegateSignature final
{
public:
	class FString                                 URL;                                               // 0x0000(0x0010)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)
};
static_assert(alignof(W_PromoNewsWidget_C_BndEvt__Hyperlink2_K2Node_ComponentBoundEvent_1_Delegate_OnHyperLinkClicked__DelegateSignature) == 0x000008, "Wrong alignment on W_PromoNewsWidget_C_BndEvt__Hyperlink2_K2Node_ComponentBoundEvent_1_Delegate_OnHyperLinkClicked__DelegateSignature");
static_assert(sizeof(W_PromoNewsWidget_C_BndEvt__Hyperlink2_K2Node_ComponentBoundEvent_1_Delegate_OnHyperLinkClicked__DelegateSignature) == 0x000010, "Wrong size on W_PromoNewsWidget_C_BndEvt__Hyperlink2_K2Node_ComponentBoundEvent_1_Delegate_OnHyperLinkClicked__DelegateSignature");
static_assert(offsetof(W_PromoNewsWidget_C_BndEvt__Hyperlink2_K2Node_ComponentBoundEvent_1_Delegate_OnHyperLinkClicked__DelegateSignature, URL) == 0x000000, "Member 'W_PromoNewsWidget_C_BndEvt__Hyperlink2_K2Node_ComponentBoundEvent_1_Delegate_OnHyperLinkClicked__DelegateSignature::URL' has a wrong offset!");

// Function W_PromoNewsWidget.W_PromoNewsWidget_C.BndEvt__Hyperlink1_K2Node_ComponentBoundEvent_0_Delegate_OnHyperLinkClicked__DelegateSignature
// 0x0010 (0x0010 - 0x0000)
struct W_PromoNewsWidget_C_BndEvt__Hyperlink1_K2Node_ComponentBoundEvent_0_Delegate_OnHyperLinkClicked__DelegateSignature final
{
public:
	class FString                                 URL;                                               // 0x0000(0x0010)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)
};
static_assert(alignof(W_PromoNewsWidget_C_BndEvt__Hyperlink1_K2Node_ComponentBoundEvent_0_Delegate_OnHyperLinkClicked__DelegateSignature) == 0x000008, "Wrong alignment on W_PromoNewsWidget_C_BndEvt__Hyperlink1_K2Node_ComponentBoundEvent_0_Delegate_OnHyperLinkClicked__DelegateSignature");
static_assert(sizeof(W_PromoNewsWidget_C_BndEvt__Hyperlink1_K2Node_ComponentBoundEvent_0_Delegate_OnHyperLinkClicked__DelegateSignature) == 0x000010, "Wrong size on W_PromoNewsWidget_C_BndEvt__Hyperlink1_K2Node_ComponentBoundEvent_0_Delegate_OnHyperLinkClicked__DelegateSignature");
static_assert(offsetof(W_PromoNewsWidget_C_BndEvt__Hyperlink1_K2Node_ComponentBoundEvent_0_Delegate_OnHyperLinkClicked__DelegateSignature, URL) == 0x000000, "Member 'W_PromoNewsWidget_C_BndEvt__Hyperlink1_K2Node_ComponentBoundEvent_0_Delegate_OnHyperLinkClicked__DelegateSignature::URL' has a wrong offset!");

// Function W_PromoNewsWidget.W_PromoNewsWidget_C.OnMouseEnter
// 0x00A8 (0x00A8 - 0x0000)
struct W_PromoNewsWidget_C_OnMouseEnter final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	struct FPointerEvent                          MouseEvent;                                        // 0x0038(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
};
static_assert(alignof(W_PromoNewsWidget_C_OnMouseEnter) == 0x000008, "Wrong alignment on W_PromoNewsWidget_C_OnMouseEnter");
static_assert(sizeof(W_PromoNewsWidget_C_OnMouseEnter) == 0x0000A8, "Wrong size on W_PromoNewsWidget_C_OnMouseEnter");
static_assert(offsetof(W_PromoNewsWidget_C_OnMouseEnter, MyGeometry) == 0x000000, "Member 'W_PromoNewsWidget_C_OnMouseEnter::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnMouseEnter, MouseEvent) == 0x000038, "Member 'W_PromoNewsWidget_C_OnMouseEnter::MouseEvent' has a wrong offset!");

// Function W_PromoNewsWidget.W_PromoNewsWidget_C.OnMouseLeave
// 0x0070 (0x0070 - 0x0000)
struct W_PromoNewsWidget_C_OnMouseLeave final
{
public:
	struct FPointerEvent                          MouseEvent;                                        // 0x0000(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
};
static_assert(alignof(W_PromoNewsWidget_C_OnMouseLeave) == 0x000008, "Wrong alignment on W_PromoNewsWidget_C_OnMouseLeave");
static_assert(sizeof(W_PromoNewsWidget_C_OnMouseLeave) == 0x000070, "Wrong size on W_PromoNewsWidget_C_OnMouseLeave");
static_assert(offsetof(W_PromoNewsWidget_C_OnMouseLeave, MouseEvent) == 0x000000, "Member 'W_PromoNewsWidget_C_OnMouseLeave::MouseEvent' has a wrong offset!");

// Function W_PromoNewsWidget.W_PromoNewsWidget_C.OnCrossPromoDataReady
// 0x0268 (0x0268 - 0x0000)
struct W_PromoNewsWidget_C_OnCrossPromoDataReady final
{
public:
	struct FCrossPromotionData                    PromotionData;                                     // 0x0000(0x0078)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	class FText                                   CallFunc_Conv_StringToText_ReturnValue;            // 0x0078(0x0018)()
	class FText                                   CallFunc_Conv_StringToText_ReturnValue_1;          // 0x0090(0x0018)()
	class FText                                   CallFunc_Conv_StringToText_ReturnValue_2;          // 0x00A8(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x00C0(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_StringToText_ReturnValue_3;          // 0x0100(0x0018)()
	class FText                                   CallFunc_Conv_StringToText_ReturnValue_4;          // 0x0118(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_1;            // 0x0130(0x0040)(HasGetValueTypeHash)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_2;            // 0x0170(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_StringToText_ReturnValue_5;          // 0x01B0(0x0018)()
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x01C8(0x0010)(ReferenceParm)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_3;            // 0x01D8(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x0218(0x0018)()
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array_1;                          // 0x0230(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue_1;                     // 0x0240(0x0018)()
	TDelegate<void(class USQCdnFile* File)>       K2Node_CreateDelegate_OutputDelegate;              // 0x0258(0x0010)(ZeroConstructor, NoDestructor)
};
static_assert(alignof(W_PromoNewsWidget_C_OnCrossPromoDataReady) == 0x000008, "Wrong alignment on W_PromoNewsWidget_C_OnCrossPromoDataReady");
static_assert(sizeof(W_PromoNewsWidget_C_OnCrossPromoDataReady) == 0x000268, "Wrong size on W_PromoNewsWidget_C_OnCrossPromoDataReady");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, PromotionData) == 0x000000, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::PromotionData' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, CallFunc_Conv_StringToText_ReturnValue) == 0x000078, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::CallFunc_Conv_StringToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, CallFunc_Conv_StringToText_ReturnValue_1) == 0x000090, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::CallFunc_Conv_StringToText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, CallFunc_Conv_StringToText_ReturnValue_2) == 0x0000A8, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::CallFunc_Conv_StringToText_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, K2Node_MakeStruct_FormatArgumentData) == 0x0000C0, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, CallFunc_Conv_StringToText_ReturnValue_3) == 0x000100, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::CallFunc_Conv_StringToText_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, CallFunc_Conv_StringToText_ReturnValue_4) == 0x000118, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::CallFunc_Conv_StringToText_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, K2Node_MakeStruct_FormatArgumentData_1) == 0x000130, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::K2Node_MakeStruct_FormatArgumentData_1' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, K2Node_MakeStruct_FormatArgumentData_2) == 0x000170, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::K2Node_MakeStruct_FormatArgumentData_2' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, CallFunc_Conv_StringToText_ReturnValue_5) == 0x0001B0, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::CallFunc_Conv_StringToText_ReturnValue_5' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, K2Node_MakeArray_Array) == 0x0001C8, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, K2Node_MakeStruct_FormatArgumentData_3) == 0x0001D8, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::K2Node_MakeStruct_FormatArgumentData_3' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, CallFunc_Format_ReturnValue) == 0x000218, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, K2Node_MakeArray_Array_1) == 0x000230, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::K2Node_MakeArray_Array_1' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, CallFunc_Format_ReturnValue_1) == 0x000240, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::CallFunc_Format_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCrossPromoDataReady, K2Node_CreateDelegate_OutputDelegate) == 0x000258, "Member 'W_PromoNewsWidget_C_OnCrossPromoDataReady::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");

// Function W_PromoNewsWidget.W_PromoNewsWidget_C.OnCloudImageReady
// 0x0018 (0x0018 - 0x0000)
struct W_PromoNewsWidget_C_OnCloudImageReady final
{
public:
	const class USQCdnFile*                       CdnFile;                                           // 0x0000(0x0008)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             CallFunc_GetAsTexture_ReturnValue;                 // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_PromoNewsWidget_C_OnCloudImageReady) == 0x000008, "Wrong alignment on W_PromoNewsWidget_C_OnCloudImageReady");
static_assert(sizeof(W_PromoNewsWidget_C_OnCloudImageReady) == 0x000018, "Wrong size on W_PromoNewsWidget_C_OnCloudImageReady");
static_assert(offsetof(W_PromoNewsWidget_C_OnCloudImageReady, CdnFile) == 0x000000, "Member 'W_PromoNewsWidget_C_OnCloudImageReady::CdnFile' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCloudImageReady, CallFunc_GetAsTexture_ReturnValue) == 0x000008, "Member 'W_PromoNewsWidget_C_OnCloudImageReady::CallFunc_GetAsTexture_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_PromoNewsWidget_C_OnCloudImageReady, CallFunc_IsValid_ReturnValue) == 0x000010, "Member 'W_PromoNewsWidget_C_OnCloudImageReady::CallFunc_IsValid_ReturnValue' has a wrong offset!");

}

