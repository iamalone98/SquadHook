#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_GridButton_SL_FTOrders

#include "Basic.hpp"

#include "W_GridButton_classes.hpp"
#include "Engine_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_GridButton_SL_FTOrders.W_GridButton_SL_FTOrders_C
// 0x0008 (0x0310 - 0x0308)
class UW_GridButton_SL_FTOrders_C final : public UW_GridButton_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_W_GridButton_SL_FTOrders_C;         // 0x0308(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_W_GridButton_SL_FTOrders(int32 EntryPoint);
	void Update_Appearance();
	void Get_Color(struct FLinearColor* Param_Icon_Color);
	void Get_Text(class FText* Text);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_GridButton_SL_FTOrders_C">();
	}
	static class UW_GridButton_SL_FTOrders_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_GridButton_SL_FTOrders_C>();
	}
};
static_assert(alignof(UW_GridButton_SL_FTOrders_C) == 0x000008, "Wrong alignment on UW_GridButton_SL_FTOrders_C");
static_assert(sizeof(UW_GridButton_SL_FTOrders_C) == 0x000310, "Wrong size on UW_GridButton_SL_FTOrders_C");
static_assert(offsetof(UW_GridButton_SL_FTOrders_C, UberGraphFrame_W_GridButton_SL_FTOrders_C) == 0x000308, "Member 'UW_GridButton_SL_FTOrders_C::UberGraphFrame_W_GridButton_SL_FTOrders_C' has a wrong offset!");

}
