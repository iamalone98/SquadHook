#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPI_Items

#include "Basic.hpp"

#include "CoreUObject_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BPI_Items.BPI_Items_C
// 0x0000 (0x0028 - 0x0028)
class IBPI_Items_C final : public IInterface
{
public:
	void Player_Enter_Radius(class APlayerController* Player, bool Can_Pickup);
	void Player_Left_Radius(class APlayerController* Player);
	void Pickup_Item(class APlayerController* Player);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BPI_Items_C">();
	}
	static class IBPI_Items_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<IBPI_Items_C>();
	}
};
static_assert(alignof(IBPI_Items_C) == 0x000008, "Wrong alignment on IBPI_Items_C");
static_assert(sizeof(IBPI_Items_C) == 0x000028, "Wrong size on IBPI_Items_C");

}
