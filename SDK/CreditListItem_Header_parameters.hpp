#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: CreditListItem_Header

#include "Basic.hpp"


namespace SDK::Params
{

// Function CreditListItem_Header.CreditListItem_Header_C.Title Text
// 0x0018 (0x0018 - 0x0000)
struct CreditListItem_Header_C_Title_Text final
{
public:
	class FText                                   ReturnValue;                                       // 0x0000(0x0018)(Parm, OutParm, ReturnParm)
};
static_assert(alignof(CreditListItem_Header_C_Title_Text) == 0x000008, "Wrong alignment on CreditListItem_Header_C_Title_Text");
static_assert(sizeof(CreditListItem_Header_C_Title_Text) == 0x000018, "Wrong size on CreditListItem_Header_C_Title_Text");
static_assert(offsetof(CreditListItem_Header_C_Title_Text, ReturnValue) == 0x000000, "Member 'CreditListItem_Header_C_Title_Text::ReturnValue' has a wrong offset!");

}
