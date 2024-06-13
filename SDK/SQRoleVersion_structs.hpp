#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SQRoleVersion

#include "Basic.hpp"

#include "ESQBiome_structs.hpp"


namespace SDK
{

// UserDefinedStruct SQRoleVersion.SQRoleVersion
// 0x0030 (0x0030 - 0x0000)
struct FSQRoleVersion final
{
public:
	ESQBiome                                      Biome_2_D719532142745FEC3461AB9F16BA3047;          // 0x0000(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_32B0[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TSoftClassPtr<class UClass>                   Role_5_0B1D95B041C0F0B8DCA4CDB248BF9B85;           // 0x0008(0x0028)(Edit, BlueprintVisible, HasGetValueTypeHash)
};
static_assert(alignof(FSQRoleVersion) == 0x000008, "Wrong alignment on FSQRoleVersion");
static_assert(sizeof(FSQRoleVersion) == 0x000030, "Wrong size on FSQRoleVersion");
static_assert(offsetof(FSQRoleVersion, Biome_2_D719532142745FEC3461AB9F16BA3047) == 0x000000, "Member 'FSQRoleVersion::Biome_2_D719532142745FEC3461AB9F16BA3047' has a wrong offset!");
static_assert(offsetof(FSQRoleVersion, Role_5_0B1D95B041C0F0B8DCA4CDB248BF9B85) == 0x000008, "Member 'FSQRoleVersion::Role_5_0B1D95B041C0F0B8DCA4CDB248BF9B85' has a wrong offset!");

}
