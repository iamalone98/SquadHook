#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Small_shack_1

#include "Basic.hpp"

#include "Engine_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass small_shack_1.small_shack_1_C
// 0x0030 (0x0258 - 0x0228)
class ASmall_shack_1_C final : public AActor
{
public:
	class UStaticMeshComponent*                   Afg_house_smallv2;                                 // 0x0228(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh4;                                       // 0x0230(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh3;                                       // 0x0238(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh2;                                       // 0x0240(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh1;                                       // 0x0248(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UArrowComponent*                        Arrow1;                                            // 0x0250(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"small_shack_1_C">();
	}
	static class ASmall_shack_1_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ASmall_shack_1_C>();
	}
};
static_assert(alignof(ASmall_shack_1_C) == 0x000008, "Wrong alignment on ASmall_shack_1_C");
static_assert(sizeof(ASmall_shack_1_C) == 0x000258, "Wrong size on ASmall_shack_1_C");
static_assert(offsetof(ASmall_shack_1_C, Afg_house_smallv2) == 0x000228, "Member 'ASmall_shack_1_C::Afg_house_smallv2' has a wrong offset!");
static_assert(offsetof(ASmall_shack_1_C, StaticMesh4) == 0x000230, "Member 'ASmall_shack_1_C::StaticMesh4' has a wrong offset!");
static_assert(offsetof(ASmall_shack_1_C, StaticMesh3) == 0x000238, "Member 'ASmall_shack_1_C::StaticMesh3' has a wrong offset!");
static_assert(offsetof(ASmall_shack_1_C, StaticMesh2) == 0x000240, "Member 'ASmall_shack_1_C::StaticMesh2' has a wrong offset!");
static_assert(offsetof(ASmall_shack_1_C, StaticMesh1) == 0x000248, "Member 'ASmall_shack_1_C::StaticMesh1' has a wrong offset!");
static_assert(offsetof(ASmall_shack_1_C, Arrow1) == 0x000250, "Member 'ASmall_shack_1_C::Arrow1' has a wrong offset!");

}
