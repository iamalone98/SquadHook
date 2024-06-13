#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: ClothingSystemRuntimeNv

#include "Basic.hpp"

#include "ClothingSystemRuntimeNv_structs.hpp"
#include "ClothingSystemRuntimeCommon_structs.hpp"
#include "ClothingSystemRuntimeCommon_classes.hpp"
#include "CoreUObject_structs.hpp"
#include "ClothingSystemRuntimeInterface_classes.hpp"


namespace SDK
{

// Class ClothingSystemRuntimeNv.ClothConfigNv
// 0x0118 (0x0140 - 0x0028)
class UClothConfigNv final : public UClothConfigCommon
{
public:
	EClothingWindMethodNv                         ClothingWindMethod;                                // 0x0028(0x0001)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_29DB[0x3];                                     // 0x0029(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FClothConstraintSetupNv                VerticalConstraint;                                // 0x002C(0x0010)(Edit, NoDestructor, NativeAccessSpecifierPublic)
	struct FClothConstraintSetupNv                HorizontalConstraint;                              // 0x003C(0x0010)(Edit, NoDestructor, NativeAccessSpecifierPublic)
	struct FClothConstraintSetupNv                BendConstraint;                                    // 0x004C(0x0010)(Edit, NoDestructor, NativeAccessSpecifierPublic)
	struct FClothConstraintSetupNv                ShearConstraint;                                   // 0x005C(0x0010)(Edit, NoDestructor, NativeAccessSpecifierPublic)
	float                                         SelfCollisionRadius;                               // 0x006C(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         SelfCollisionStiffness;                            // 0x0070(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         SelfCollisionCullScale;                            // 0x0074(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector                                Damping;                                           // 0x0078(0x000C)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         Friction;                                          // 0x0084(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         WindDragCoefficient;                               // 0x0088(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         WindLiftCoefficient;                               // 0x008C(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector                                LinearDrag;                                        // 0x0090(0x000C)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector                                AngularDrag;                                       // 0x009C(0x000C)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector                                LinearInertiaScale;                                // 0x00A8(0x000C)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector                                AngularInertiaScale;                               // 0x00B4(0x000C)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector                                CentrifugalInertiaScale;                           // 0x00C0(0x000C)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         SolverFrequency;                                   // 0x00CC(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         StiffnessFrequency;                                // 0x00D0(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         GravityScale;                                      // 0x00D4(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector                                GravityOverride;                                   // 0x00D8(0x000C)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	bool                                          bUseGravityOverride;                               // 0x00E4(0x0001)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_29DC[0x3];                                     // 0x00E5(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         TetherStiffness;                                   // 0x00E8(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         TetherLimit;                                       // 0x00EC(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         CollisionThickness;                                // 0x00F0(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         AnimDriveSpringStiffness;                          // 0x00F4(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         AnimDriveDamperStiffness;                          // 0x00F8(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	EClothingWindMethod_Legacy                    WindMethod;                                        // 0x00FC(0x0001)(ZeroConstructor, Deprecated, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_29DD[0x3];                                     // 0x00FD(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FClothConstraintSetup_Legacy           VerticalConstraintConfig;                          // 0x0100(0x0010)(Deprecated, NoDestructor, NativeAccessSpecifierPublic)
	struct FClothConstraintSetup_Legacy           HorizontalConstraintConfig;                        // 0x0110(0x0010)(Deprecated, NoDestructor, NativeAccessSpecifierPublic)
	struct FClothConstraintSetup_Legacy           BendConstraintConfig;                              // 0x0120(0x0010)(Deprecated, NoDestructor, NativeAccessSpecifierPublic)
	struct FClothConstraintSetup_Legacy           ShearConstraintConfig;                             // 0x0130(0x0010)(Deprecated, NoDestructor, NativeAccessSpecifierPublic)

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ClothConfigNv">();
	}
	static class UClothConfigNv* GetDefaultObj()
	{
		return GetDefaultObjImpl<UClothConfigNv>();
	}
};
static_assert(alignof(UClothConfigNv) == 0x000008, "Wrong alignment on UClothConfigNv");
static_assert(sizeof(UClothConfigNv) == 0x000140, "Wrong size on UClothConfigNv");
static_assert(offsetof(UClothConfigNv, ClothingWindMethod) == 0x000028, "Member 'UClothConfigNv::ClothingWindMethod' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, VerticalConstraint) == 0x00002C, "Member 'UClothConfigNv::VerticalConstraint' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, HorizontalConstraint) == 0x00003C, "Member 'UClothConfigNv::HorizontalConstraint' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, BendConstraint) == 0x00004C, "Member 'UClothConfigNv::BendConstraint' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, ShearConstraint) == 0x00005C, "Member 'UClothConfigNv::ShearConstraint' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, SelfCollisionRadius) == 0x00006C, "Member 'UClothConfigNv::SelfCollisionRadius' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, SelfCollisionStiffness) == 0x000070, "Member 'UClothConfigNv::SelfCollisionStiffness' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, SelfCollisionCullScale) == 0x000074, "Member 'UClothConfigNv::SelfCollisionCullScale' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, Damping) == 0x000078, "Member 'UClothConfigNv::Damping' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, Friction) == 0x000084, "Member 'UClothConfigNv::Friction' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, WindDragCoefficient) == 0x000088, "Member 'UClothConfigNv::WindDragCoefficient' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, WindLiftCoefficient) == 0x00008C, "Member 'UClothConfigNv::WindLiftCoefficient' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, LinearDrag) == 0x000090, "Member 'UClothConfigNv::LinearDrag' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, AngularDrag) == 0x00009C, "Member 'UClothConfigNv::AngularDrag' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, LinearInertiaScale) == 0x0000A8, "Member 'UClothConfigNv::LinearInertiaScale' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, AngularInertiaScale) == 0x0000B4, "Member 'UClothConfigNv::AngularInertiaScale' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, CentrifugalInertiaScale) == 0x0000C0, "Member 'UClothConfigNv::CentrifugalInertiaScale' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, SolverFrequency) == 0x0000CC, "Member 'UClothConfigNv::SolverFrequency' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, StiffnessFrequency) == 0x0000D0, "Member 'UClothConfigNv::StiffnessFrequency' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, GravityScale) == 0x0000D4, "Member 'UClothConfigNv::GravityScale' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, GravityOverride) == 0x0000D8, "Member 'UClothConfigNv::GravityOverride' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, bUseGravityOverride) == 0x0000E4, "Member 'UClothConfigNv::bUseGravityOverride' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, TetherStiffness) == 0x0000E8, "Member 'UClothConfigNv::TetherStiffness' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, TetherLimit) == 0x0000EC, "Member 'UClothConfigNv::TetherLimit' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, CollisionThickness) == 0x0000F0, "Member 'UClothConfigNv::CollisionThickness' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, AnimDriveSpringStiffness) == 0x0000F4, "Member 'UClothConfigNv::AnimDriveSpringStiffness' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, AnimDriveDamperStiffness) == 0x0000F8, "Member 'UClothConfigNv::AnimDriveDamperStiffness' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, WindMethod) == 0x0000FC, "Member 'UClothConfigNv::WindMethod' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, VerticalConstraintConfig) == 0x000100, "Member 'UClothConfigNv::VerticalConstraintConfig' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, HorizontalConstraintConfig) == 0x000110, "Member 'UClothConfigNv::HorizontalConstraintConfig' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, BendConstraintConfig) == 0x000120, "Member 'UClothConfigNv::BendConstraintConfig' has a wrong offset!");
static_assert(offsetof(UClothConfigNv, ShearConstraintConfig) == 0x000130, "Member 'UClothConfigNv::ShearConstraintConfig' has a wrong offset!");

// Class ClothingSystemRuntimeNv.ClothingSimulationFactoryNv
// 0x0000 (0x0028 - 0x0028)
class UClothingSimulationFactoryNv final : public UClothingSimulationFactory
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ClothingSimulationFactoryNv">();
	}
	static class UClothingSimulationFactoryNv* GetDefaultObj()
	{
		return GetDefaultObjImpl<UClothingSimulationFactoryNv>();
	}
};
static_assert(alignof(UClothingSimulationFactoryNv) == 0x000008, "Wrong alignment on UClothingSimulationFactoryNv");
static_assert(sizeof(UClothingSimulationFactoryNv) == 0x000028, "Wrong size on UClothingSimulationFactoryNv");

// Class ClothingSystemRuntimeNv.ClothingSimulationInteractorNv
// 0x0010 (0x00A0 - 0x0090)
class UClothingSimulationInteractorNv final : public UClothingSimulationInteractor
{
public:
	uint8                                         Pad_29DE[0x10];                                    // 0x0090(0x0010)(Fixing Struct Size After Last Property [ Dumper-7 ])

public:
	void SetAnimDriveDamperStiffness(float InStiffness);

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ClothingSimulationInteractorNv">();
	}
	static class UClothingSimulationInteractorNv* GetDefaultObj()
	{
		return GetDefaultObjImpl<UClothingSimulationInteractorNv>();
	}
};
static_assert(alignof(UClothingSimulationInteractorNv) == 0x000008, "Wrong alignment on UClothingSimulationInteractorNv");
static_assert(sizeof(UClothingSimulationInteractorNv) == 0x0000A0, "Wrong size on UClothingSimulationInteractorNv");

// Class ClothingSystemRuntimeNv.ClothPhysicalMeshDataNv_Legacy
// 0x0040 (0x0120 - 0x00E0)
class UClothPhysicalMeshDataNv_Legacy final : public UClothPhysicalMeshDataBase_Legacy
{
public:
	TArray<float>                                 MaxDistances;                                      // 0x00E0(0x0010)(ZeroConstructor, NativeAccessSpecifierPublic)
	TArray<float>                                 BackstopDistances;                                 // 0x00F0(0x0010)(ZeroConstructor, NativeAccessSpecifierPublic)
	TArray<float>                                 BackstopRadiuses;                                  // 0x0100(0x0010)(ZeroConstructor, NativeAccessSpecifierPublic)
	TArray<float>                                 AnimDriveMultipliers;                              // 0x0110(0x0010)(ZeroConstructor, NativeAccessSpecifierPublic)

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ClothPhysicalMeshDataNv_Legacy">();
	}
	static class UClothPhysicalMeshDataNv_Legacy* GetDefaultObj()
	{
		return GetDefaultObjImpl<UClothPhysicalMeshDataNv_Legacy>();
	}
};
static_assert(alignof(UClothPhysicalMeshDataNv_Legacy) == 0x000008, "Wrong alignment on UClothPhysicalMeshDataNv_Legacy");
static_assert(sizeof(UClothPhysicalMeshDataNv_Legacy) == 0x000120, "Wrong size on UClothPhysicalMeshDataNv_Legacy");
static_assert(offsetof(UClothPhysicalMeshDataNv_Legacy, MaxDistances) == 0x0000E0, "Member 'UClothPhysicalMeshDataNv_Legacy::MaxDistances' has a wrong offset!");
static_assert(offsetof(UClothPhysicalMeshDataNv_Legacy, BackstopDistances) == 0x0000F0, "Member 'UClothPhysicalMeshDataNv_Legacy::BackstopDistances' has a wrong offset!");
static_assert(offsetof(UClothPhysicalMeshDataNv_Legacy, BackstopRadiuses) == 0x000100, "Member 'UClothPhysicalMeshDataNv_Legacy::BackstopRadiuses' has a wrong offset!");
static_assert(offsetof(UClothPhysicalMeshDataNv_Legacy, AnimDriveMultipliers) == 0x000110, "Member 'UClothPhysicalMeshDataNv_Legacy::AnimDriveMultipliers' has a wrong offset!");

}

