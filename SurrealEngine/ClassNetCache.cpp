
#include "Precomp.h"
#include "ClassNetCache.h"
#include "Packages/Core/UClass.h"
#include "Packages/Core/UFunction.h"
#include "Packages/Core/Properties/UProperty.h"
#include <algorithm>

std::map<UClass*, std::unique_ptr<ClassNetCache>>& ClassNetCache::GetCacheMap()
{
	static std::map<UClass*, std::unique_ptr<ClassNetCache>> cache;
	return cache;
}

ClassNetCache* ClassNetCache::Get(UClass* cls)
{
	if (!cls)
		return nullptr;

	auto& cache = GetCacheMap();
	auto it = cache.find(cls);
	if (it != cache.end())
		return it->second.get();

	// Insert a placeholder before recursing so a self-referential lookup (shouldn't happen for a
	// well-formed class hierarchy, but package data is a foreign input) can't infinite-loop.
	auto result = std::make_unique<ClassNetCache>();
	ClassNetCache* resultPtr = result.get();
	resultPtr->Class = cls;
	cache[cls] = std::move(result);

	UClass* superClass = UObject::TryCast<UClass>(cls->BaseStruct);
	ClassNetCache* super = superClass ? Get(superClass) : nullptr;
	resultPtr->super = super;
	resultPtr->fieldsBase = super ? super->GetMaxIndex() : 0;

	// This class's own directly-declared properties are the tail of Properties[] past whatever it
	// inherited (Properties[] is built in UStruct::Load as BaseStruct->Properties + this class's
	// own Children, in that order - see UStruct.cpp).
	size_t inheritedPropertyCount = superClass ? superClass->Properties.size() : 0;
	Array<UField*> ownNetFields;
	for (size_t i = inheritedPropertyCount; i < cls->Properties.size(); i++)
	{
		UProperty* prop = cls->Properties[i];
		if (AllFlags(prop->PropFlags, PropertyFlags::Net))
			ownNetFields.push_back(prop);
	}

	// This class's own directly-declared network functions - walk Children (the per-class linked
	// list UStruct::Load itself walks to build Properties[]), skipping overrides of a function
	// already indexed by a superclass.
	for (UField* child = cls->Children; child; child = child->Next)
	{
		UFunction* func = UObject::TryCast<UFunction>(child);
		if (func && AllFlags(func->FuncFlags, FunctionFlags::Net))
		{
			bool isOverride = false;
			for (ClassNetCache* c = super; c && !isOverride; c = c->super)
				for (UField* f : c->fields)
					if (f->Name == func->Name)
						isOverride = true;
			if (!isOverride)
				ownNetFields.push_back(func);
		}
	}

	// Sort by export-table position (UField::GetLinkerIndex() in the real engine - SurrealEngine's
	// UObject::exportIndex is the same thing), matching UClass::Link's
	// Sort(&NetFields(0),NetFields.Num()) with its Compare() using GetLinkerIndex(). This is what
	// makes the resulting index deterministic and identical between independently-compiled client
	// and server processes: it depends only on each field's fixed position in the shared .u file,
	// never on load order or anything decided at runtime.
	std::sort(ownNetFields.begin(), ownNetFields.end(), [](UField* a, UField* b)
	{
		return a->exportIndex < b->exportIndex;
	});

	resultPtr->fields = std::move(ownNetFields);
	return resultPtr;
}

UField* ClassNetCache::GetFromIndex(int index) const
{
	for (const ClassNetCache* c = this; c; c = c->super)
		if (index >= c->fieldsBase && index < c->fieldsBase + (int)c->fields.size())
			return c->fields[index - c->fieldsBase];
	return nullptr;
}

int ClassNetCache::GetFieldNetIndex(UField* field) const
{
	for (const ClassNetCache* c = this; c; c = c->super)
		for (size_t i = 0; i < c->fields.size(); i++)
			if (c->fields[i] == field)
				return c->fieldsBase + (int)i;
	return -1;
}
