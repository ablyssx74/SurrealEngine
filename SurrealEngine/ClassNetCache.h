#pragma once

#include <map>
#include "Utils/Array.h"

class UClass;
class UField;

// Reimplements UE1's FClassNetCache (UnCoreNet.cpp) / UClass::Link (UnClass.cpp) net-property
// indexing scheme, reverse-engineered this session from a real 1997-1999 UT99 engine source
// excerpt obtained separately - never copied, just the understood algorithm rewritten fresh.
//
// Every replicated property and network function a class declares gets a small integer index
// ("FieldNetIndex") that's what actually goes over the wire (Bunch.ReadInt(ClassCache->
// GetMaxIndex())) instead of a name or pointer - real UT99 clients and servers derive the exact
// same index for the exact same field without ever agreeing on it explicitly, because both sides
// compute it the same deterministic way from the same compiled .u package data:
//   - A class's *own* directly-declared Net-flagged properties and functions (not inherited ones -
//     those already have an index, assigned once by whichever class first declared them) are
//     sorted by their position in the package's export table (UField::GetLinkerIndex() in the real
//     engine - SurrealEngine's UObject::exportIndex, already populated by Package::GetUObject/
//     LoadExportObject, is exactly the same thing).
//   - Each class's own fields are numbered starting right after its superclass's last index
//     (FieldsBase = Super->GetMaxIndex()), chaining the whole inheritance hierarchy into one
//     contiguous index space.
// Since this only depends on the class hierarchy and each package's fixed on-disk export order -
// never anything decided at runtime - it comes out identical on a real client, a real server, and
// this reimplementation, as long as all three loaded the same compiled packages (guaranteed for
// same-version UT99 play).
class ClassNetCache
{
public:
	// Builds (and caches) the net cache for a class, recursively building its superclass's cache
	// first if needed. The result is owned by the cache and remains valid for the process lifetime
	// (packages are never unloaded once loaded).
	static ClassNetCache* Get(UClass* cls);

	// One past the highest FieldNetIndex any field of this class (own or inherited) can have -
	// what Bunch.ReadInt()'s Max bound should be when decoding a RepIndex for this class.
	int GetMaxIndex() const { return fieldsBase + (int)fields.size(); }

	// Looks up the field a given wire index refers to, searching this class's own fields first and
	// then walking up to superclasses as needed (an index can belong to any ancestor). Returns
	// nullptr for an index that isn't a real field of this class or any of its superclasses (e.g.
	// past GetMaxIndex(), which real UE1 traffic uses as the "no more replicated fields" sentinel).
	UField* GetFromIndex(int index) const;

	// The reverse of GetFromIndex - mainly useful for tests/diagnostics.
	int GetFieldNetIndex(UField* field) const;

	UClass* Class = nullptr;

private:
	ClassNetCache* super = nullptr;
	int fieldsBase = 0;
	Array<UField*> fields; // fields[i] has FieldNetIndex == fieldsBase + i

	static std::map<UClass*, std::unique_ptr<ClassNetCache>>& GetCacheMap();
};
