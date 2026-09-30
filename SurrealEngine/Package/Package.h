#pragma once

#include "GC/GC.h"
#include "PackageFlags.h"
#include "PackageTables.h"
#include "ObjectFlags.h"
#include "NameString.h"
#include <functional>

class PackageManager;
class PackageStream;
class ObjectStream;
class UObject;
class UClass;

class Package : public GCObject
{
public:
	Package(PackageManager* packageManager, const NameString& name, const std::string& filepath);
	~Package();

	UObject* NewObject(const NameString& objname, UClass* objclass, ObjectFlags flags, bool initProperties = true);

	UObject* GetUObject(int objref);
	UObject* GetUObject(const NameString& className, const NameString& objectName) { return GetUObject(className, objectName, {}, true); }
	UObject* GetUObject(const NameString& className, const NameString& objectName, const NameString& group, bool ignoreGroup = false);

	UClass* GetClass(const NameString& className);

	void LoadAll();
	void Save(UObject* object = nullptr, const std::string& filename = {});

	const NameString& GetName(int index) const;
	int GetVersion() const { return Version; }
	NameString GetPackageName() const { return Name; }
	std::string GetPackageFileName() const { return FileName; }
	std::string GetPackageFilePath() const { return FilePath; }
	std::string GetPackageFileExtension() const { return FileExtension; }

	PackageManager* GetPackageManager() { return Packages; }

	ExportTableEntry* GetExportEntry(int objref);
	ImportTableEntry* GetImportEntry(int objref);
	int FindObjectReference(const NameString& className, const NameString& objectName, const NameString& group, bool ignoreGroup = false);

	std::string GetExportName(int objref);

	// Number of entries in this package's export table - the size of the flat, package-relative
	// object-index space that RemoteConnection's PackageMap equivalent sums across packages (see
	// UPackageMap::Compute/ObjectToIndex/IndexToObject in real UT99 source: a connection-wide object
	// index is just a running sum of each known package's own export count, in USES-message order).
	int GetExportCount() const { return (int)ExportTable.size(); }

	// The package's 16-byte GUID, as stored in its header - used to cross-check against the
	// GUID= a server's USES message announced for this package.
	const uint8_t* GetGuid() const { return Guid; }

	// This package's export count as of a given point in its own save history (the package header's
	// "generations" list, one entry per time the package was ever saved, each recording that save's
	// ExportCount/NameCount - a real, distinct concept from Version). A server's USES GEN= value is
	// exactly this: which of ITS package's generations the wire's flat object-index space was built
	// against. If a locally-installed copy of the same package has since grown its export table
	// (e.g. a newer content patch added objects), computing this connection's object indices against
	// our full, current export count would disagree with the server's index space for every later
	// package too - the client needs to size this package down to what the server's generation
	// actually had. Mirrors UPackageMap::Compute()'s clipping, Core/Src/UnCoreNet.cpp:252-260:
	// remoteGeneration is 1-based (as it appears on the wire); 0 or anything at or past this
	// package's own generation count means "use the full, current export table" - either the server
	// didn't send GEN= at all, or its copy is the same generation as ours (or newer, which this
	// engine has no way to size up to and falls back to its own full count for, same as real UT99).
	//
	// Two details matter for agreeing with a real server's index space: the generation table's own
	// count is used whenever the server's generation exists locally (including the current one),
	// exactly as UPackageMap::Compute does - and the fallback is the export count stored in the file,
	// never GetExportCount(), because ReadTables() appends stub exports for native classes (e.g. +43
	// for Engine, +25 for Core) that the server's copy of the package doesn't have.
	int GetExportCountForGeneration(int remoteGeneration) const
	{
		int localGeneration = (int)Generations.size();
		int actualRemoteGeneration = (remoteGeneration <= 0) ? localGeneration : remoteGeneration;
		if (actualRemoteGeneration > 0 && actualRemoteGeneration <= localGeneration)
			return (int)Generations[actualRemoteGeneration - 1].ExportCount;
		return (int)FileExportCount;
	}

	template<class T> Array<T*> GetAllObjects();

private:
	GCAllocation* Mark(GCAllocation* marklist) override;

	void ReadTables();
	std::unique_ptr<ObjectStream> OpenObjectStream(int index, const NameString& name, UClass* base);
	void LoadExportObject(int index);

	PackageManager* Packages = nullptr;
	NameString Name;
	std::string FilePath;
	std::string FileName;
	std::string FileExtension;

	uint32_t FileExportCount = 0; // export count as stored in the file header, before ReadTables() appends native class stubs
	int Version = 0;
	int LicenseeMode = 0;
	PackageFlags Flags = PackageFlags::NoFlags;
	Array<NameTableEntry> NameTable;
	Array<ExportTableEntry> ExportTable;
	Array<ImportTableEntry> ImportTable;
	uint8_t Guid[16] = {};

	struct PackageGeneration
	{
		uint32_t ExportCount = 0;
		uint32_t NameCount = 0;
	};
	Array<PackageGeneration> Generations;

	std::map<NameString, int> NameHash;

	Array<UObject*> ExportObjects;

	Package(const Package&) = delete;
	Package& operator=(const Package&) = delete;

	friend class PackageManager;
	friend class UObject;
	friend class PackageWriter;
};
