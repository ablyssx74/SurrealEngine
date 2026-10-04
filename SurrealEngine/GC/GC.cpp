
#include "Precomp.h"
#include "GC.h"

static GCRootNode* roots;
static GCAllocation* allocations;
static GCStats stats;

GCRootNode::GCRootNode()
{
	next = roots;
	prev = nullptr;
	if (roots)
		roots->prev = this;
	roots = this;
}

GCRootNode::~GCRootNode()
{
	if (prev)
	{
		prev->next = next;
	}
	else
	{
		roots = next;
	}

	if (next)
	{
		next->prev = prev;
	}
}

GCAllocation* GC::GetAllocations()
{
	return allocations;
}

GCAllocation* GC::AllocMemory(size_t size)
{
	size_t memsize = sizeof(GCAllocation) + size;
	GCAllocation* allocation = (GCAllocation*)calloc(1, memsize);
	if (allocation == nullptr)
		throw std::bad_alloc();
	allocation->allocklistNext = allocations;
	allocation->memsize = memsize;
	allocation->unreferencedFlag = true;
	allocations = allocation;
	stats.numObjects++;
	stats.memoryUsage += memsize;
	return allocation;
}

void GC::FreeMemory(GCAllocation* allocation)
{
	// Used when an object's constructor threw: the allocation was already linked into the object list (objects
	// allocated by the constructor itself may sit in front of it), so unlink it before freeing. Leaving a freed
	// node in the list corrupts it - later walks can loop forever or read freed memory.
	GCAllocation* prev = nullptr;
	for (GCAllocation* cur = allocations; cur; prev = cur, cur = cur->allocklistNext)
	{
		if (cur == allocation)
		{
			if (prev)
				prev->allocklistNext = cur->allocklistNext;
			else
				allocations = cur->allocklistNext;
			stats.numObjects--;
			stats.memoryUsage -= allocation->memsize;
			break;
		}
	}
	free(allocation);
}

void GC::Collect()
{
	GCAllocation* marklist = nullptr;
	for (GCRootNode* root = roots; root != nullptr; root = root->next)
		marklist = GC::MarkObject(marklist, root->obj);

	while (marklist)
	{
		marklist = Mark(marklist);
	}

	Sweep();
}

GCStats GC::GetStats()
{
	return stats;
}

GCAllocation* GC::Mark(GCAllocation* marklist)
{
	GCAllocation* marklistout = nullptr;
	for (GCAllocation* allocation = marklist; allocation != nullptr; allocation = allocation->marklistNext)
	{
		marklistout = allocation->object()->Mark(marklistout);
	}
	return marklistout;
}

void GC::Sweep()
{
	GCAllocation* prev = nullptr;
	GCAllocation* cur = allocations;
	while (cur)
	{
		if (cur->unreferencedFlag)
		{
			GCAllocation* unreferenced = cur;

			cur = cur->allocklistNext;
			if (prev)
				prev->allocklistNext = cur;
			else
				allocations = cur;

			stats.memoryUsage -= unreferenced->memsize;
			stats.numObjects--;

			GCObject* obj = unreferenced->object();
			obj->~GCObject();
			free(unreferenced);
		}
		else
		{
			cur->unreferencedFlag = true;
			prev = cur;
			cur = cur->allocklistNext;
		}
	}
}
