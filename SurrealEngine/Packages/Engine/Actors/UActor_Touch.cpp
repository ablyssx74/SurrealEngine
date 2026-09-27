
#include "Precomp.h"
#include "UActor.h"
#include "VM/ScriptCall.h"
#include "Engine.h"

void UActor::CheckPendingTouch()
{
	if (engine->LaunchInfo.ue1Version >= 400)
	{
		if (PendingTouch())
		{
			CallEvent(PendingTouch(), EventName::PostTouch, { ExpressionValue::ObjectValue(this) });
			if (PendingTouch())
			{
				UActor* cur = PendingTouch();
				UActor* next = cur->PendingTouch();
				PendingTouch() = next;
				cur->PendingTouch() = nullptr;
			}
		}
	}
}

void UActor::Touch(UActor* actor)
{
	// Don't setup touch if any object has been destroyed
	if (bDeleteMe() || actor->bDeleteMe())
		return;

	if (engine->LaunchInfo.IsUnrealTournament_469())
	{
		auto TouchingArray = Touching_UT469();
		auto TouchingArray2 = actor->Touching_UT469();

		// Do nothing if actors are already touching
		for (size_t i = 0; i < TouchingArray.size(); i++)
		{
			if (TouchingArray[i] == actor)
				return;
		}

		// UT469 made Touching a real dynamic array specifically to remove the original engine's
		// fixed 4-simultaneous-touch limit - so, unlike the array below, finding no empty slot
		// here means grow the array by one slot rather than giving up (an empty/newly-spawned
		// actor's Touching array starts with zero elements, so without this every single Touch()
		// call - including the very first one on any actor, e.g. walking over a weapon pickup -
		// would silently do nothing).
		int slot1 = -1, slot2 = -1;
		for (size_t i = 0; i < TouchingArray.size(); i++)
		{
			if (slot1 == -1 && TouchingArray[i] == nullptr)
				slot1 = (int)i;
		}
		if (slot1 == -1)
		{
			slot1 = (int)TouchingArray.size();
			TouchingArray.push_back(nullptr);
			TouchEventSentUT469.push_back(false);
		}
		while (TouchEventSentUT469.size() < TouchingArray.size())
			TouchEventSentUT469.push_back(false);

		for (size_t i = 0; i < TouchingArray2.size(); i++)
		{
			if (slot2 == -1 && TouchingArray2[i] == nullptr)
				slot2 = (int)i;
		}
		if (slot2 == -1)
		{
			slot2 = (int)TouchingArray2.size();
			TouchingArray2.push_back(nullptr);
			actor->TouchEventSentUT469.push_back(false);
		}
		while (actor->TouchEventSentUT469.size() < TouchingArray2.size())
			actor->TouchEventSentUT469.push_back(false);

		// Setup links first so Destroy or recursive Touch calls always finds the touch binding
		TouchingArray[slot1] = actor;
		TouchEventSentUT469[slot1] = true;
		TouchingArray2[slot2] = this;
		actor->TouchEventSentUT469[slot2] = false;

		// Notify unrealscript for first actor
		CallEvent(this, EventName::Touch, { ExpressionValue::ObjectValue(actor) });

		// Notify unrealscript for second actor
		if (!actor->bDeleteMe())
		{
			for (size_t i = 0; i < TouchingArray2.size(); i++)
			{
				if (TouchingArray2[i] == this && !actor->TouchEventSentUT469[i])
				{
					actor->TouchEventSentUT469[i] = true;
					CallEvent(actor, EventName::Touch, { ExpressionValue::ObjectValue(this) });
					break;
				}
			}
		}
	}
	else
	{
		auto TouchingArray = Touching();
		auto TouchingArray2 = actor->Touching();

		// Do nothing if actors are already touching
		for (int i = 0; i < TouchingArraySize; i++)
		{
			if (TouchingArray[i] == actor)
				return;
		}

		// Only setup touch if we have room in both arrays
		int slot1 = -1, slot2 = -1;
		for (int i = 0; i < TouchingArraySize; i++)
		{
			if (slot1 == -1 && TouchingArray[i] == nullptr)
				slot1 = i;
			if (slot2 == -1 && TouchingArray2[i] == nullptr)
				slot2 = i;
		}
		if (slot1 == -1 || slot2 == -1)
			return;

		// Setup links first so Destroy or recursive Touch calls always finds the touch binding
		TouchingArray[slot1] = actor;
		TouchEventSent[slot1] = true;
		TouchingArray2[slot2] = this;
		actor->TouchEventSent[slot2] = false;

		// Notify unrealscript for first actor
		CallEvent(this, EventName::Touch, { ExpressionValue::ObjectValue(actor) });

		// Notify unrealscript for second actor
		if (!actor->bDeleteMe())
		{
			for (int i = 0; i < TouchingArraySize; i++)
			{
				if (TouchingArray2[i] == this && !actor->TouchEventSent[i])
				{
					actor->TouchEventSent[i] = true;
					CallEvent(actor, EventName::Touch, { ExpressionValue::ObjectValue(this) });
					break;
				}
			}
		}
	}
}

void UActor::UnTouch(UActor* actor)
{
	if (engine->LaunchInfo.IsUnrealTournament_469())
	{
		// Touching is a real dynamic array under UT469 (see Touch()'s UT469 branch) - a completely
		// different in-memory layout (array header: pointer/count/capacity) than the fixed 4-element
		// inline array the version-agnostic path below assumes. Reading/writing it through that
		// wrong layout would misinterpret the array header's own bytes as actor pointers.
		auto TouchingArray = Touching_UT469();
		auto TouchingArray2 = actor->Touching_UT469();

		if (!bDeleteMe())
		{
			for (size_t i = 0; i < TouchingArray.size(); i++)
			{
				if (TouchingArray[i] == actor)
				{
					TouchingArray[i] = nullptr;
					if (i < TouchEventSentUT469.size() && TouchEventSentUT469[i])
					{
						TouchEventSentUT469[i] = false;
						CallEvent(this, EventName::UnTouch, { ExpressionValue::ObjectValue(actor) });
					}
				}
			}
		}

		if (!actor->bDeleteMe())
		{
			for (size_t i = 0; i < TouchingArray2.size(); i++)
			{
				if (TouchingArray2[i] == this)
				{
					TouchingArray2[i] = nullptr;
					if (i < actor->TouchEventSentUT469.size() && actor->TouchEventSentUT469[i])
					{
						actor->TouchEventSentUT469[i] = false;
						CallEvent(actor, EventName::UnTouch, { ExpressionValue::ObjectValue(this) });
					}
				}
			}
		}
		return;
	}

	auto TouchingArray = Touching();
	auto TouchingArray2 = actor->Touching();

	if (!bDeleteMe())
	{
		for (int i = 0; i < TouchingArraySize; i++)
		{
			if (TouchingArray[i] == actor)
			{
				TouchingArray[i] = nullptr;
				if (TouchEventSent[i])
				{
					TouchEventSent[i] = false;
					CallEvent(this, EventName::UnTouch, { ExpressionValue::ObjectValue(actor) });
				}
			}
		}
	}

	if (!actor->bDeleteMe())
	{
		for (int i = 0; i < TouchingArraySize; i++)
		{
			if (TouchingArray2[i] == this)
			{
				TouchingArray2[i] = nullptr;
				if (actor->TouchEventSent[i])
				{
					actor->TouchEventSent[i] = false;
					CallEvent(actor, EventName::UnTouch, { ExpressionValue::ObjectValue(this) });
				}
			}
		}
	}
}
