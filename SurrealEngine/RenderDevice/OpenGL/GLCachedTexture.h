#pragma once

#include "GLHandles.h"

class GLCachedTexture
{
public:
	std::shared_ptr<GLTexture2D> Texture;
	int RealtimeChangeCount = 0;
	int DummyMipmapCount = 0;

	float UScale = 0.0f;
	float VScale = 0.0f;
	float PanX = 0.0f;
	float PanY = 0.0f;
	float UMult = 0.0f;
	float VMult = 0.0f;

	// Average color of the source texture data (P8 palette indices run through the palette),
	// computed once at upload time. Used on Haiku to approximate a real texture's color when
	// sampling it directly renders black on that platform's driver - see
	// GLRenderDevice::DrawComplexSurfaceFaces(). Defaults to white so anything that doesn't
	// compute it (non-P8 textures, nulltex) behaves as a no-op multiplier.
	float AverageColorR = 1.0f;
	float AverageColorG = 1.0f;
	float AverageColorB = 1.0f;
};
