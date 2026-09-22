/**
 * OpenAL cross platform audio library
 * Copyright (C) 2018 by authors.
 * This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 *  License along with this library; if not, write to the
 *  Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * Or go to http://www.gnu.org/copyleft/lgpl.html
 */

#include "config.h"

#include "haiku.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "almalloc.h"
#include "alnumeric.h"
#include "core/device.h"
#include "core/logging.h"

#include <media/MediaDefs.h>
#include <media/SoundPlayer.h>


namespace {

constexpr char defaultDeviceName[] = "Default Device";

struct HaikuBackend final : public BackendBase {
    HaikuBackend(DeviceBase *device) noexcept : BackendBase{device} { }
    ~HaikuBackend() override;

    void playBuffer(void *buffer, size_t size) noexcept;
    static void playBufferC(void *cookie, void *buffer, size_t size,
        const media_raw_audio_format &format) noexcept
    {
        (void)format;
        static_cast<HaikuBackend*>(cookie)->playBuffer(buffer, size);
    }

    void open(const char *name) override;
    bool reset() override;
    void start() override;
    void stop() override;

    BSoundPlayer *mPlayer{nullptr};
    uint mFrameSize{0};

    uint mFrequency{0u};
    DevFmtChannels mFmtChans{};
    DevFmtType     mFmtType{};
    uint mUpdateSize{0u};

    DEF_NEWDEL(HaikuBackend)
};

HaikuBackend::~HaikuBackend()
{
    if(mPlayer)
    {
        mPlayer->Stop();
        delete mPlayer;
    }
    mPlayer = nullptr;
}

void HaikuBackend::playBuffer(void *buffer, size_t size) noexcept
{
    const auto ulen = static_cast<unsigned int>(size);
    assert((ulen % mFrameSize) == 0);
    mDevice->renderSamples(buffer, ulen / mFrameSize, mDevice->channelsFromFmt());
}

void HaikuBackend::open(const char *name)
{
    if(!name)
        name = defaultDeviceName;

    media_raw_audio_format format = media_raw_audio_format::wildcard;
    format.frame_rate = static_cast<float>(mDevice->Frequency);
    format.channel_count = (mDevice->FmtChans == DevFmtMono) ? 1 : 2;
    format.format = media_raw_audio_format::B_AUDIO_FLOAT;
    format.byte_order = B_MEDIA_HOST_ENDIAN;
    format.buffer_size = minu(mDevice->UpdateSize, 8192u) * format.channel_count
        * static_cast<uint>(sizeof(float));

    auto *player = new BSoundPlayer(&format, name, &HaikuBackend::playBufferC, nullptr, this);
    status_t err = player->InitCheck();
    if(err != B_OK)
    {
        delete player;
        throw al::backend_exception{al::backend_error::NoDevice,
            "Could not initialize BSoundPlayer: %s", strerror(err)};
    }

    if(mPlayer)
    {
        mPlayer->Stop();
        delete mPlayer;
    }
    mPlayer = player;

    /* Every field above was given an exact, non-wildcard value (not left for the Media Kit
     * to negotiate), so what we requested is what BSoundPlayer opened with. */
    mFrameSize = static_cast<uint>(format.channel_count) * sizeof(float);
    mFrequency = static_cast<uint>(format.frame_rate);
    mFmtChans = (format.channel_count >= 2) ? DevFmtStereo : DevFmtMono;
    mFmtType = DevFmtFloat;
    mUpdateSize = mFrameSize ? static_cast<uint>(format.buffer_size) / mFrameSize : 0u;

    mDevice->DeviceName = name;
}

bool HaikuBackend::reset()
{
    mDevice->Frequency = mFrequency;
    mDevice->FmtChans = mFmtChans;
    mDevice->FmtType = mFmtType;
    mDevice->UpdateSize = mUpdateSize;
    mDevice->BufferSize = mUpdateSize * 2; /* Match the double-buffering used elsewhere. */
    setDefaultWFXChannelOrder();
    return true;
}

void HaikuBackend::start()
{
    if(!mPlayer)
        throw al::backend_exception{al::backend_error::DeviceError, "BSoundPlayer not initialized"};

    status_t err = mPlayer->Start();
    if(err != B_OK)
        throw al::backend_exception{al::backend_error::DeviceError,
            "Could not start BSoundPlayer: %s", strerror(err)};
    mPlayer->SetHasData(true);
}

void HaikuBackend::stop()
{
    if(mPlayer)
        mPlayer->Stop();
}

} // namespace

BackendFactory &HaikuBackendFactory::getFactory()
{
    static HaikuBackendFactory factory{};
    return factory;
}

bool HaikuBackendFactory::init()
{ return true; }

bool HaikuBackendFactory::querySupport(BackendType type)
{ return type == BackendType::Playback; }

std::string HaikuBackendFactory::probe(BackendType type)
{
    std::string outnames;

    if(type != BackendType::Playback)
        return outnames;

    /* The Media Kit mixes down to whatever the system's chosen output device
     * is, so there's just the one implicit "device" to report. */
    outnames.append(defaultDeviceName, sizeof(defaultDeviceName));
    return outnames;
}

BackendPtr HaikuBackendFactory::createBackend(DeviceBase *device, BackendType type)
{
    if(type == BackendType::Playback)
        return BackendPtr{new HaikuBackend{device}};
    return nullptr;
}
