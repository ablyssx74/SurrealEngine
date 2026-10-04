#ifndef BACKENDS_HAIKU_H
#define BACKENDS_HAIKU_H

#include "base.h"

struct HaikuBackendFactory final : public BackendFactory {
public:
    bool init() override;

    bool querySupport(BackendType type) override;

    std::string probe(BackendType type) override;

    BackendPtr createBackend(DeviceBase *device, BackendType type) override;

    static BackendFactory &getFactory();
};

#endif /* BACKENDS_HAIKU_H */
