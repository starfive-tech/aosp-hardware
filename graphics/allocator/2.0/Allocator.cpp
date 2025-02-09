/*
 * Copyright 2020 Android-RPi Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "allocator@2.0-Allocator"
//#define LOG_NDEBUG 0
#include <android-base/logging.h>
#include <utils/Log.h>
#include <cutils/properties.h>

#include <hardware/gralloc1.h>
#include <drm_gralloc.h>

#include "Allocator.h"

namespace android {
namespace hardware {
namespace graphics {
namespace allocator {
namespace V2_0 {
namespace implementation {

Allocator::Allocator() {
    ALOGV("Allocator()");
    char path[PROPERTY_VALUE_MAX];
    property_get("gralloc.drm.kms", path, "/dev/dri/card0");

    kms_fd = open(path, O_RDWR | O_CLOEXEC);
    if (kms_fd < 0) {
        ALOGE("failed to open %s", path);
    }
}

Allocator::~Allocator() {
	ALOGV("~Allocator()");
    if (kms_fd >= 0) {
        close(kms_fd);
    }
}

Return<void> Allocator::dumpDebugInfo(dumpDebugInfo_cb hidl_cb) {
    std::vector<char> buf(1);
    buf[0] = '\0';
	hidl_cb(buf.data());
    return Void();
}

static gralloc1_producer_usage_t toProducerUsage(uint64_t usage) {
    uint64_t producerUsage = usage & ~static_cast<uint64_t>(
            BufferUsage::CPU_READ_MASK | BufferUsage::CPU_WRITE_MASK |
            BufferUsage::GPU_DATA_BUFFER);
    switch (usage & BufferUsage::CPU_WRITE_MASK) {
    case static_cast<uint64_t>(BufferUsage::CPU_WRITE_RARELY):
        producerUsage |= GRALLOC1_PRODUCER_USAGE_CPU_WRITE;
        break;
    case static_cast<uint64_t>(BufferUsage::CPU_WRITE_OFTEN):
        producerUsage |= GRALLOC1_PRODUCER_USAGE_CPU_WRITE_OFTEN;
        break;
    default:
        break;
    }
    switch (usage & BufferUsage::CPU_READ_MASK) {
    case static_cast<uint64_t>(BufferUsage::CPU_READ_RARELY):
        producerUsage |= GRALLOC1_PRODUCER_USAGE_CPU_READ;
        break;
    case static_cast<uint64_t>(BufferUsage::CPU_READ_OFTEN):
        producerUsage |= GRALLOC1_PRODUCER_USAGE_CPU_READ_OFTEN;
        break;
    default:
        break;
    }
    return (gralloc1_producer_usage_t)producerUsage;
}

static gralloc1_consumer_usage_t toConsumerUsage(uint64_t usage) {
    uint64_t consumerUsage = usage & ~static_cast<uint64_t>(
            BufferUsage::CPU_READ_MASK | BufferUsage::CPU_WRITE_MASK |
            BufferUsage::SENSOR_DIRECT_DATA | BufferUsage::GPU_DATA_BUFFER);
    switch (usage & BufferUsage::CPU_READ_MASK) {
    case static_cast<uint64_t>(BufferUsage::CPU_READ_RARELY):
        consumerUsage |= GRALLOC1_CONSUMER_USAGE_CPU_READ;
        break;
    case static_cast<uint64_t>(BufferUsage::CPU_READ_OFTEN):
        consumerUsage |= GRALLOC1_CONSUMER_USAGE_CPU_READ_OFTEN;
        break;
    default:
        break;
    }
    if (usage & BufferUsage::GPU_DATA_BUFFER) {
        consumerUsage |= GRALLOC1_CONSUMER_USAGE_GPU_DATA_BUFFER;
    }
    return (gralloc1_consumer_usage_t)consumerUsage;
}

Error Allocator::allocateOneBuffer(
		const IMapper::BufferDescriptorInfo& descInfo,
        buffer_handle_t* outBufferHandle, uint32_t* outStride)
{
    uint64_t usage = toProducerUsage(descInfo.usage) | toConsumerUsage(descInfo.usage);
    buffer_handle_t handle = nullptr;
    int stride = 0;

    ALOGV("Calling alloc(%u, %u, %i, %lx)", descInfo.width,
            descInfo.height, descInfo.format, usage);
    auto error = drm_alloc(kms_fd, static_cast<int>(descInfo.width),
            static_cast<int>(descInfo.height), static_cast<int>(descInfo.format),
            usage, &handle, &stride);
    if (error != 0) {
        ALOGE("allocateOneBuffer() failed: %d (%s)", error, strerror(-error));
        return Error::NO_RESOURCES;
    }
    *outBufferHandle = handle;
    *outStride = stride;
    return Error::NONE;
}

Return<void> Allocator::allocate(const BufferDescriptor& descriptor,
        uint32_t count, IAllocator::allocate_cb hidl_cb) {
    IMapper::BufferDescriptorInfo descInfo;
    if (!grallocDecodeBufferDescriptor(descriptor, &descInfo)) {
        hidl_cb(Error::BAD_DESCRIPTOR, 0, hidl_vec<hidl_handle>());
        return Void();
    }

    uint32_t stride = 0;
    std::vector<const native_handle_t*> buffers;
    buffers.reserve(count);

    Error error = Error::NONE;
    for (uint32_t i = 0; i < count; i++) {
        const native_handle_t* tmpBuffer;
        uint32_t tmpStride;

        error = allocateOneBuffer(descInfo, &tmpBuffer, &tmpStride);
        if (error != Error::NONE) {
            break;
        }
        buffers.push_back(tmpBuffer);
        if (stride == 0) {
            stride = tmpStride;
        } else if (stride != tmpStride) {
            error = Error::UNSUPPORTED;
            break;
        }
    }

    if (error != Error::NONE) {
        freeBuffers(buffers);
        hidl_cb(error, 0, hidl_vec<hidl_handle>());
        return Void();
    }

    hidl_vec<hidl_handle> hidlBuffers(buffers.cbegin(), buffers.cend());
    hidl_cb(Error::NONE, stride, hidlBuffers);

    freeBuffers(buffers);
    return Void();
}

void Allocator::freeBuffers(const std::vector<const native_handle_t*>& buffers) {
    for (auto buffer : buffers) {
    	drm_free(kms_fd, buffer);
        native_handle_close(buffer);
        delete buffer;
    }
}

}  // namespace implementation
}  // namespace V2_0
}  // namespace allocator
}  // namespace graphics
}  // namespace hardware
}  // namespace android
