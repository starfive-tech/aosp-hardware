/*
 * Copyright (C) 2022 Android-RPi Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#define LOG_TAG "drm_gralloc"
//#define LOG_NDEBUG 0
#include <utils/Log.h>
#include <cutils/properties.h>
#include <sys/errno.h>
#include <sys/mman.h>

#include <unordered_map>

#include <xf86drm.h>
#include <xf86drmMode.h>
#include <drm_fourcc.h>

#include <hardware/gralloc.h>

#include "drm_gralloc.h"

static int get_bpp(int format)
{
	int bpp;

	switch (format) {
	case HAL_PIXEL_FORMAT_RGBA_8888:
	case HAL_PIXEL_FORMAT_RGBX_8888:
	case HAL_PIXEL_FORMAT_BGRA_8888:
		bpp = 4;
		break;
	case HAL_PIXEL_FORMAT_RGB_888:
		bpp = 3;
		break;
	case HAL_PIXEL_FORMAT_RGB_565:
	case HAL_PIXEL_FORMAT_YCbCr_422_I:
	case HAL_PIXEL_FORMAT_YCBCR_420_888:
		bpp = 2;
		break;
	/* planar; only Y is considered */
	case HAL_PIXEL_FORMAT_YV12:
	case HAL_PIXEL_FORMAT_YCbCr_422_SP:
	case HAL_PIXEL_FORMAT_YCrCb_420_SP:
	case HAL_PIXEL_FORMAT_BLOB:
		bpp = 1;
		break;
	default:
		bpp = 0;
		break;
	}

	return bpp;
}

static buffer_handle_t drm_create(int kms_fd,
		int width, int height, int usage, int *stride) {
    struct drm_mode_create_dumb carg;
    memset (&carg, 0, sizeof (carg));
    carg.bpp = 32;
    carg.width = width;
    carg.height = height;

    int ret = drmIoctl(kms_fd, DRM_IOCTL_MODE_CREATE_DUMB, &carg);
    if (ret != 0) {
        ALOGE("failed CREATE_DUMB : %s", strerror(errno));
    	return NULL;
    } 
    ALOGV("CREATE_DUMB size: %lld , handle: %x ", carg.size, carg.handle);

    struct drm_mode_map_dumb marg;
    memset (&marg, 0, sizeof (marg));
    marg.handle = carg.handle;
    ret = drmIoctl(kms_fd, DRM_IOCTL_MODE_MAP_DUMB, &marg);
    if (ret != 0) {
        ALOGE("failed MAP_DUMB : %s", strerror(errno));
        return NULL;
    }
    void *map = mmap(nullptr, carg.size, PROT_READ | PROT_WRITE, MAP_SHARED, kms_fd, marg.offset);
    if (map == MAP_FAILED) {
        ALOGE("mmap() failed");
        return NULL;
    }

    int prime_fd = 0;
    ret = drmPrimeHandleToFD(kms_fd, carg.handle, O_CLOEXEC, &prime_fd);
    if (ret != 0) {
        ALOGE("failed drmPrimeHandleToFd() : %s", strerror(errno));
		return NULL;
    }


	private_handle_t *handle = new private_handle_t(prime_fd, carg.size,
	    (usage & GRALLOC_USAGE_HW_FB)?private_handle_t::PRIV_FLAGS_FRAMEBUFFER:0);
	handle->base = (intptr_t)map;
	handle->drm_handle = carg.handle;

	/* in pixels */
	*stride = width;

	return handle;
}

int drm_alloc(int kms_fd, int w, int h, int format, int usage,
		buffer_handle_t *handle, int *stride) {
	int err = 0;
	int bpp = get_bpp(format);
	if (bpp != 4) {
	    ALOGE("drm_alloc() get_bpp() %d, format 0x%x", bpp, format);
	    if (!bpp) return -EINVAL;
	}

	*handle = drm_create(kms_fd, w, h, usage, stride);
	if (!*handle)
		err = -errno;

	ALOGV("buffer %p usage = %08x", *handle, usage);
	return err;
}

int drm_register(int kms_fd, buffer_handle_t _handle)
{
	private_handle_t* hnd = (private_handle_t *)_handle;
    if (private_handle_t::validate(_handle) < 0)
        return -EINVAL;

    int ret = drmPrimeFDToHandle(kms_fd, hnd->fd, &hnd->drm_handle);
    if (ret != 0) {
        ALOGE("failed drmPrimeFdToHandle() : %s", strerror(errno));
		return -EINVAL;
    }

    struct drm_mode_map_dumb marg;
    memset (&marg, 0, sizeof (marg));
    marg.handle = hnd->drm_handle;
    ret = drmIoctl(kms_fd, DRM_IOCTL_MODE_MAP_DUMB, &marg);
    if (ret != 0) {
        ALOGE("failed MAP_DUMB : %s", strerror(errno));
        return -EINVAL;
    }
    void *map = mmap(nullptr, hnd->size, PROT_READ | PROT_WRITE, MAP_SHARED, kms_fd, marg.offset);
    if (map == MAP_FAILED) {
        ALOGE("mmap() failed");
        return -EINVAL;
    }
	hnd->base=(intptr_t)map;
	return 0;
}


int drm_lock(buffer_handle_t handle,
		int /*usage*/, int /*x*/, int /*y*/, int /*w*/, int /*h*/,
		void **addr)
{
    if (private_handle_t::validate(handle) < 0)
        return -EINVAL;

    private_handle_t* hnd = (private_handle_t*)handle;
    *addr = (void*)hnd->base;
	return 0;
}

int drm_unlock(buffer_handle_t handle)
{
    if (private_handle_t::validate(handle) < 0)
        return -EINVAL;
	return 0;
}


void drm_free(int kms_fd, buffer_handle_t handle) {
    private_handle_t const* hnd = reinterpret_cast<private_handle_t const*>(handle);

	int ret = munmap((void *)hnd->base, hnd->size);
    if (ret != 0) {
        ALOGE("failed unmap() : %s", strerror(errno));
    }

	struct drm_mode_destroy_dumb darg;
    memset (&darg, 0, sizeof (darg));
    darg.handle = hnd->drm_handle;
    ret = drmIoctl(kms_fd, DRM_IOCTL_MODE_DESTROY_DUMB, &darg);
    if (ret != 0) {
        ALOGE(" failed to destory bo : %s", strerror(errno));
    }
}
