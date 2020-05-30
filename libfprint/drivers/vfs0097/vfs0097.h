/*
 * Validity VFS0097 driver for libfprint
 * Copyright (C) 2020 Viktor Smolov <smolovv@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include "fpi-image-device.h"

/* Timeout for all send/recv operations, except interrupt waiting and abort */
#define VFS_USB_TIMEOUT 100
/* Timeout for usb abort */
#define VFS_USB_ABORT_TIMEOUT 20
/* Default timeout for SSM timers */
#define VFS_SSM_TIMEOUT 100
/* Buffer size for abort and fprint receiving */
#define VFS_USB_BUFFER_SIZE 65536

/* The main driver structure */
struct _FpiDeviceVfs0097
{
  FpDevice   parent;

  GPtrArray *list_result;
};

G_DECLARE_FINAL_TYPE (FpiDeviceVfs0097, fpi_device_vfs0097, FPI, DEVICE_VFS0097, FpDevice)

/* Blocks of data from USB sniffer */

/* Known interrupts */
