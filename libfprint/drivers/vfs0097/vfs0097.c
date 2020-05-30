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

#define FP_COMPONENT "vfs0097"

#include "drivers_api.h"
#include "vfs0097.h"

G_DEFINE_TYPE (FpiDeviceVfs0097, fpi_device_vfs0097, FP_TYPE_DEVICE)

/* Usb id table of device */
static const FpIdEntry id_table[] = {
  {.vid = 0x138a,  .pid = 0x0097, },
  {.vid = 0,  .pid = 0,  .driver_data = 0},
};

/* USB functions */

/* Image processing functions */

/* Proto functions */

/* Clears all fprint data */
static void
clear_data (FpiDeviceVfs0097 *vdev)
{

}

/* Driver functions */

static void
list (FpDevice *device)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);

  G_DEBUG_HERE ();

  self->list_result = g_ptr_array_new_with_free_func (g_object_unref);

  fpi_device_list_complete (FP_DEVICE (self),
                            g_steal_pointer (&self->list_result),
                            NULL);
}


/* Callback for dev_open ssm */
static void
dev_open_callback (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  /* Notify open complete */
  fpi_device_open_complete (dev, error);
}

/* Open device */
static void
dev_open (FpDevice *device)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);
  GError *error = NULL;

  G_DEBUG_HERE ();

//  self->interrupt_cancellable = g_cancellable_new ();

  if (!g_usb_device_reset (fpi_device_get_usb_device (device), &error))
    {
      fpi_device_open_complete (FP_DEVICE (self), error);
      return;
    }

  /* Claim usb interface */
  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (device), 0, 0, &error))
    {
      fpi_device_open_complete (FP_DEVICE (self), error);
      return;
    }

  fpi_device_open_complete (FP_DEVICE (self), NULL);
}

/* Close device */
static void
dev_close (FpDevice *device)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);
  GError *error = NULL;

  clear_data (self);

  /* Release usb interface */
  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (self)),
                                  0, 0, &error);

  /* Notify close complete */
  fpi_device_close_complete (FP_DEVICE (self), error);
}

static void
fpi_device_vfs0097_init (FpiDeviceVfs0097 *self)
{
}

static void
fpi_device_vfs0097_class_init (FpiDeviceVfs0097Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id = "vfs0097";
  dev_class->full_name = "Validity VFS0097";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->id_table = id_table;

  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->probe = NULL;
  dev_class->verify = NULL;
  dev_class->enroll = NULL;
  dev_class->delete = NULL;
  dev_class->cancel = NULL;
  dev_class->list = list;
}
