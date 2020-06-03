/*
 * Validity VFS0097 driver for libfprint
 * Copyright (C) 2017 Nikita Mikhailov <nikita.s.mikhailov@gmail.com>
 * Copyright (C) 2018 Marco Trevisan <marco@ubuntu.com>
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

#include <nss.h>
#include <stdio.h>

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
clear_data (FpiDeviceVfs0097 *self)
{
  if (self->seed) {
    g_free(self->seed);
  }
}

/* Device functions */

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
  GError *error = NULL;
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);

  GUsbDevice *usb_dev = fpi_device_get_usb_device (device);
  gint config;
  SECStatus rv;

  if (!self->seed)
    {
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                        "Seed value is not initialized");
      fpi_device_open_complete (FP_DEVICE (self), error);
      return;
    }

  if (!g_usb_device_reset (usb_dev, &error))
    {
      fpi_device_open_complete (FP_DEVICE (self), error);
      return;
    }

  config = g_usb_device_get_configuration (usb_dev, &error);
  if (config < 0)
    {
      fpi_device_open_complete (FP_DEVICE (self), error);
      return;
    }
  else if (config == 0)
    {
      g_usb_device_set_configuration (usb_dev, 1, &error);
    }

  /* Claim usb interface */
  if (!g_usb_device_claim_interface (usb_dev, 0, 0, &error))
    {
      fpi_device_open_complete (FP_DEVICE (self), error);
      return;
    }

  /* Initialise NSS early */
  rv = NSS_NoDB_Init (".");
  if (rv != SECSuccess)
  {
    fp_err ("Could not initialize NSS");
    error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                      "Could not initialize NSS");
    fpi_device_open_complete (FP_DEVICE (self), error);
    return;
  }


  //  self->interrupt_cancellable = g_cancellable_new ();

  dev_open_callback (NULL, FP_DEVICE (self), NULL);
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

/* List prints */
static void
dev_list (FpDevice *device)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);

  G_DEBUG_HERE ();

  self->list_result = g_ptr_array_new_with_free_func (g_object_unref);

  fpi_device_list_complete (FP_DEVICE (self),
                            g_steal_pointer (&self->list_result),
                            NULL);
}

/* List prints */
static void
dev_enroll (FpDevice *device)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);
  FpPrint *print = NULL;

  G_DEBUG_HERE ();

  fpi_device_get_enroll_data (device, &print);

  fpi_device_enroll_complete (FP_DEVICE (self), g_object_ref (print), NULL);
}

/* Delete print */
static void
dev_delete (FpDevice *device)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);

  G_DEBUG_HERE ();

  fpi_device_delete_complete (FP_DEVICE (self), NULL);
}

/* Identify print */
static void
dev_identify (FpDevice *device)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);

  G_DEBUG_HERE ();

  fpi_device_identify_complete (FP_DEVICE (self), NULL);
}

/* Verify print */
static void
dev_verify (FpDevice *device)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);
  FpPrint *print = NULL;

  G_DEBUG_HERE ();

//  fpi_device_get_verify_data (device, &print);
//  g_debug ("username: %s", fp_print_get_username(print));
//  fpi_device_verify_report (device, FPI_MATCH_SUCCESS, NULL, NULL);

  fpi_device_verify_complete (FP_DEVICE (self), NULL);
}

/* Cancel current action */
static void
dev_cancel (FpDevice *device)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);

  G_DEBUG_HERE ();

}

static gsize
read_dmi (const char *filename, char *buffer, int buffer_len)
{
  FILE *file;
  size_t read;

  if (!(file = fopen (filename, "r")))
    {
      g_warning ("Could not read %s", filename);
      buffer[0] = 0;
      return 0;
    }

  fgets (buffer, buffer_len, file);

  read = strlen (buffer);
  g_assert (read > 0);
  read--;

  // Remove newline
  buffer[read] = 0;
  return read;
}

static void
fpi_device_vfs0097_init (FpiDeviceVfs0097 *self)
{
  char name[1024], serial[1024];
  gsize name_len, serial_len;

  name_len = read_dmi("/sys/class/dmi/id/product_name", name, sizeof(name));
  serial_len = read_dmi("/sys/class/dmi/id/product_serial", serial, sizeof(serial));

  if (name_len == 0)
    {
      // Set system id to default value (i.e. "VirtualBox")
    }

  self->seed = g_malloc0 (name_len + serial_len + 2);

  memcpy (self->seed, name, name_len + 1);
  memcpy (self->seed + name_len + 1, serial, serial_len + 1);

  g_debug ("Initialized seed value: %s", self->seed);
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
  dev_class->enroll = dev_enroll;
  dev_class->delete = dev_delete;
  dev_class->identify = dev_identify;
  dev_class->verify = dev_verify;
  dev_class->cancel = dev_cancel;
  dev_class->list = dev_list;
}
