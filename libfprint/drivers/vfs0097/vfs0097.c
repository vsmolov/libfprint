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

#define EP_IN (1 | FPI_USB_ENDPOINT_IN)
#define EP_OUT (1 | FPI_USB_ENDPOINT_OUT)
#define EP_INTERRUPT (3 | FPI_USB_ENDPOINT_IN)

G_DEFINE_TYPE (FpiDeviceVfs0097, fpi_device_vfs0097, FP_TYPE_DEVICE)

/* Usb id table of device */
static const FpIdEntry id_table[] = {
  {.vid = 0x138a,  .pid = 0x0097, },
  {.vid = 0,  .pid = 0,  .driver_data = 0},
};

/* USB functions */

/* Callback for async_write */
static void
async_write_callback (FpiUsbTransfer *transfer, FpDevice *device,
                      gpointer user_data, GError *error)
{
  if (error)
    {
      fp_err ("USB write transfer: %s", error->message);
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fpi_ssm_next_state (transfer->ssm);
}

/* Send data to EP1, the only out endpoint */
static void
async_write (FpiSsm   *ssm,
             FpDevice *dev,
             void     *data,
             int       len)
{
  FpiUsbTransfer *transfer;

  transfer = fpi_usb_transfer_new (FP_DEVICE (dev));
  fpi_usb_transfer_fill_bulk_full (transfer, EP_OUT, data, len, NULL);
  transfer->ssm = ssm;
  transfer->short_is_error = TRUE;
  fpi_usb_transfer_submit (transfer, VFS_USB_TIMEOUT, NULL,
                           async_write_callback, NULL);
}

/* Callback for async_read */
static void
async_read_callback (FpiUsbTransfer *transfer, FpDevice *device,
                     gpointer user_data, GError *error)
{
  if (error)
    {
      fp_err ("USB read transfer on endpoint %d: %s", transfer->endpoint, error->message);
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (user_data)
    *((gsize *) user_data) = transfer->actual_length;
  fpi_ssm_next_state (transfer->ssm);
}

/* Receive data from the given ep and either discard or fill the given buffer */
static void
async_read (FpiSsm   *ssm,
            FpDevice *dev,
            void     *data,
            gsize     len,
            gsize    *actual_length)
{
  FpiUsbTransfer *transfer;
  GDestroyNotify free_func = NULL;

  transfer = fpi_usb_transfer_new (FP_DEVICE (dev));
  transfer->ssm = ssm;
  transfer->short_is_error = FALSE; // TODO: We do not know actual response lengths yet, so

  if (data == NULL)
    {
      data = g_malloc0 (len);
      free_func = g_free;
    }

  fpi_usb_transfer_fill_bulk_full (transfer, EP_IN, data, len, free_func);

  fpi_usb_transfer_submit (transfer, VFS_USB_TIMEOUT, NULL,
                           async_read_callback, actual_length);
}
/* Image processing functions */

/* Proto functions */
struct command_ssm_data_t
{
  guchar *buffer;
  gssize  length;
};

static void
init_keys (FpDevice *dev)
{

}

/* SSM loop for exec_command */
static void
exec_command_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (dev);
  struct command_ssm_data_t *data = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case EXEC_COMMAND_SM_WRITE:
      async_write (ssm, dev, data->buffer, data->length);
      break;

    case EXEC_COMMAND_SM_READ:
      async_read (ssm, dev, self->buffer, VFS_USB_BUFFER_SIZE, &self->buffer_length);
      break;

    default:
      fp_err ("Unknown EXEC_COMMAND_SM state");
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
    }
}

/* Send command and read response */
static void
exec_command (FpDevice *dev, FpiSsm *ssm, const guchar *buffer, gsize length)
{
  struct command_ssm_data_t *data;
  FpiSsm *subsm;

  data = g_new0 (struct command_ssm_data_t, 1);
  data->buffer = (guchar *) buffer;
  data->length = length;

  subsm = fpi_ssm_new (dev, exec_command_ssm, EXEC_COMMAND_SM_STATES);
  fpi_ssm_set_data (subsm, data, g_free);

  fpi_ssm_start_subsm (ssm, subsm);
}

/* Clears all fprint data */
static void
clear_data (FpiDeviceVfs0097 *self)
{
  g_clear_pointer (&self->seed, g_free);
  g_clear_pointer (&self->buffer, g_free);
}

/* Device functions */

/* SSM loop for device initialization */
static void
init_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case SEND_INIT_1:
      exec_command (dev, ssm, INIT_SEQUENCE_MSG1, G_N_ELEMENTS (INIT_SEQUENCE_MSG1));
      break;

    case CHECK_INITIALIZED:
      if (self->buffer_length == 38)
        {
          if (self->buffer[self->buffer_length - 1] != 0x07)
            {
              fp_err ("Sensor is not initialized, init byte is 0x%02x "
                      "(should be 0x07 on initialized devices, 0x02 otherwise)\n" \
                      "This is a driver in alpha state and the device needs to be setup in a VirtualBox " \
                      "instance running Windows, or with a native Windows installation first.",
                      self->buffer[self->buffer_length - 1]);
              fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                                  "Device is not initialized"));
              break;
            }
        }
      else
        {
          fp_warn ("Unknown reply at init");
          break;
        }

    case SEND_INIT_2:
      exec_command (dev, ssm, INIT_SEQUENCE_MSG2, G_N_ELEMENTS (INIT_SEQUENCE_MSG2));
      break;

    case GET_PARTITION_HEADER:
      exec_command (dev, ssm, INIT_SEQUENCE_MSG3, G_N_ELEMENTS (INIT_SEQUENCE_MSG3));
      break;

    case SEND_INIT_4:
      exec_command (dev, ssm, INIT_SEQUENCE_MSG4, G_N_ELEMENTS (INIT_SEQUENCE_MSG4));
      break;

    case GET_FLASH_INFO:
      exec_command (dev, ssm, INIT_SEQUENCE_MSG5, G_N_ELEMENTS (INIT_SEQUENCE_MSG5));
      break;

    case READ_FLASH_TLS_DATA:
      exec_command (dev, ssm, INIT_SEQUENCE_MSG6, G_N_ELEMENTS (INIT_SEQUENCE_MSG6));
      break;

    case INIT_KEYS:
      init_keys (dev);
      break;

    default:
      fp_err ("Unknown INIT_SM state");
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
    }
}

/* Callback for device initialization SSM */
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

  GUsbDevice *usb_dev;
  gint config;
  SECStatus rv;

  if (!self->seed)
    {
      error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                        "Seed value is not initialized");
      fpi_device_open_complete (FP_DEVICE (self), error);
      return;
    }

  /* Claim usb interface */
  usb_dev = fpi_device_get_usb_device (device);
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

  self->buffer = g_malloc0 (VFS_USB_BUFFER_SIZE);

  FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (self), init_ssm, INIT_SM_STATES);
  fpi_ssm_start (ssm, dev_open_callback);
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

  name_len = read_dmi ("/sys/class/dmi/id/product_name", name, sizeof (name));
  serial_len = read_dmi ("/sys/class/dmi/id/product_serial", serial, sizeof (serial));

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
