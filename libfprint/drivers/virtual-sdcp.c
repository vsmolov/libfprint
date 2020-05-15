/*
 * Virtual driver for SDCP device debugging
 *
 * Copyright (C) 2020 Benjamin Berg <bberg@redhat.com>
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

/*
 * This is a virtual test driver to test the basic SDCP functionality.
 * It uses the test binaries from Microsoft, which were extended to allow
 * a simple chat with the device.
 * The environment variable contains the to be executed binary including
 * arguments. This binary should be compiled from the code in
 *   https://github.com/Microsoft/SecureDeviceConnectionProtocol
 * or, until it is merged upstream
 *   https://github.com/benzea/SecureDeviceConnectionProtocol
 *
 * Note that using this as an external executable has the advantage that we
 * do not need to link against mbedtls or any other crypto library.
 */

#define FP_COMPONENT "virtual_sdcp"

#include "fpi-log.h"

#include "../fpi-sdcp-device.h"

#include <glib/gstdio.h>
#include <gio/gio.h>

struct _FpDeviceVirtualSdcp
{
  FpSdcpDevice   parent;

  GSubprocess   *proc;
  GOutputStream *proc_stdin;
  GInputStream  *proc_stdout;

  /* Only valid while a read/write is pending */
  GByteArray *message;
};

G_DECLARE_FINAL_TYPE (FpDeviceVirtualSdcp, fpi_device_virtual_sdcp, FPI, DEVICE_VIRTUAL_SDCP, FpSdcpDevice)
G_DEFINE_TYPE (FpDeviceVirtualSdcp, fpi_device_virtual_sdcp, FP_TYPE_SDCP_DEVICE)


static void
connect_recv_2_cb (GObject      *source_object,
                   GAsyncResult *res,
                   gpointer      user_data)
{
  GError *error = NULL;
  GInputStream *stream = G_INPUT_STREAM (source_object);
  FpSdcpDevice *dev = FP_SDCP_DEVICE (user_data);
  FpDeviceVirtualSdcp *self = FPI_DEVICE_VIRTUAL_SDCP (dev);
  gsize read;

  g_autoptr(GBytes) recv_data = NULL;
  guint16 cert_size;
  GBytes *r_d;
  FpiSdcpClaim *claim;
  GBytes *mac;

  if (!g_input_stream_read_all_finish (stream, res, &read, &error) ||
      read != self->message->len - 34)
    {
      g_clear_pointer (&self->message, g_byte_array_unref);

      if (!error)
        error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                          "Received EOF while reading from test binary.");

      fpi_sdcp_device_connect_complete (dev, NULL, NULL, NULL, error);
      return;
    }

  memcpy (&cert_size, self->message->data + 32, 2);
  recv_data = g_byte_array_free_to_bytes (self->message);
  self->message = NULL;

  /* Got everything, disect the buffer and pass back.
   * This is a bit crazy, but well ... */
  claim = fpi_sdcp_claim_new ();
  r_d = g_bytes_new_from_bytes (recv_data, 0, 32);
  claim->cert_m = g_bytes_new_from_bytes (recv_data, 34, cert_size);
  claim->pk_d = g_bytes_new_from_bytes (recv_data, 34 + cert_size, 65);
  claim->pk_f = g_bytes_new_from_bytes (recv_data, 34 + cert_size + 65, 65);
  claim->h_f = g_bytes_new_from_bytes (recv_data, 34 + cert_size + 65 + 65, 32);
  claim->s_m = g_bytes_new_from_bytes (recv_data, 34 + cert_size + 65 + 65 + 32, 64);
  claim->s_d = g_bytes_new_from_bytes (recv_data, 34 + cert_size + 65 + 65 + 32 + 64, 64);
  mac = g_bytes_new_from_bytes (recv_data, 34 + cert_size + 65 + 65 + 32 + 64 + 64, 32);

  fpi_sdcp_device_connect_complete (dev, r_d, claim, mac, NULL);
}

static void
connect_recv_1_cb (GObject      *source_object,
                   GAsyncResult *res,
                   gpointer      user_data)
{
  GError *error = NULL;
  gsize size;
  gsize read;
  guint16 cert_size;
  GInputStream *stream = G_INPUT_STREAM (source_object);
  FpSdcpDevice *dev = FP_SDCP_DEVICE (user_data);
  FpDeviceVirtualSdcp *self = FPI_DEVICE_VIRTUAL_SDCP (dev);

  if (!g_input_stream_read_all_finish (stream, res, &read, &error) ||
      read != self->message->len)
    {
      g_clear_pointer (&self->message, g_byte_array_unref);

      if (!error)
        error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                          "Received EOF while reading from test binary.");

      fpi_sdcp_device_connect_complete (dev, NULL, NULL, NULL, error);
      return;
    }

  /* Grab the certificate size */
  memcpy (&cert_size, self->message->data + 32, 2);
  /* We can now calculate how many more bytes we need to read. */
  size = 32 + (2 + cert_size + 65 + 65 + 32 + 64 + 64) + 32;
  g_debug ("Reading rest of %zd bytes, certificate is %d bytes", size, cert_size);

  g_byte_array_set_size (self->message, size);

  /* Read the rest (34 bytes were already read). */
  g_input_stream_read_all_async (self->proc_stdout,
                                 self->message->data + 34,
                                 self->message->len - 34,
                                 G_PRIORITY_DEFAULT,
                                 fpi_device_get_cancellable (FP_DEVICE (dev)),
                                 connect_recv_2_cb,
                                 self);
}

static void
connect_written_cb (GObject      *source_object,
                    GAsyncResult *res,
                    gpointer      user_data)
{
  GError *error = NULL;
  GOutputStream *stream = G_OUTPUT_STREAM (source_object);
  FpSdcpDevice *dev = FP_SDCP_DEVICE (user_data);
  FpDeviceVirtualSdcp *self = FPI_DEVICE_VIRTUAL_SDCP (dev);

  g_clear_pointer (&self->message, g_byte_array_unref);

  if (!g_output_stream_write_all_finish (stream, res, NULL, &error))
    {
      fpi_sdcp_device_connect_complete (dev, NULL, NULL, NULL, error);
      return;
    }

  /* The connect response has a variable length, so chunk it up into
   * two reads. The initial read reads:
   *  - r_d
   *  - size header for certificate (inside claim) */
  self->message = g_byte_array_new ();
  g_byte_array_set_size (self->message, 32 + 2);

  g_debug ("Reading first 34 bytes of response");

  g_input_stream_read_all_async (self->proc_stdout,
                                 self->message->data,
                                 self->message->len,
                                 G_PRIORITY_DEFAULT,
                                 fpi_device_get_cancellable (FP_DEVICE (dev)),
                                 connect_recv_1_cb,
                                 self);
}

static void
connect (FpSdcpDevice *dev)
{
  GBytes *r_h, *pk_h;
  FpDeviceVirtualSdcp *self = FPI_DEVICE_VIRTUAL_SDCP (dev);

  G_DEBUG_HERE ();

  g_assert (self->proc);
  g_assert (self->message == NULL);

  fpi_sdcp_device_get_connect_data (dev, &r_h, &pk_h);

  self->message = g_byte_array_new ();
  g_byte_array_append (self->message, (const guint8 *) "C", 1);
  g_byte_array_append (self->message,
                       g_bytes_get_data (r_h, NULL),
                       g_bytes_get_size (r_h));
  g_byte_array_append (self->message,
                       g_bytes_get_data (pk_h, NULL),
                       g_bytes_get_size (pk_h));

  g_output_stream_write_all_async (self->proc_stdin,
                                   self->message->data,
                                   self->message->len,
                                   G_PRIORITY_DEFAULT,
                                   fpi_device_get_cancellable (FP_DEVICE (dev)),
                                   connect_written_cb,
                                   dev);
}

static void
probe (FpDevice *dev)
{
  g_auto(GStrv) argv = NULL;
  FpDeviceVirtualSdcp *self = FPI_DEVICE_VIRTUAL_SDCP (dev);
  GError *error = NULL;
  const char *env;

  /* We launch the test binary alread at probe time and quit only when
   * the object is finalized. This allows testing reconnect properly.
   *
   * Also, we'll fail probe if something goes wrong executing it.
   */
  env = fpi_device_get_virtual_env (FP_DEVICE (self));

  if (!g_shell_parse_argv (env, NULL, &argv, &error))
    goto out;

  self->proc = g_subprocess_newv ((const char * const *) argv,
                                  G_SUBPROCESS_FLAGS_STDIN_PIPE | G_SUBPROCESS_FLAGS_STDOUT_PIPE,
                                  &error);
  if (!self->proc)
    goto out;

  self->proc_stdin = g_object_ref (g_subprocess_get_stdin_pipe (self->proc));
  self->proc_stdout = g_object_ref (g_subprocess_get_stdout_pipe (self->proc));


out:
  fpi_device_probe_complete (dev, "virtual-sdcp", NULL, error);
}

static void
dev_close (FpDevice *dev)
{
  /* No-op, needs to be defined. */
  fpi_device_close_complete (dev, NULL);
}

static void
fpi_device_virtual_sdcp_init (FpDeviceVirtualSdcp *self)
{
}

static void
fpi_device_virtual_sdcp_finalize (GObject *obj)
{
  FpDeviceVirtualSdcp *self = FPI_DEVICE_VIRTUAL_SDCP (obj);

  /* Just kill the subprocess, no need to be graceful here. */
  if (self->proc)
    g_subprocess_force_exit (self->proc);

  g_clear_object (&self->proc);
  g_clear_object (&self->proc_stdin);
  g_clear_object (&self->proc_stdout);
}

static const FpIdEntry driver_ids[] = {
  { .virtual_envvar = "FP_VIRTUAL_SDCP" },
  { .virtual_envvar = NULL }
};

static void
fpi_device_virtual_sdcp_class_init (FpDeviceVirtualSdcpClass *klass)
{
  GObjectClass *obj_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpSdcpDeviceClass *sdcp_class = FP_SDCP_DEVICE_CLASS (klass);

  obj_class->finalize = fpi_device_virtual_sdcp_finalize;

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "Virtual SDCP device talking to MS test code";
  dev_class->type = FP_DEVICE_TYPE_VIRTUAL;
  dev_class->id_table = driver_ids;

  /* The SDCP base class may need to override this in the long run */
  dev_class->probe = probe;
  dev_class->close = dev_close;

  sdcp_class->connect = connect;
}
