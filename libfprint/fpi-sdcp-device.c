/*
 * FpSdcpDevice - A base class for SDCP enabled devices
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

#define FP_COMPONENT "sdcp_device"
#include "fpi-log.h"

#include "fp-sdcp-device-private.h"
#include "fpi-sdcp-device.h"
#include "fpi-print.h"

/**
 * SECTION: fpi-sdcp-device
 * @title: Internal FpSdcpDevice
 * @short_description: Internal SDCP Device routines
 *
 * Internal SDCP handling routines. See #FpSdcpDevice for public routines.
 */


G_DEFINE_BOXED_TYPE (FpiSdcpClaim, fpi_sdcp_claim, fpi_sdcp_claim_copy, fpi_sdcp_claim_free)

/**
 * fpi_sdcp_claim_new:
 *
 * Create an empty #FpiSdcpClaim to provide to the base class.
 *
 * Returns: (transfer full): A newly created #FpiSdcpClaim
 */
FpiSdcpClaim *
fpi_sdcp_claim_new (void)
{
  FpiSdcpClaim *res = NULL;

  res = g_new0 (FpiSdcpClaim, 1);

  return res;
}

/**
 * fpi_sdcp_claim_free:
 * @claim: a #FpiSdcpClaim
 *
 * Release the memory used by an #FpiSdcpClaim.
 */
void
fpi_sdcp_claim_free (FpiSdcpClaim * claim)
{
  g_return_if_fail (claim);

  g_clear_pointer (&claim->cert_m, g_bytes_unref);
  g_clear_pointer (&claim->pk_d, g_bytes_unref);
  g_clear_pointer (&claim->pk_f, g_bytes_unref);
  g_clear_pointer (&claim->h_f, g_bytes_unref);
  g_clear_pointer (&claim->s_m, g_bytes_unref);
  g_clear_pointer (&claim->s_d, g_bytes_unref);

  g_free (claim);
}

/**
 * fpi_sdcp_claim_copy:
 * @other: The #FpiSdcpClaim to copy
 *
 * Create a (shallow) copy of a #FpiSdcpClaim.
 *
 * Returns: (transfer full): A newly created #FpiSdcpClaim
 */
FpiSdcpClaim *
fpi_sdcp_claim_copy (FpiSdcpClaim *other)
{
  FpiSdcpClaim *res = NULL;

  res = fpi_sdcp_claim_new ();

  if (other->cert_m)
    res->cert_m = g_bytes_ref (other->cert_m);
  if (other->pk_d)
    res->pk_d = g_bytes_ref (other->pk_d);
  if (other->pk_f)
    res->pk_f = g_bytes_ref (other->pk_f);
  if (other->h_f)
    res->h_f = g_bytes_ref (other->h_f);
  if (other->s_m)
    res->s_m = g_bytes_ref (other->s_m);
  if (other->s_d)
    res->s_d = g_bytes_ref (other->s_d);

  return res;
}

/* FpiSdcpDevice */


/* Manually redefine what G_DEFINE_* macro does */
static inline gpointer
fp_sdcp_device_get_instance_private (FpSdcpDevice *self)
{
  FpSdcpDeviceClass *sdcp_class = g_type_class_peek_static (FP_TYPE_SDCP_DEVICE);

  return G_STRUCT_MEMBER_P (self,
                            g_type_class_get_instance_private_offset (sdcp_class));
}

/* Internal functions of FpSdcpDevice */
void
fpi_sdcp_device_connect (FpSdcpDevice *self)
{
  FpSdcpDeviceClass *cls = FP_SDCP_DEVICE_GET_CLASS (self);
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);
  static guint8 pk_h[65] = {
    0x04, 0x98, 0x9d, 0xd6, 0x97, 0xa4, 0xdd, 0x09, 0x1e, 0xd3, 0x75,
    0x97, 0xe0, 0x1a, 0xab, 0x25, 0x2c, 0x3d, 0xda, 0x08, 0xda, 0x9e,
    0x87, 0x0d, 0xfb, 0x80, 0x5d, 0x90, 0x79, 0x9d, 0x73, 0xd7, 0xc7,
    0x6d, 0xbb, 0xba, 0x13, 0x16, 0x7e, 0xb4, 0x39, 0x60, 0x3c, 0xec,
    0xc6, 0xd8, 0x66, 0x6a, 0xdc, 0x27, 0x34, 0x6b, 0x54, 0x93, 0x07,
    0xda, 0xf6, 0xd4, 0x20, 0x64, 0x3c, 0xc0, 0x5c, 0xd6, 0xad
  };

  /* s_h: eb1ad072c6e631e575a2b213c7975360e097324c999ef42a6bbaf3b79f858472 */


  /* FIXME: Setup TPM instead; only start to connect when that ready. */

  /* FIXME: Dummy values as one can see */
  g_clear_pointer (&priv->r_h, g_bytes_unref);
  g_clear_pointer (&priv->pk_h, g_bytes_unref);
  priv->r_h = g_bytes_new_take (g_malloc0 (32), 32);
  priv->pk_h = g_bytes_new (&pk_h, 65);

  cls->connect (self);
}

void
fpi_sdcp_device_reconnect (FpSdcpDevice *self)
{
  FpSdcpDeviceClass *cls = FP_SDCP_DEVICE_GET_CLASS (self);
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);

  /* FIXME: Ensure we have */

  /* FIXME: Dummy values as one can see */
  g_clear_pointer (&priv->r_h, g_bytes_unref);
  priv->r_h = g_bytes_new_take (g_malloc0 (32), 32);

  cls->reconnect (self);
}

/*********************************************************/
/* Private API */

/* FIXME: I am not sure I like the (transfer none) here. Happy to change
 *        but we should also adjust other getters then. */
/**
 * fp_sdcp_device_get_connect_data:
 * @r_h: (out) (transfer none): The host random
 * @pk_h: (out) (transfer none): The host public key
 *
 * Get data required to connect to (i.e. open) the device securely.
 */
void
fpi_sdcp_device_get_connect_data (FpSdcpDevice *self,
                                  GBytes      **r_h,
                                  GBytes      **pk_h)
{
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);

  g_return_if_fail (r_h != NULL);
  g_return_if_fail (pk_h != NULL);

  *r_h = priv->r_h;
  *pk_h = priv->pk_h;
}

/**
 * fp_sdcp_device_get_reconnect_data:
 * @r_h: (out) (transfer none): The host random
 *
 * Get data required to reconnect to (i.e. open) to the device securely.
 */
void
fpi_sdcp_device_get_reconnect_data (FpSdcpDevice *self,
                                    GBytes      **r_h)
{
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);

  g_return_if_fail (r_h != NULL);

  *r_h = priv->r_h;
}

/* FIXME: How to provide intermediate CAs provided? Same call or separate channel? */
/**
 * fpi_sdcp_device_connect_complete:
 * @self: a #FpSdcpDevice fingerprint device
 * @r_d: The device random nonce
 * @claim: The device #FpiSdcpClaim
 * @mac: The MAC authenticating @claim
 * @error: A #GError or %NULL on success
 *
 * Reports completion of connect (i.e. open) operation.
 */
void
fpi_sdcp_device_connect_complete (FpSdcpDevice *self,
                                  GBytes       *r_d,
                                  FpiSdcpClaim *claim,
                                  GBytes       *mac,
                                  GError       *error)
{
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);
  FpiDeviceAction action;

  action = fpi_device_get_current_action (FP_DEVICE (self));

  g_return_if_fail (action == FPI_DEVICE_ACTION_OPEN);

  if (error)
    {
      if (r_d || claim || mac)
        {
          g_warning ("Driver provided connect information but also reported error.");
          g_clear_pointer (&r_d, g_bytes_unref);
          g_clear_pointer (&claim, fpi_sdcp_claim_free);
          g_clear_pointer (&mac, g_bytes_unref);
        }

      g_clear_pointer (&priv->r_h, g_bytes_unref);
      fpi_device_open_complete (FP_DEVICE (self), error);
      return;
    }

  if (!r_d || !claim || !mac ||
      (!claim->cert_m || !claim->pk_d || !claim->pk_f || !claim->h_f || !claim->s_m || !claim->s_d))
    {
      g_warning ("Driver did not provide all required information to callback, returning error instead.");
      g_clear_pointer (&r_d, g_bytes_unref);
      g_clear_pointer (&claim, fpi_sdcp_claim_free);
      g_clear_pointer (&mac, g_bytes_unref);

      g_clear_pointer (&priv->r_h, g_bytes_unref);
      fpi_device_open_complete (FP_DEVICE (self),
                                fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                          "Driver called connect complete with incomplete arguments."));
      return;
    }

  /* FIXME:
   *  * Derive the secrets
   *  * Verify claim
   *  * Verify certificate
   */
  g_clear_pointer (&priv->r_h, g_bytes_unref);
  fpi_device_open_complete (FP_DEVICE (self), error);
}

/**
 * fpi_sdcp_device_reconnect_complete:
 * @self: a #FpSdcpDevice fingerprint device
 * @mac: The MAC authenticating @claim
 * @error: A #GError or %NULL on success
 *
 * Reports completion of a reconnect (i.e. open) operation.
 */
void
fpi_sdcp_device_reconnect_complete (FpSdcpDevice *self,
                                    GBytes       *mac,
                                    GError       *error)
{
  FpiDeviceAction action;

  action = fpi_device_get_current_action (FP_DEVICE (self));

  g_return_if_fail (action == FPI_DEVICE_ACTION_OPEN);

  if (error)
    {
      if (mac)
        {
          g_warning ("Driver provided a MAC but also reported an error.");
          g_bytes_unref (mac);
        }

      /* FIXME: Silently try a normal connect instead. */
      fpi_sdcp_device_connect (self);
    }
  else if (mac)
    {
      /* FIXME: Verify MAC */

      fpi_device_open_complete (FP_DEVICE (self), NULL);
    }
  else
    {
      fpi_device_open_complete (FP_DEVICE (self),
                                fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                          "Driver called reconnect complete with wrong arguments."));
    }
}

/**
 * fpi_sdcp_device_enroll_set_nonce:
 * @self: a #FpSdcpDevice fingerprint device
 * @nonce: The device generated nonce
 *
 * Called during enroll to inform the SDCP base class about the nonce
 * that the device chose. This can be called at any point, but must be
 * called before calling fpi_sdcp_device_enroll_ready().
 *
 * Calling it will start the required TPM interactions on the host.
 */
void
fpi_sdcp_device_enroll_set_nonce (FpSdcpDevice *self,
                                  GBytes       *nonce)
{
  FpPrint *print;

  g_return_if_fail (FP_IS_SDCP_DEVICE (self));
  g_return_if_fail (fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_ENROLL);
  /* XXX: Ensure the nonce has a reasonable size, is 16 bytes good? */
  g_return_if_fail (nonce || g_bytes_get_size (nonce) < 16);

  fpi_device_get_enroll_data (FP_DEVICE (self), &print);

  /* Attach the ID to the print; XXX: This is obviously just a placeholder */
  g_object_set_data_full (G_OBJECT (print),
                          "id",
                          g_bytes_new_with_free_func (g_malloc0 (32), 32, (GDestroyNotify) g_free, NULL),
                          (GDestroyNotify) g_bytes_unref);
}

/**
 * fpi_sdcp_device_enroll_ready:
 * @self: a #FpSdcpDevice fingerprint device
 * @error: a #GError or %NULL on success
 *
 * Called when the print is ready to be committed to device memory.
 */
void
fpi_sdcp_device_enroll_ready (FpSdcpDevice *self,
                              GError       *error)
{
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);
  FpSdcpDeviceClass *cls = FP_SDCP_DEVICE_GET_CLASS (self);
  FpPrint *print;
  GBytes *id;

  g_return_if_fail (FP_IS_SDCP_DEVICE (self));
  g_return_if_fail (fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_ENROLL);

  if (error)
    {
      fpi_device_enroll_complete (FP_DEVICE (self), NULL, error);
      return;
    }

  /* TODO: The following will need to ensure that the ID has been generated */

  fpi_device_get_enroll_data (FP_DEVICE (self), &print);
  id = g_object_get_data (G_OBJECT (print), "id");

  if (!id)
    {
      g_warning ("Driver failed to call fpi_sdcp_device_enroll_set_nonce, aborting enroll.");

      /* NOTE: Cancel the enrollment, i.e. don't commit */
      priv->enroll_pre_commit_error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                "Device/driver did not provide a nonce as required by protocol, aborting enroll!");
      cls->enroll_commit (self, NULL);
    }
  else
    {
      cls->enroll_commit (self, id);
    }
}

/**
 * fpi_sdcp_device_enroll_commit_complete:
 * @self: a #FpSdcpDevice fingerprint device
 *
 * Called when device has committed the given print to memory.
 * This finalizes the enroll operation.
 */
void
fpi_sdcp_device_enroll_commit_complete (FpSdcpDevice *self,
                                        GError       *error)
{
  FpSdcpDevicePrivate *priv = fp_sdcp_device_get_instance_private (self);
  FpPrint *print;
  GBytes *id;
  GVariant *id_var;
  GVariant *data;

  g_return_if_fail (FP_IS_SDCP_DEVICE (self));
  g_return_if_fail (fpi_device_get_current_action (FP_DEVICE (self)) == FPI_DEVICE_ACTION_ENROLL);

  if (priv->enroll_pre_commit_error)
    {
      if (error)
        {
          g_warning ("Cancelling enroll after error failed with: %s", error->message);
          g_error_free (error);
        }
      fpi_device_enroll_complete (FP_DEVICE (self),
                                  NULL,
                                  g_steal_pointer (&priv->enroll_pre_commit_error));
      return;
    }

  if (error)
    {
      fpi_device_enroll_complete (FP_DEVICE (self), NULL, error);
      return;
    }

  fpi_device_get_enroll_data (FP_DEVICE (self), &print);
  id = g_object_steal_data (G_OBJECT (print), "id");
  if (!id)
    {
      fpi_device_enroll_complete (FP_DEVICE (self),
                                  NULL,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                            "Driver confirmed a enroll commit at an impossible time!"));
    }

  fpi_print_set_type (print, FPI_PRINT_SDCP);
  fpi_print_set_device_stored (print, TRUE);

  /* TODO: Move this into the print or even a separate print class? */
  id_var = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                      g_bytes_get_data (id, NULL),
                                      g_bytes_get_size (id),
                                      1);
  data = g_variant_new ("(@ay)",
                        id_var);
  g_object_set (print, "fpi-data", data, NULL);

  fpi_device_enroll_complete (FP_DEVICE (self), g_object_ref (print), NULL);
}

/**
 * fpi_sdcp_device_identify_retry:
 * @self: a #FpSdcpDevice fingerprint device
 * @error: a #GError containing the retry condition
 *
 * Called when the device requires the finger to be presented again.
 * This should not be called for a verified no-match, it should only
 * be called if e.g. the finger was not centered properly or similar.
 *
 * Effectively this simply raises the error up. This function exists
 * to bridge the difference in semantics that SDPC has from how
 * libfprint works internally.
 */
void
fpi_sdcp_device_identify_retry (FpSdcpDevice *self,
                                GError       *error)
{
  FpiDeviceAction action;

  g_return_if_fail (FP_IS_SDCP_DEVICE (self));
  action = fpi_device_get_current_action (FP_DEVICE (self));

  g_return_if_fail (action == FPI_DEVICE_ACTION_IDENTIFY || action == FPI_DEVICE_ACTION_VERIFY);

  if (action == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_report (FP_DEVICE (self), FPI_MATCH_ERROR, NULL, error);
  else if (action == FPI_DEVICE_ACTION_IDENTIFY)
    fpi_device_identify_report (FP_DEVICE (self), NULL, NULL, error);
}

/**
 * fpi_sdcp_device_identify_complete:
 * @self: a #FpSdcpDevice fingerprint device
 * @id: the ID as reported by the device
 * @error: #GError if an error occured
 *
 * Called when device is done with the identification routine. The
 * returned ID may be %NULL if none of the in-device templates matched.
 */
void
fpi_sdcp_device_identify_complete (FpSdcpDevice *self,
                                   GBytes       *id,
                                   GError       *error)
{
  G_GNUC_UNUSED g_autoptr(GBytes) id_free = id;
  FpiDeviceAction action;

  g_return_if_fail (FP_IS_SDCP_DEVICE (self));
  action = fpi_device_get_current_action (FP_DEVICE (self));

  g_return_if_fail (action == FPI_DEVICE_ACTION_IDENTIFY || action == FPI_DEVICE_ACTION_VERIFY);

  if (error)
    {
      fpi_device_action_error (FP_DEVICE (self), error);
      return;
    }

  /* XXX: We should create a new print representing the on-chip ID,
   *      which would also make the matching code nicer ... */

  /* The surrounding API expects a match/no-match against a given set. */
  if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      g_autoptr(GVariant) data = NULL, p_id_var = NULL;
      FpPrint *print;
      const char *p_id;
      gsize p_id_len;

      fpi_device_get_verify_data (FP_DEVICE (self), &print);
      g_object_get (print, "fpi-data", &data, NULL);
      p_id_var = g_variant_get_child_value (data, 0);
      p_id = g_variant_get_fixed_array (p_id_var, &p_id_len, 1);

      if (p_id_len == g_bytes_get_size (id) && memcmp (p_id, g_bytes_get_data (id, NULL), p_id_len))
        fpi_device_verify_report (FP_DEVICE (self), FPI_MATCH_SUCCESS, NULL, NULL);
      else
        fpi_device_verify_report (FP_DEVICE (self), FPI_MATCH_FAIL, NULL, NULL);

      fpi_device_verify_complete (FP_DEVICE (self), NULL);
    }
  else
    {
      GPtrArray *prints;
      gint i;

      fpi_device_get_identify_data (FP_DEVICE (self), &prints);

      for (i = 0; i < prints->len; i++)
        {
          g_autoptr(GVariant) data = NULL, p_id_var = NULL;
          FpPrint *print = g_ptr_array_index (prints, i);
          const char *p_id;
          gsize p_id_len;

          fpi_device_get_verify_data (FP_DEVICE (self), &print);
          g_object_get (print, "fpi-data", &data, NULL);
          p_id_var = g_variant_get_child_value (data, 0);
          p_id = g_variant_get_fixed_array (p_id_var, &p_id_len, 1);

          if (p_id_len == g_bytes_get_size (id) && memcmp (p_id, g_bytes_get_data (id, NULL), p_id_len))
            {
              fpi_device_identify_report (FP_DEVICE (self), print, NULL, NULL);
              fpi_device_identify_complete (FP_DEVICE (self), NULL);
              return;
            }
        }

      /* Print wasn't in database. */
      fpi_device_identify_report (FP_DEVICE (self), NULL, NULL, NULL);
      fpi_device_identify_complete (FP_DEVICE (self), NULL);
    }
}
