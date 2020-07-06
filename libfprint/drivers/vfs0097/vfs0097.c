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

#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "drivers_api.h"

#include "fpi-byte-reader.h"
#include "fpi-byte-writer.h"

#include "vfs0097.h"

#define EP_IN (1 | FPI_USB_ENDPOINT_IN)
#define EP_OUT (1 | FPI_USB_ENDPOINT_OUT)
#define EP_INTERRUPT (3 | FPI_USB_ENDPOINT_IN)

#define INTERRUPT_CMP(transfer, interrupt) (transfer->actual_length == G_N_ELEMENTS (interrupt) && \
                                            memcmp (transfer->buffer, interrupt, G_N_ELEMENTS (interrupt)) == 0)

G_DEFINE_TYPE (FpiDeviceVfs0097, fpi_device_vfs0097, FP_TYPE_DEVICE)

/* Usb id table of device */
static const FpIdEntry id_table[] = {
  {.vid = 0x138a,  .pid = 0x0097, },
  {.vid = 0,  .pid = 0,  .driver_data = 0},
};

static FpFinger
subtype_to_finger (guint16 subtype)
{
  if (subtype >= 0xf5 && subtype <= 0xfe)
    return FP_FINGER_FIRST + subtype - 0xf5;
  else
    return FP_FINGER_UNKNOWN;
}

static guint16
finger_to_subtype (FpFinger finger)
{
  if (finger == FP_FINGER_UNKNOWN)
    return 0xff;
  else
    return finger - FP_FINGER_FIRST + 0xf5;
}

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

  fpi_ssm_next_state_delayed (transfer->ssm, VFS_SSM_TIMEOUT, NULL);
}

/* Send data to EP_OUT */
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
    *((guint *) user_data) = transfer->actual_length;
  fpi_ssm_next_state (transfer->ssm);
}

/* Receive data from the given ep and either discard or fill the given buffer */
static void
async_read (FpiSsm   *ssm,
            FpDevice *dev,
            void     *data,
            guint     len,
            guint    *actual_length)
{
  FpiUsbTransfer *transfer;
  GDestroyNotify free_func = NULL;

  transfer = fpi_usb_transfer_new (FP_DEVICE (dev));
  transfer->ssm = ssm;
  transfer->short_is_error = FALSE; //

  if (data == NULL)
    {
      data = g_malloc0 (len);
      free_func = g_free;
    }

  fpi_usb_transfer_fill_bulk_full (transfer, EP_IN, data, len, free_func);

  fpi_usb_transfer_submit (transfer, VFS_USB_TIMEOUT, NULL,
                           async_read_callback, actual_length);
}

static void
await_interrupt (FpDevice *dev, FpiSsm *ssm, FpiUsbTransferCallback callback)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (dev);
  FpiUsbTransfer *transfer;

  transfer = fpi_usb_transfer_new (dev);
  transfer->ssm = ssm;
  fpi_usb_transfer_fill_interrupt (transfer, EP_INTERRUPT, USB_INTERRUPT_DATA_SIZE);
  fpi_usb_transfer_submit (transfer,
                           0,
                           self->interrupt_cancellable,
                           callback,
                           NULL);
}

/* Cryptographic functions */

static guint8 *
HMAC_SHA256 (const guint8 *key, guint32 key_len,
             const guint8 *data, guint32 data_len,
             guint8 *result)
{
  guint32 unused;

  return HMAC (EVP_sha256 (), key, key_len, data, data_len, result, &unused);
}

static void
PRF_SHA256 (const guint8 *secret, guint32 secret_len,
            const guint8 *label, guint32 label_len,
            const guint8 *seed, guint32 seed_len, guint8 *out, guint32 len)
{
  guint size;
  guint pos;
  guint8 P[SHA256_DIGEST_LENGTH];
  guint8 *A;

  /*
   * RFC 5246, Chapter 5
   * A(0) = lseed
   * A(i) = HMAC_hash(secret, A(i-1))
   *
   * P_hash(secret, lseed) = HMAC_hash(secret, A(1) + lseed) +
   *                         HMAC_hash(secret, A(2) + lseed) +
   *                         HMAC_hash(secret, A(3) + lseed) + ...
   *
   * PRF(secret, label, seed) = P_hash(secret, label + seed)
   */

  // A(0)
  A = g_malloc0 (SHA256_DIGEST_LENGTH + label_len + seed_len);
  memcpy (A, label, label_len);
  memcpy (A + label_len, seed, seed_len);

  // A(1)
  HMAC_SHA256 (secret, secret_len, A, label_len + seed_len, A);

  pos = 0;
  while (pos < len)
    {
      // Concatenate A + label + seed
      memcpy (A + SHA256_DIGEST_LENGTH, label, label_len);
      memcpy (A + SHA256_DIGEST_LENGTH + label_len, seed, seed_len);

      // Calculate new P_hash part
      HMAC_SHA256 (secret, secret_len, A, SHA256_DIGEST_LENGTH + label_len + seed_len, P);

      // Calculate next A
      HMAC_SHA256 (secret, secret_len, A, SHA256_DIGEST_LENGTH, A);

      size = MIN (len - pos, SHA256_DIGEST_LENGTH);
      memcpy (out + pos, P, size);
      pos += size;
    }

  g_free (A);
}

/* TLS forward declarations */

static void tls_sign_and_encrypt (guint8   content_type,
                                  guint8   sign_key[0x20],
                                  guint8   encryption_key[0x20],
                                  guint8  *data,
                                  guint    length,
                                  guint8 **out,
                                  guint   *out_len);

static void tls_decrypt_and_validate (guint8   content_type,
                                      guint8   validation_key[0x20],
                                      guint8   decryption_key[0x20],
                                      guint8  *data,
                                      guint    length,
                                      guint8 **out,
                                      guint   *out_len);

static void tls_create_record (guint8   content_type,
                               guint8  *fragment,
                               guint    length,
                               guint8 **out,
                               guint   *out_len);

static void tls_parse_record (guint8   content_type,
                              guint8  *fragment,
                              guint    length,
                              guint8 **out,
                              guint   *out_len);

/* Initialization from device's flash */

static void
init_private_key (FpiDeviceVfs0097 *self, const guint8 *body, guint16 size)
{
  guint8 AES_MASTER_KEY[SHA256_DIGEST_LENGTH];
  guint8 VALIDATION_KEY[SHA256_DIGEST_LENGTH];

  PRF_SHA256 (PRE_KEY, G_N_ELEMENTS (PRE_KEY),
              LABEL, G_N_ELEMENTS (LABEL),
              self->seed, self->seed_length,
              AES_MASTER_KEY, SHA256_DIGEST_LENGTH);

  PRF_SHA256 (AES_MASTER_KEY, SHA256_DIGEST_LENGTH,
              LABEL_SIGN, G_N_ELEMENTS (LABEL_SIGN),
              SIGN_KEY, G_N_ELEMENTS (SIGN_KEY),
              VALIDATION_KEY, SHA256_DIGEST_LENGTH);

  const guint8 prefix = body[0];
  if (prefix != 2)
    {
      fp_warn ("Unknown private key prefix %02x", prefix);
      return;
    }

  const guint8 *encrypted = &body[1];
  const guint8 *hash = &body[size - SHA256_DIGEST_LENGTH];

  guint8 calc_hash[SHA256_DIGEST_LENGTH];
  HMAC_SHA256 (VALIDATION_KEY, SHA256_DIGEST_LENGTH, encrypted, size - 1 - SHA256_DIGEST_LENGTH, calc_hash);

  if (memcmp (calc_hash, hash, SHA256_DIGEST_LENGTH) != 0)
    {
      fp_warn ("Signature verification failed. This device was probably paired with another computer.");
      return;
    }

  EVP_CIPHER_CTX *context;
  context = EVP_CIPHER_CTX_new ();
  unsigned char *decrypted = NULL;
  int tlen1 = 0, tlen2;

  if (!EVP_DecryptInit (context, EVP_aes_256_cbc (), AES_MASTER_KEY, encrypted))
    {
      fp_err ("Failed to initialize EVP decrypt, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  decrypted = g_malloc (0x70);
  EVP_CIPHER_CTX_set_padding (context, 0);

  if (!EVP_DecryptUpdate (context, decrypted, &tlen1, encrypted + 0x10, 0x70))
    {
      fp_err ("Failed to EVP decrypt, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  if (!EVP_DecryptFinal (context, decrypted + tlen1, &tlen2))
    {
      fp_err ("EVP Final decrypt failed, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  EVP_CIPHER_CTX_free (context);

  BIGNUM *x = BN_lebin2bn (decrypted, 0x20, NULL);
  BIGNUM *y = BN_lebin2bn (decrypted + 0x20, 0x20, NULL);
  BIGNUM *d = BN_lebin2bn (decrypted + 0x40, 0x20, NULL);

  EC_KEY *key = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);

  if (!EC_KEY_set_public_key_affine_coordinates (key, x, y))
    {
      fp_err ("Failed to set public key coordinates, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  if (!EC_KEY_set_private_key (key, d))
    {
      fp_err ("Failed to set private key, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));

      return;
    }

  if (!EC_KEY_check_key (key))
    {
      fp_err ("Failed to check key, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  self->private_key = key;

  g_clear_pointer (&decrypted, g_free);
  g_clear_pointer (&x, BN_free);
  g_clear_pointer (&y, BN_free);
  g_clear_pointer (&d, BN_free);
}

static void
init_ecdh (FpiDeviceVfs0097 *self, const guint8 *body, guint16 size)
{
  FpiByteReader *reader;
  const guint8 *xb;
  const guint8 *yb;
  const guint16 KEY_SIZE = 0x90;

  reader = fpi_byte_reader_new (body, size);

  fpi_byte_reader_set_pos (reader, 0x08);
  fpi_byte_reader_get_data (reader, 0x20, &xb);
  fpi_byte_reader_set_pos (reader, 0x4c);
  fpi_byte_reader_get_data (reader, 0x20, &yb);

  BIGNUM *x = BN_lebin2bn (xb, 0x20, NULL);
  BIGNUM *y = BN_lebin2bn (yb, 0x20, NULL);

  EC_KEY *key = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);

  if (!EC_KEY_set_public_key_affine_coordinates (key, x, y))
    {
      fp_err ("Failed to set public key coordinates, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  g_clear_pointer (&x, BN_free);
  g_clear_pointer (&y, BN_free);

  self->ecdh_q = key;

  const guint8 *signature;
  guint32 signature_length;

  fpi_byte_reader_set_pos (reader, KEY_SIZE);

  fpi_byte_reader_get_uint32_le (reader, &signature_length);
  fpi_byte_reader_get_data (reader, signature_length, &signature);

  while (fpi_byte_reader_get_remaining (reader))
    {
      guint8 b;
      fpi_byte_reader_get_uint8 (reader, &b);
      if (b != 0)
        fp_warn ("Expected zero at %d", fpi_byte_reader_get_pos (reader));
    }

  x = BN_bin2bn (DEVICE_KEY_X, 0x20, NULL);
  y = BN_bin2bn (DEVICE_KEY_Y, 0x20, NULL);

  EC_KEY *device_key = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);

  if (!EC_KEY_set_public_key_affine_coordinates (device_key, x, y))
    {
      fp_err ("Failed to set public key coordinates, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  guint8 dgst[SHA256_DIGEST_LENGTH];
  SHA256 (body, KEY_SIZE, dgst);

  int verify_status = ECDSA_verify (0, dgst, SHA256_DIGEST_LENGTH, signature, signature_length, device_key);
  if (verify_status == 0)
    fp_err ("Untrusted device");
  else if (verify_status < 0)
    fp_err ("Failed to verify signature, error: %lu, %s",
            ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));

  g_clear_pointer (&reader, fpi_byte_reader_free);
  g_clear_pointer (&device_key, EC_KEY_free);
  g_clear_pointer (&x, BN_free);
  g_clear_pointer (&y, BN_free);
}

static void
init_certificate (FpiDeviceVfs0097 *self, const guint8 *body, guint16 size)
{
  self->certificate_length = size;
  self->certificate = g_malloc0 (size);
  memcpy (self->certificate, body, size);
}

static void
init_keys (FpDevice *dev)
{
  FpiByteReader reader;
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (dev);
  guint32 size;

  fpi_byte_reader_init (&reader, self->buffer, self->buffer_length);
  fpi_byte_reader_skip (&reader, 2);
  fpi_byte_reader_get_uint32_le (&reader, &size);
  fpi_byte_reader_skip (&reader, 2);

  g_assert (fpi_byte_reader_get_remaining (&reader) == size);

  guint16 id, body_size;
  const guint8 *hash;
  const guint8 *body;

  while (fpi_byte_reader_get_remaining_inline (&reader) > 0)
    {
      fpi_byte_reader_get_uint16_le (&reader, &id);
      fpi_byte_reader_get_uint16_le (&reader, &body_size);

      if (id == 0xffff)
        break;

      fpi_byte_reader_get_data (&reader, SHA256_DIGEST_LENGTH, &hash);
      fpi_byte_reader_get_data (&reader, body_size, &body);

      guint8 calc_hash[SHA256_DIGEST_LENGTH];
      SHA256 (body, body_size, calc_hash);

      if (memcmp (calc_hash, hash, SHA256_DIGEST_LENGTH) != 0)
        {
          fp_warn ("Hash mismatch for block %d", id);
          continue;
        }

      switch (id)
        {
        case 0:
        case 1:
        case 2:
          // All zeros
          break;

        case 3:
          init_certificate (self, body, body_size);
          break;

        case 4:
          init_private_key (self, body, body_size);
          break;

        case 6:
          init_ecdh (self, body, body_size);
          break;

        default:
          fp_warn ("Unhandled block id %04x (%d bytes)", id, body_size);
          break;
        }
    }
}

/* SSM for exec_command */

struct command_ssm_data_t
{
  guint8 *buffer;
  guint   length;
};

static void
command_ssm_data_free (void *data)
{
  struct command_ssm_data_t *ssm_data = data;

  g_free (ssm_data->buffer);
  g_free (ssm_data);
}

static void
exec_command_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (dev);
  struct command_ssm_data_t *data = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case EXEC_COMMAND_SM_ENCRYPT:
      if (self->tls)
        {
          guint8 *raw = data->buffer;
          guint raw_length = data->length;

          guint8 *encrypted;
          guint encrypted_length;

          tls_sign_and_encrypt (CONTENT_TYPE_DATA, self->sign_key, self->encryption_key, raw, raw_length,
                                &encrypted, &encrypted_length);
          tls_create_record (CONTENT_TYPE_DATA, encrypted, encrypted_length, &data->buffer, &data->length);

          g_free (raw);
          g_free (encrypted);
        }

      fpi_ssm_next_state (ssm);
      break;

    case EXEC_COMMAND_SM_WRITE:
      async_write (ssm, dev, data->buffer, data->length);
      break;

    case EXEC_COMMAND_SM_READ:
      async_read (ssm, dev, self->buffer, VFS_USB_BUFFER_SIZE, &self->buffer_length);
      break;

    case EXEC_COMMAND_SM_DECRYPT:
      if (self->tls)
        {
          guint8 *encrypted;
          guint encrypted_length;

          guint8 *raw;
          guint raw_length;

          tls_parse_record (CONTENT_TYPE_DATA, self->buffer, self->buffer_length, &encrypted, &encrypted_length);
          tls_decrypt_and_validate (CONTENT_TYPE_DATA, self->validation_key, self->decryption_key, encrypted, encrypted_length,
                                    &raw, &raw_length);

          memcpy (self->buffer, raw, raw_length);
          self->buffer_length = raw_length;

          g_free (raw);
          g_free (encrypted);
        }

      fpi_ssm_next_state (ssm);
      break;

    default:
      fp_err ("Unknown EXEC_COMMAND_SM state");
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
    }
}

/* Send command and read response */
static void
exec_command (FpDevice *dev, FpiSsm *ssm, const guint8 *buffer, guint length)
{
  struct command_ssm_data_t *data;
  FpiSsm *subsm;

  data = g_new0 (struct command_ssm_data_t, 1);
  data->buffer = g_memdup (buffer, length);
  data->length = length;

  subsm = fpi_ssm_new (dev, exec_command_ssm, EXEC_COMMAND_SM_STATES);
  fpi_ssm_set_data (subsm, data, command_ssm_data_free);

  fpi_ssm_start_subsm (ssm, subsm);
}

/* TLS */

static void
tls_create_record (guint8 content_type, guint8 *fragment, guint length, guint8 **out, guint *out_len)
{
  FpiByteWriter writer;

  fpi_byte_writer_init_with_size (&writer, 1 + G_N_ELEMENTS (TLS_VERSION) + 2 + length, TRUE);
  fpi_byte_writer_put_uint8 (&writer, content_type);
  fpi_byte_writer_put_data (&writer, TLS_VERSION, G_N_ELEMENTS (TLS_VERSION));
  fpi_byte_writer_put_uint16_be (&writer, length); // Length of the record
  fpi_byte_writer_put_data (&writer, fragment, length);

  *out_len = fpi_byte_writer_get_size (&writer);
  *out = fpi_byte_writer_reset_and_get_data (&writer);
}

static void
tls_parse_record (guint8 content_type, guint8 *fragment, guint length, guint8 **out, guint *out_len)
{
  FpiByteReader reader;
  const guint8 *data;
  guint16 data_length;
  guint8 type;

  fpi_byte_reader_init (&reader, fragment, length);
  fpi_byte_reader_get_uint8 (&reader, &type);
  fpi_byte_reader_skip (&reader, G_N_ELEMENTS (TLS_VERSION));

  if (type != content_type)
    fp_warn ("Unexpected content type: %02x", type);

  fpi_byte_reader_get_uint16_be (&reader, &data_length);
  fpi_byte_reader_get_data (&reader, data_length, &data);

  *out = g_memdup (data, data_length);
  *out_len = data_length;
}

static void
tls_sign_and_encrypt (guint8 content_type, guint8 sign_key[0x20], guint8 encryption_key[0x20],
                      guint8 *data, guint length, guint8 **out, guint *out_len)
{
  guint8 *record;
  guint record_length;
  guint8 hmac[0x20];
  guint8 iv[0x10];

  guint8 *encrypted;
  guint encrypted_length;

  RAND_bytes (iv, G_N_ELEMENTS (iv));

  tls_create_record (content_type, data, length, &record, &record_length);
  HMAC_SHA256 (sign_key, 0x20, record, record_length, hmac);
  g_free (record);

  guint8 *block = g_malloc0 (length + 0x20);
  memcpy (block, data, length);
  memcpy (block + length, hmac, 0x20);

  encrypted_length = ((length + 16) / 16) * 16 + 0x10 + 0x20;
  encrypted = g_malloc0 (encrypted_length);
  memcpy (encrypted, iv, 0x10);

  EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new ();

  gint elen1, elen2, elen3;

  if (!EVP_EncryptInit (context, EVP_aes_256_cbc (), encryption_key, iv))
    {
      fp_err ("Failed to initialize EVP decrypt, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  EVP_CIPHER_CTX_set_padding (context, 0);

  if (!EVP_EncryptUpdate (context, encrypted + 0x10, &elen1, block, (int) length + 0x20))
    {
      fp_err ("Failed to EVP encrypt, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  g_free (block);

  gint pad_len = encrypted_length - (length + 0x10 + 0x20);
  if (pad_len == 0)
    pad_len = 16;

  guint8 *pad = g_malloc0 (pad_len);
  memset (pad, pad_len - 1, pad_len);

  if (!EVP_EncryptUpdate (context, encrypted + 0x10 + elen1, &elen2, pad, pad_len))
    {
      fp_err ("Failed to EVP encrypt, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  g_free (pad);

  if (!EVP_EncryptFinal (context, encrypted + 0x10 + elen1 + elen2, &elen3))
    {
      fp_err ("EVP Final encrypt failed, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  EVP_CIPHER_CTX_free (context);

  *out = encrypted;
  *out_len = 0x10 + elen1 + elen2 + elen3;
}

static void
tls_decrypt_and_validate (guint8 content_type, guint8 validation_key[0x20], guint8 decryption_key[0x20],
                          guint8 *data, guint length, guint8 **out, guint *out_len)
{
  guint8 *record;
  guint record_length;
  guint8 hmac[0x20];
  guint8 iv[0x10];

  guint8 *decrypted = g_malloc0 (length);

  memcpy (iv, data, G_N_ELEMENTS (iv));

  EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new ();

  gint delen1, delen2;

  if (!EVP_DecryptInit (context, EVP_aes_256_cbc (), decryption_key, iv))
    {
      fp_err ("Failed to initialize EVP decrypt, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  EVP_CIPHER_CTX_set_padding (context, 0);

  if (!EVP_DecryptUpdate (context, decrypted, &delen1, data + G_N_ELEMENTS (iv), length - G_N_ELEMENTS (iv)))
    {
      fp_err ("Failed to EVP decrypt, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  if (!EVP_DecryptFinal (context, decrypted + delen1, &delen2))
    {
      fp_err ("EVP Final decrypt failed, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  EVP_CIPHER_CTX_free (context);

  guint full_length = delen1 + delen2;
  guint no_pad_length = full_length - (decrypted[full_length - 1] + 1);
  guint no_hash_length = no_pad_length - 0x20;

  tls_create_record (content_type, decrypted, no_hash_length, &record, &record_length);
  HMAC_SHA256 (validation_key, 0x20, record, record_length, hmac);
  g_free (record);

  if (memcmp (hmac, decrypted + no_hash_length, 0x20) != 0)
    fp_warn ("TLS record validation failed");

  *out = decrypted;
  *out_len = no_hash_length;
}

static void
tls_create_handshake (guint8 msg_type, guint8 *msg, guint length, guint8 **out, guint *out_len)
{
  FpiByteWriter writer;

  fpi_byte_writer_init_with_size (&writer, 1 + 3 + length, TRUE);
  fpi_byte_writer_put_uint8 (&writer, msg_type);
  fpi_byte_writer_put_uint24_be (&writer, length); // Length of the message
  fpi_byte_writer_put_data (&writer, msg, length);

  *out_len = fpi_byte_writer_get_size (&writer);
  *out = fpi_byte_writer_reset_and_get_data (&writer);
}

static void
tls_prepare_client_hello (FpiDeviceVfs0097 *self, guint8 **record, guint *record_length)
{
  FpiByteWriter writer;
  guint client_hello_length;

  static const guint8 session[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  static const guint8 suits[] = { 0xc0, 0x05,     // TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
                                  0x00, 0x3d };   // TLS_RSA_WITH_AES_256_CBC_SHA256
  static const guint8 extensions[] = { 0x00, 0x04, 0x00, 0x02, 0x00, 0x17,  // Truncated HMAC
                                       0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}; // EC Point Format: Uncompressed

  RAND_bytes (self->client_random, G_N_ELEMENTS (self->client_random));

  fpi_byte_writer_init (&writer);

  fpi_byte_writer_put_data (&writer, TLS_VERSION, G_N_ELEMENTS (TLS_VERSION));
  fpi_byte_writer_put_data (&writer, self->client_random, G_N_ELEMENTS (self->client_random));

  fpi_byte_writer_put_uint8 (&writer, G_N_ELEMENTS (session));
  fpi_byte_writer_put_data (&writer, session, G_N_ELEMENTS (session));

  fpi_byte_writer_put_uint16_be (&writer, G_N_ELEMENTS (suits));
  fpi_byte_writer_put_data (&writer, suits, G_N_ELEMENTS (suits));

  fpi_byte_writer_put_uint8 (&writer, 0); // No compression

  fpi_byte_writer_put_uint16_be (&writer, G_N_ELEMENTS (extensions) - 2);  // Non standard
  fpi_byte_writer_put_data (&writer, extensions, G_N_ELEMENTS (extensions));

  client_hello_length = fpi_byte_writer_get_size (&writer);
  guint8 *client_hello = fpi_byte_writer_reset_and_get_data (&writer);

  guint8 *handshake;
  guint handshake_length;
  tls_create_handshake (HANDSHAKE_TYPE_CLIENT_HELLO, client_hello, client_hello_length,
                        &handshake, &handshake_length);
  g_free (client_hello);

  SHA256_Update (&self->handshake_hash, handshake, handshake_length);

  tls_create_record (CONTENT_TYPE_HANDSHAKE, handshake, handshake_length, record, record_length);
  g_free (handshake);
}

static void
tls_prepare_certificate_kex_verify (FpiDeviceVfs0097 *self, guint8 **record, guint *record_length)
{
  FpiByteWriter writer;

  guint8 *h_certificate;
  guint h_certificate_length;
  guint8 *h_client_key_exchange;
  guint h_client_key_exchange_length;
  guint8 *h_certificate_verify;
  guint h_certificate_verify_length;

  guint8 change_cipher_spec[] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
  guint change_cipher_spec_length = G_N_ELEMENTS (change_cipher_spec);

  guint8 *h_finished;
  guint h_finished_length;
  guint8 *h_finished_enc;
  guint h_finished_enc_length;
  guint8 *tls_finished;
  guint tls_finished_length;

  guint8 *data;
  guint length;

  fpi_byte_writer_init (&writer);
  fpi_byte_writer_put_int24_be (&writer, self->certificate_length);
  fpi_byte_writer_put_int24_be (&writer, self->certificate_length);
  fpi_byte_writer_put_int16_be (&writer, 0); // Add 2 byte padding (0xfd 0xf3 in the dump)
  fpi_byte_writer_put_data (&writer, self->certificate, self->certificate_length);
  length = fpi_byte_writer_get_size (&writer);
  data = fpi_byte_writer_reset_and_get_data (&writer);

  tls_create_handshake (HANDSHAKE_TYPE_CERTIFICATE, data, length, &h_certificate, &h_certificate_length);
  SHA256_Update (&self->handshake_hash, h_certificate, h_certificate_length);

  g_free (data);

  const EC_POINT *point = EC_KEY_get0_public_key (self->session_key);
  EC_GROUP *group = EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1);
  BIGNUM *x = BN_new ();
  BIGNUM *y = BN_new ();
  EC_POINT_get_affine_coordinates (group, point, x, y, NULL);

  guint8 coord[0x20];

  fpi_byte_writer_init (&writer);
  fpi_byte_writer_put_uint8 (&writer, POINT_FORM_UNCOMPRESSED);

  BN_bn2bin (x, coord);
  fpi_byte_writer_put_data (&writer, coord, 0x20);

  BN_bn2bin (y, coord);
  fpi_byte_writer_put_data (&writer, coord, 0x20);

  length = fpi_byte_writer_get_size (&writer);
  data = fpi_byte_writer_reset_and_get_data (&writer);

  tls_create_handshake (HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, data, length, &h_client_key_exchange, &h_client_key_exchange_length);
  SHA256_Update (&self->handshake_hash, h_client_key_exchange, h_client_key_exchange_length);

  g_free (data);
  EC_GROUP_free (group);
  BN_free (x);
  BN_free (y);

  guint8 hash[0x20];
  SHA256_CTX ctx;
  memcpy (&ctx, &self->handshake_hash, sizeof (ctx));
  SHA256_Final (hash, &ctx);

  guint8 signature[0x48];
  guint signature_length;
  do   // Do we really need to loop?
    ECDSA_sign (0, hash, 0x20, signature, &signature_length, self->private_key);
  while (signature_length != 0x48);

  tls_create_handshake (HANDSHAKE_TYPE_CERTIFICATE_VERIFY, signature, signature_length,
                        &h_certificate_verify, &h_certificate_verify_length);
  SHA256_Update (&self->handshake_hash, h_certificate_verify, h_certificate_verify_length);
  SHA256_Final (hash, &self->handshake_hash);

  guint8 verify[0xC];
  PRF_SHA256 (self->master_secret, 0x30,
              LABEL_CLIENT_FINISHED, G_N_ELEMENTS (LABEL_CLIENT_FINISHED),
              hash, 0x20,
              verify, 0xC);
  tls_create_handshake (HANDSHAKE_TYPE_FINISHED, verify, 0xC, &h_finished, &h_finished_length);

  tls_sign_and_encrypt (CONTENT_TYPE_HANDSHAKE, self->sign_key, self->encryption_key, h_finished, h_finished_length,
                        &h_finished_enc, &h_finished_enc_length);
  tls_create_record (CONTENT_TYPE_HANDSHAKE, h_finished_enc, h_finished_enc_length, &tls_finished, &tls_finished_length);

  fpi_byte_writer_init (&writer);
  fpi_byte_writer_put_data (&writer, h_certificate, h_certificate_length);
  fpi_byte_writer_put_data (&writer, h_client_key_exchange, h_client_key_exchange_length);
  fpi_byte_writer_put_data (&writer, h_certificate_verify, h_certificate_verify_length);
  length = fpi_byte_writer_get_size (&writer);
  data = fpi_byte_writer_reset_and_get_data (&writer);

  guint8 *first_part;
  guint first_part_length;
  tls_create_record (CONTENT_TYPE_HANDSHAKE, data, length, &first_part, &first_part_length);
  g_free (data);

  fpi_byte_writer_init (&writer);
  fpi_byte_writer_put_data (&writer, first_part, first_part_length);
  fpi_byte_writer_put_data (&writer, change_cipher_spec, change_cipher_spec_length);
  fpi_byte_writer_put_data (&writer, tls_finished, tls_finished_length);
  *record_length = fpi_byte_writer_get_size (&writer);
  *record = fpi_byte_writer_reset_and_get_data (&writer);
}


static void
tls_make_keys (FpiDeviceVfs0097 *self)
{
  EVP_PKEY_CTX *ctx;
  EVP_PKEY *pkey;
  EVP_PKEY *peer_pkey;

  self->session_key = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);

  if (!EC_KEY_generate_key (self->session_key))
    {
      fp_err ("Failed to generate key, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  if (!EC_KEY_check_key (self->session_key))
    {
      fp_err ("Failed to check key, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  pkey = EVP_PKEY_new ();
  peer_pkey = EVP_PKEY_new ();

  if (!EVP_PKEY_set1_EC_KEY (pkey, self->session_key))
    {
      fp_err ("Failed to initialize session pkey, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  if (!EVP_PKEY_set1_EC_KEY (peer_pkey, self->ecdh_q))
    {
      fp_err ("Failed to initialize peer pkey, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  if (!(ctx = EVP_PKEY_CTX_new (pkey, NULL)))
    {
      fp_err ("Failed to initialize context, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  if (EVP_PKEY_derive_init (ctx) <= 0)
    {
      fp_err ("Failed to initialize derive, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  if (EVP_PKEY_derive_set_peer (ctx, peer_pkey) <= 0)
    {
      fp_err ("Failed to set peer key, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  guint8 *pre_master_secret;
  gulong pre_master_secret_length;

  /* Determine buffer length */
  if (EVP_PKEY_derive (ctx, NULL, &pre_master_secret_length) <= 0)
    {
      fp_err ("Failed to calculate derive length, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  if (!(pre_master_secret = g_malloc0 (pre_master_secret_length)))
    {
      fp_err ("Failed to allocate memory for derived key, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  if (EVP_PKEY_derive (ctx, pre_master_secret, &pre_master_secret_length) <= 0)
    {
      fp_err ("Failed to derive key, error: %lu, %s",
              ERR_peek_last_error (), ERR_error_string (ERR_peek_last_error (), NULL));
      return;
    }

  guint8 *seed = g_malloc0 (0x20 + 0x20);
  memcpy (seed, self->client_random, 0x20);
  memcpy (seed + 0x20, self->server_random, 0x20);

  PRF_SHA256 (pre_master_secret, pre_master_secret_length, LABEL_MASTER_SECRET, G_N_ELEMENTS (LABEL_MASTER_SECRET),
              seed, 0x40, self->master_secret, 0x30);

  g_free (pre_master_secret);

  guint8 key_block[0x120];
  PRF_SHA256 (self->master_secret, 0x30, LABEL_KEY_EXPANSION, G_N_ELEMENTS (LABEL_KEY_EXPANSION),
              seed, 0x40, key_block, 0x120);

  memcpy (self->sign_key, key_block, 0x20);
  memcpy (self->validation_key, key_block + 0x20, 0x20);
  memcpy (self->encryption_key, key_block + 0x40, 0x20);
  memcpy (self->decryption_key, key_block + 0x60, 0x20);

#if 0
  fp_dbg ("sign key");
  print_hex (self->sign_key, 0x20);
  fp_dbg ("validation_key");
  print_hex (self->validation_key, 0x20);
  fp_dbg ("encryption_key");
  print_hex (self->encryption_key, 0x20);
  fp_dbg ("decryption_key");
  print_hex (self->decryption_key, 0x20);
#endif

  g_free (seed);
  EVP_PKEY_free (pkey);
  EVP_PKEY_free (peer_pkey);
  EVP_PKEY_CTX_free (ctx);
}

static void
tls_parse_handshake_response (FpiDeviceVfs0097 *self)
{
  FpiByteReader reader;

  fpi_byte_reader_init (&reader, self->buffer, self->buffer_length);

  guint8 type;
  guint16 length;

  fpi_byte_reader_get_uint8 (&reader, &type);
  fpi_byte_reader_skip (&reader, G_N_ELEMENTS (TLS_VERSION));
  fpi_byte_reader_get_uint16_be (&reader, &length);
  fp_dbg ("Type: %x, Length: %x", type, length);

  while (fpi_byte_reader_get_remaining (&reader) > 0)
    {
      static const guint8 header_length = 4;
      guint8 handshake_type;
      guint handshake_length;
      const guint8 *data;
      guint pos;
      guint8 tmp8;
      guint16 tmp16;

      pos = fpi_byte_reader_get_pos (&reader);

      fpi_byte_reader_get_uint8 (&reader, &handshake_type);
      fpi_byte_reader_get_uint24_be (&reader, &handshake_length);

      fp_dbg ("Handshake Type: %x, len: %x", handshake_type, handshake_length);
      fpi_byte_reader_set_pos (&reader, pos);

      fpi_byte_reader_get_data (&reader, header_length + handshake_length, &data);
      SHA256_Update (&self->handshake_hash, data, header_length + handshake_length);

      fpi_byte_reader_set_pos (&reader, pos);
      fpi_byte_reader_skip (&reader, header_length);

      switch (handshake_type)
        {
        case HANDSHAKE_TYPE_SERVER_HELLO:
          fpi_byte_reader_skip (&reader, G_N_ELEMENTS (TLS_VERSION));
          fpi_byte_reader_get_data (&reader, 0x20, &data);
          memcpy (self->server_random, data, 0x20);

          fpi_byte_reader_get_uint8 (&reader, &self->session_id_length);
          fpi_byte_reader_get_data (&reader, self->session_id_length, &data);
          self->session_id = g_memdup (data, self->session_id_length);

          fpi_byte_reader_get_uint16_be (&reader, &tmp16);
          if (tmp16 != 0xc005)
            fp_warn ("Unexpected cipher suite: %04x", tmp16);

          fpi_byte_reader_get_uint8 (&reader, &tmp8);
          if (tmp8 != 0)
            fp_warn ("Unexpected compression: %02x", tmp8);

          break;

        case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
          fpi_byte_reader_get_uint8 (&reader, &tmp8); // Length of requested certificate types
          if (tmp8 != 1)
            fp_warn ("Server requested too many certificate types: %02x", tmp8);

          fpi_byte_reader_get_uint8 (&reader, &tmp8); // Certificate type
          if (tmp8 != 64) // CERT_TYPE_ECDSA_SIGN
            fp_warn ("Server requested an unexpected certificate type: %02d", tmp8);

          fpi_byte_reader_get_uint16_le (&reader, &tmp16);
          if (tmp16 != 0)
            fp_warn ("Server requested an unsupported signature and hash algorithms");

          break;

        case HANDSHAKE_TYPE_SERVER_DONE:
          if (handshake_length != 0)
            fp_warn ("Expected no data for HANDSHAKE_TYPE_SERVER_DONE");
          break;

        default:
          fp_warn ("Unexpected handshake message type: %02x", handshake_type);
        }
    }
}

static void
handshake_command (guint8 *data, guint data_length, guint8 **buffer, guint *buffer_length)
{
  static const guint8 command[] = {0x44, 0x00, 0x00, 0x00};
  static const guint len = G_N_ELEMENTS (command);

  *buffer_length = data_length + len;
  *buffer = g_malloc0 (*buffer_length);
  memcpy (*buffer, command, len);
  memcpy (*buffer + len, data, data_length);
}

/* SSM loop for TLS handshake */
static void
handshake_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (dev);
  guint8 *record;
  guint record_length;

  guint8 *command;
  guint command_length;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case TLS_HANDSHAKE_SM_INIT:
      SHA256_Init (&self->handshake_hash);
      fpi_ssm_next_state (ssm);
      break;

    case TLS_HANDSHAKE_SM_CLIENT_HELLO:
      tls_prepare_client_hello (self, &record, &record_length);
      handshake_command (record, record_length, &command, &command_length);
      g_free (record);

      exec_command (dev, ssm, command, command_length);
      g_free (command);
      break;

    case TLS_HANDSHAKE_SM_SERVER_HELLO:
      tls_parse_handshake_response (self);
      fpi_ssm_next_state (ssm);
      break;

    case TLS_HANDSHAKE_SM_MAKE_KEYS:
      tls_make_keys (self);
      fpi_ssm_next_state (ssm);
      break;

    case TLS_HANDSHAKE_SM_CLIENT_FINISHED:
      tls_prepare_certificate_kex_verify (self, &record, &record_length);
      handshake_command (record, record_length, &command, &command_length);
      g_free (record);

      exec_command (dev, ssm, command, command_length);
      g_free (command);
      break;

    case TLS_HANDSHAKE_SM_SERVER_FINISHED:
      if (self->buffer[0] == CONTENT_TYPE_ALERT)
        {
          // 15 03 03 00 02 02 2f
          fp_err ("TLS handshake failed: %02x", self->buffer[6]);
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
        }
      else
        {
          fp_info ("TLS connection established");
          self->tls = TRUE;
          fpi_ssm_next_state (ssm);
        }
      break;

    default:
      fp_err ("Unknown EXEC_COMMAND_SM state");
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
    }
}

static void
do_handshake (FpDevice *dev, FpiSsm *ssm)
{
  FpiSsm *subsm;

  subsm = fpi_ssm_new (dev, handshake_ssm, TLS_HANDSHAKE_STATES);
  fpi_ssm_start_subsm (ssm, subsm);
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
      fpi_ssm_next_state (ssm);
      break;

    case HANDSHAKE:
      do_handshake (dev, ssm);
      break;

    default:
      fp_err ("Unknown INIT_SM state");
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
    }
}

static void
get_users_db_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GET_USER_STORAGE:
      {
        FpiByteWriter writer;
        fpi_byte_writer_init (&writer);
        fpi_byte_writer_put_uint8 (&writer, 0x4b);
        fpi_byte_writer_put_uint16_le (&writer, 0);
        fpi_byte_writer_put_uint16_le (&writer, G_N_ELEMENTS (STORAGE));
        fpi_byte_writer_put_data (&writer, STORAGE, G_N_ELEMENTS (STORAGE));

        guint length = fpi_byte_writer_get_size (&writer);
        guint8 *data = fpi_byte_writer_reset_and_get_data (&writer);

        exec_command (dev, ssm, data, length);
        break;
      }

    case PARSE_USER_STORAGE:
      {
        FpiByteReader reader;
        fpi_byte_reader_init (&reader, self->buffer, self->buffer_length);

        guint16 status;
        fpi_byte_reader_get_uint16_le (&reader, &status);

        if (status == 0x04b3)
          fp_warn ("Weird status");

        if (status != 0)
          fp_warn ("Bad status");

        guint16 recid, usercnt, namesz, unknwn;
        fpi_byte_reader_get_uint16_le (&reader, &recid);
        fpi_byte_reader_get_uint16_le (&reader, &usercnt);
        fpi_byte_reader_get_uint16_le (&reader, &namesz);
        fpi_byte_reader_get_uint16_le (&reader, &unknwn);

        fp_dbg ("recid: %u, usercnt: %u, namesz: %u, unknwn: %u", recid, usercnt, namesz, unknwn);

        GSList *list = NULL;

        for (int i = 0; i < usercnt; i++)
          {
            guint16 id, val;
            fpi_byte_reader_get_uint16_le (&reader, &id);
            fpi_byte_reader_get_uint16_le (&reader, &val);

            list = g_slist_append (list, GUINT_TO_POINTER (id));

            fp_dbg ("DBID: %d, ValueSize: %d", id, val);
          }

        const guint8 *name;
        fpi_byte_reader_get_data (&reader, namesz, &name);

        fp_dbg ("Name: %s", name);
        if (fpi_byte_reader_get_remaining (&reader) > 0)
          fp_warn ("Junk at the end of the storage info response");

        fpi_ssm_set_data (ssm, list, NULL); // TODO: ?

        fpi_ssm_next_state (ssm);
        break;
      }

    case GET_USER:
      {
        GSList *list = fpi_ssm_get_data (ssm);
        GSList *first = list;

        list = g_slist_remove_link (list, first);
        fpi_ssm_set_data (ssm, list, NULL);

        guint16 id = GPOINTER_TO_UINT (first->data);

        g_slist_free (first);

        fp_info ("Querying DB for user: %u", id);

        FpiByteWriter writer;
        fpi_byte_writer_init (&writer);
        fpi_byte_writer_put_uint8 (&writer, 0x4a);
        fpi_byte_writer_put_uint16_le (&writer, id); // DBID
        fpi_byte_writer_put_uint16_le (&writer, 0); // Lookup: DBID
        fpi_byte_writer_put_uint16_le (&writer, 0); // Lookup: IDENTITY

        guint length = fpi_byte_writer_get_size (&writer);
        guint8 *data = fpi_byte_writer_reset_and_get_data (&writer);

        exec_command (dev, ssm, data, length);
        break;
      }

    case PARSE_USER:
      {
        FpiByteReader reader;
        fpi_byte_reader_init (&reader, self->buffer, self->buffer_length);

        guint16 status;
        fpi_byte_reader_get_uint16_le (&reader, &status);

        if (status == 0x04b3)
          fp_warn ("Weird status");

        if (status != 0)
          fp_warn ("Bad status");

        guint16 recid, fingercnt, unknwn, identitysz;
        fpi_byte_reader_get_uint16_le (&reader, &recid);
        fpi_byte_reader_get_uint16_le (&reader, &fingercnt);
        fpi_byte_reader_get_uint16_le (&reader, &unknwn);
        fpi_byte_reader_get_uint16_le (&reader, &identitysz);

        fp_dbg ("recid: %u, fingercnt: %u, unknwn: %u, identitysz: %u", recid, fingercnt, unknwn, identitysz);

        guint16 *ids = g_malloc0 (fingercnt * sizeof (guint16));
        guint16 *subtypes = g_malloc0 (fingercnt * sizeof (guint16));

        for (int i = 0; i < fingercnt; i++)
          {
            guint16 stgid, valsz;
            fpi_byte_reader_get_uint16_le (&reader, &ids[i]);
            fpi_byte_reader_get_uint16_le (&reader, &subtypes[i]);
            fpi_byte_reader_get_uint16_le (&reader, &stgid);
            fpi_byte_reader_get_uint16_le (&reader, &valsz);

            fp_dbg ("FRID: %d, SUBTYPE: %d, STGID: %d, VALSZ: %d", ids[i], subtypes[i], stgid, valsz);
          }

        const guint8 *identity;
        fpi_byte_reader_get_data (&reader, identitysz, &identity);

        {
          FpiByteReader r;
          guint type;

          fpi_byte_reader_init (&r, identity, identitysz);
          fpi_byte_reader_get_uint32_le (&r, &type);

          if (type == 3)
            {
              guint length;
              fpi_byte_reader_get_uint32_le (&r, &length);

              guint8 revision, subcnt;
              fpi_byte_reader_get_uint8 (&r, &revision);
              fpi_byte_reader_get_uint8 (&r, &subcnt);

              guint8 auth[6];
              for (int i = 0; i < 6; i++)
                fpi_byte_reader_get_uint8 (&r, &auth[i]);

              if (memcmp (auth, FPRINT_AUTHORITY, G_N_ELEMENTS (FPRINT_AUTHORITY)) == 0)
                {
                  const guint8 *username;
                  fpi_byte_reader_get_data (&r, subcnt * 4, &username);
                  fp_dbg ("Found FPrint user: %s", username);

                  for (int i = 0; i < fingercnt; i++)
                    {
                      FpPrint *print = fp_print_new (dev);

                      fpi_print_set_device_stored (print, TRUE);
                      fpi_print_set_type (print, FPI_PRINT_RAW);

                      fp_print_set_username (print, (gchar *) username);
                      fp_print_set_finger (print, subtype_to_finger (subtypes[i]));
                      GDateTime *dt = g_date_time_new_now_local ();
                      GDate *date = g_date_new_dmy (
                        g_date_time_get_day_of_month (dt),
                        g_date_time_get_month (dt),
                        g_date_time_get_year (dt));
                      fp_print_set_enroll_date (print, date);

                      g_date_time_unref (dt);
                      g_date_free (date);

                      char buf[100];
                      sprintf (buf, "id = %d", ids[i]);
                      fp_print_set_description (print, buf);

                      g_ptr_array_add (self->list_result, g_object_ref_sink (print));
                    }
                }
              else
                {
                  gulong authority = (gulong) auth[0] << 40 |
                                     (gulong) auth[1] << 32 |
                                     auth[2] << 24 |
                                     auth[3] << 16 |
                                     auth[4] << 8  |
                                     auth[5];

                  guint *subauth = g_malloc0_n (subcnt, sizeof (guint));
                  for (int i = 0; i < subcnt; i++)
                    fpi_byte_reader_get_uint32_le (&r, &subauth[i]);

                  gchar buffer[100] = { 0 };
                  for (int i = 0, l = 0; i < subcnt; i++)
                    {
                      sprintf (&buffer[l], "%u-", subauth[i]);
                      l = strlen (buffer);
                    }

                  g_free (subauth);

                  fp_dbg ("SID: S-%d-%ld-%s", revision, authority, buffer);
                }
            }
          else
            {
              fp_warn ("Unknown identity type");
            }
        }

        g_free (ids);
        g_free (subtypes);

        if (fpi_byte_reader_get_remaining (&reader) > 0)
          fp_warn ("Junk at the end of the user info response");

        GSList *list = fpi_ssm_get_data (ssm);
        if (list != NULL)
          fpi_ssm_jump_to_state (ssm, GET_USER);
        else
          fpi_ssm_next_state (ssm);
        break;
      }

    default:
      fp_err ("Unknown GET_USERS_DB_SM state: %d", fpi_ssm_get_cur_state (ssm));
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
    }
}

static void
enroll_interrupt_cb (FpiUsbTransfer *transfer,
                     FpDevice       *dev,
                     gpointer        user_data,
                     GError         *error)
{
  if (error)
    {
      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          g_error_free (error);
          fpi_ssm_jump_to_state (transfer->ssm, ENROLL_FAILED);
          return;
        }

      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  g_clear_pointer (&error, g_error_free);

  fpi_ssm_next_state (transfer->ssm);
}

static void
match_interrupt_cb (FpiUsbTransfer *transfer,
                    FpDevice       *dev,
                    gpointer        user_data,
                    GError         *error)
{
  gint *data = fpi_ssm_get_data (transfer->ssm);

  *data = -1;

  if (error)
    {
      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          g_error_free (error);
          fpi_ssm_jump_to_state (transfer->ssm, MATCH_USER_FINISH);
          return;
        }

      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  g_clear_pointer (&error, g_error_free);

  enum FINGERPRINT_VERIFY_SM next_state;
  if (transfer->buffer[0] == 0x03 && transfer->buffer[4] == 0xdb)
    {
      *data = transfer->buffer[2];
      next_state = MATCH_USER_FINISH;
    }
  else if (INTERRUPT_CMP (transfer, INTERRUPT_USER_NOT_FOUND))
    {
      next_state = MATCH_USER_FINISH;
    }
  else
    {
      fp_warn ("Unknown interrupt: %02x %02x %02x %02x %02x", transfer->buffer[0], transfer->buffer[1], transfer->buffer[2],
               transfer->buffer[3], transfer->buffer[4]);
      next_state = MATCH_USER_FINISH;
    }
  fpi_ssm_jump_to_state (transfer->ssm, next_state);
}

static void
capture_interrupt_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  if (error)
    {
      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          g_error_free (error);
//      fpi_ssm_jump_to_state (transfer->ssm, SCAN_FAILED);
          fpi_ssm_mark_failed (transfer->ssm, error);
          return;
        }

      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  g_clear_pointer (&error, g_error_free);

  enum CAPTURE_SM next_state;
  if (INTERRUPT_CMP (transfer, INTERRUPT_WAITING_FINGER))
    {
      next_state = WAITING_FINGER;
    }
  else if (INTERRUPT_CMP (transfer, INTERRUPT_FINGER_DOWN))
    {
      next_state = FINGER_DOWN;
    }
  else if (INTERRUPT_CMP (transfer, INTERRUPT_SCANNING_FINGERPRINT))
    {
      next_state = SCANNING_FINGERPRINT;
    }
  else if (INTERRUPT_CMP (transfer, INTERRUPT_SCAN_FAILED_TOO_SHORT))
    {
      next_state = SCAN_FAILED_TOO_SHORT;
    }
  else if (INTERRUPT_CMP (transfer, INTERRUPT_SCAN_FAILED_TOO_FAST))
    {
      next_state = SCAN_FAILED_TOO_FAST;
    }
  else if (INTERRUPT_CMP (transfer, INTERRUPT_SCAN_COMPLETED))
    {
      next_state = SCAN_COMPLETED;
    }
  else if (INTERRUPT_CMP (transfer, INTERRUPT_SCAN_SUCCESS))
    {
      next_state = SCAN_SUCCESS;
    }
  else
    {
      fp_warn ("Unknown interrupt: %02x %02x %02x %02x %02x",
               transfer->buffer[0], transfer->buffer[1], transfer->buffer[2], transfer->buffer[3], transfer->buffer[4]);
      next_state = SCAN_FAILED;
    }
  fpi_ssm_jump_to_state (transfer->ssm, next_state);
}

static void
capture_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (dev);
  gint *data = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VERIFY_START:
      exec_command (dev, ssm, LED_GREEN_ON, G_N_ELEMENTS (LED_GREEN_ON));
      break;

    case START_IDENTIFY_PROGRAM:
      exec_command (dev, ssm, CAPTURE_PROGRAM, G_N_ELEMENTS (CAPTURE_PROGRAM));
      break;

    case AWAIT_INTERRUPT:
      await_interrupt (dev, ssm, capture_interrupt_cb);
      break;

    case WAITING_FINGER:
      fp_info ("Waiting for finger");
      fpi_ssm_jump_to_state (ssm, AWAIT_INTERRUPT);
      break;

    case FINGER_DOWN:
      fp_info ("Finger is on the sensor");
      fpi_ssm_jump_to_state (ssm, AWAIT_INTERRUPT);
      break;

    case SCANNING_FINGERPRINT:
      fp_info ("Fingerprint scan in progress");
      fpi_ssm_jump_to_state (ssm, AWAIT_INTERRUPT);
      break;

    case SCAN_FAILED_TOO_SHORT:
      fp_info ("Impossible to read fingerprint, keep it in the sensor");
      fpi_ssm_jump_to_state (ssm, SCAN_FAILED);
      break;

    case SCAN_FAILED_TOO_FAST:
      fp_info ("Impossible to read fingerprint, movement was too fast");
      fpi_ssm_jump_to_state (ssm, SCAN_FAILED);
      break;

    case SCAN_COMPLETED:
      fp_info ("Fingerprint scan completed");
      fpi_ssm_jump_to_state (ssm, AWAIT_INTERRUPT);
      break;

    case SCAN_SUCCESS:
      fp_info ("Successful scan");
      *data = TRUE;
      fpi_ssm_mark_completed (ssm);
      break;

    case SCAN_FAILED:
      fp_info ("Failed to scan");
      *data = FALSE;
      fpi_ssm_mark_completed (ssm);
      break;

    default:
      fp_err ("Unknown CAPTURE_SM state");
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
    }
}

static void
do_capture (FpDevice *dev, FpiSsm *ssm, gpointer data)
{
  FpiSsm *subsm;

  subsm = fpi_ssm_new (dev, capture_ssm, CAPTURE_STATES);
  fpi_ssm_set_data (subsm, data, NULL);
  fpi_ssm_start_subsm (ssm, subsm);
}

struct create_record_data_t
{
  guint16 dbid;

  guint16 parent_id;
  guint8  type;
  guint8 *data;
  guint   length;
  guint  *record_id;
};

static void
create_record_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (dev);
  struct create_record_data_t *ssm_data = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CR_GET_USER_STORAGE: {
        FpiByteWriter writer;
        fpi_byte_writer_init (&writer);
        fpi_byte_writer_put_uint8 (&writer, 0x4b);
        fpi_byte_writer_put_uint16_le (&writer, 0);
        fpi_byte_writer_put_uint16_le (&writer, G_N_ELEMENTS (STORAGE));
        fpi_byte_writer_put_data (&writer, STORAGE, G_N_ELEMENTS (STORAGE));

        guint length = fpi_byte_writer_get_size (&writer);
        guint8 *data = fpi_byte_writer_reset_and_get_data (&writer);

        exec_command (dev, ssm, data, length);
        break;
      }

    case CR_PARSE_USER_STORAGE: {
        FpiByteReader reader;
        fpi_byte_reader_init (&reader, self->buffer, self->buffer_length);

        guint16 status;
        fpi_byte_reader_get_uint16_le (&reader, &status);

        if (status == 0x04b3)
          fp_warn ("Weird status");

        if (status != 0)
          fp_warn ("Bad status");

        guint16 recid, usercnt, namesz, unknwn;
        fpi_byte_reader_get_uint16_le (&reader, &recid);
        fpi_byte_reader_get_uint16_le (&reader, &usercnt);
        fpi_byte_reader_get_uint16_le (&reader, &namesz);
        fpi_byte_reader_get_uint16_le (&reader, &unknwn);

        ssm_data->dbid = recid;
        fpi_ssm_next_state (ssm);
        break;
      }

    case CREATE_RECORD_INIT: {
        guint8 command[] = {0x45};
        exec_command (dev, ssm, command, G_N_ELEMENTS (command));
        break;
      }

    case DB_WRITE_ENABLE:
      exec_command (dev, ssm, DB_WRITE_ENABLE_COMMAND, G_N_ELEMENTS (DB_WRITE_ENABLE_COMMAND));
      break;

    case CREATE_RECORD_COMMAND:
      {
        FpiByteWriter writer;
        fpi_byte_writer_init (&writer);

        fpi_byte_writer_put_uint8 (&writer, 0x47);
        fpi_byte_writer_put_uint16_le (&writer, ssm_data->parent_id);
        fpi_byte_writer_put_uint16_le (&writer, ssm_data->type);
        fpi_byte_writer_put_uint16_le (&writer, ssm_data->dbid);
        fpi_byte_writer_put_uint16_le (&writer, ssm_data->length);
        fpi_byte_writer_put_data (&writer, ssm_data->data, ssm_data->length);

        guint length = fpi_byte_writer_get_size (&writer);
        guint8 *command = fpi_byte_writer_reset_and_get_data (&writer);

        exec_command (dev, ssm, command, length);
        break;
      }

    case GET_RECORD_ID:
      {
        guint16 id = self->buffer[2] + (self->buffer[3] << 8u);
        *ssm_data->record_id = id;
        fpi_ssm_next_state (ssm);
        break;
      }

    case FLUSH_CHANGES:
      {
        guint8 command[] = { 0x1a };
        exec_command (dev, ssm, command, G_N_ELEMENTS (command));
        break;
      }

    default:
      fp_err ("Unknown FINGERPRINT_VERIFY_SM state");
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
    }
}

static void
do_create_record (FpDevice *dev, FpiSsm *ssm, guint16 parent_id, guint8 type, guint8 *data, guint length, guint *record_id)
{
  FpiSsm *subsm;

  struct create_record_data_t *ssm_data = g_new0 (struct create_record_data_t, 1);

  ssm_data->parent_id = parent_id;
  ssm_data->type = type;
  ssm_data->data = data;
  ssm_data->length = length;
  ssm_data->record_id = record_id;

  subsm = fpi_ssm_new (dev, create_record_ssm, CREATE_RECORD_STATES);
  fpi_ssm_set_data (subsm, ssm_data, g_free);
  fpi_ssm_start_subsm (ssm, subsm);
}

static void
verify_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (dev);
  gboolean *data = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VERIFY_CAPTURE:
      do_capture (dev, ssm, data);
      break;

    case VERIFY_CHECK_CAPTURE:
      if (*data)
        fpi_ssm_next_state (ssm);
      else
        fpi_ssm_jump_to_state (ssm, VERIFY_CAPTURE);
      break;

    case MATCH_USER:
      exec_command (dev, ssm, MATCH_SEQUENCE, G_N_ELEMENTS (MATCH_SEQUENCE));
      break;

    case MATCH_USER_WAIT:
      await_interrupt (dev, ssm, match_interrupt_cb);
      break;

    case MATCH_USER_FINISH:
      if (*data < 0)
        fp_info ("Fingerprint UNKNOWN");
      else
        fp_info ("Fingerprint FOUND = %d", *data);
      fpi_ssm_jump_to_state (ssm, RESET);
      break;

    case RESET:
      exec_command (dev, ssm, RESET_SEQUENCE, G_N_ELEMENTS (RESET_SEQUENCE));
      break;

    case FINISH:
      exec_command (dev, ssm, FINISH_SEQUENCE, G_N_ELEMENTS (FINISH_SEQUENCE));
      break;

    case VERIFY_SUCCESS:
      if (*data < 0)
        fpi_ssm_jump_to_state (ssm, VERIFY_FAILED);
      else
        exec_command (dev, ssm, LED_GREEN_BLINK, G_N_ELEMENTS (LED_GREEN_BLINK));
      break;

    case VERIFY_SUCCESS_FINISH:
      fpi_ssm_mark_completed (ssm);
      break;

    case VERIFY_FAILED:
      exec_command (dev, ssm, LED_RED_BLINK, G_N_ELEMENTS (LED_RED_BLINK));
      break;

    case VERIFY_FAILED_FINISH:
      fpi_ssm_mark_completed (ssm);
      break;

    default:
      fp_err ("Unknown FINGERPRINT_VERIFY_SM state");
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
    }
}

struct enroll_ssm_data_t
{
  gboolean captured;

  guint8  *tinfo;
  guint    tinfo_len;

  GArray  *template;
  guint    key;
  guint    progress;

  FpPrint *print;

  guint    user_id;
  guint    fingerprint_id;
  guint    fingerprint_data_id;
};

static void
enroll_ssm_data_clear (gpointer pointer)
{
  struct enroll_ssm_data_t *data = pointer;

  g_array_unref (data->template);
  g_free (data);
}

static void
enroll_ssm (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (dev);
  struct enroll_ssm_data_t *data = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ENROLL_CAPTURE:
      do_capture (dev, ssm, &data->captured);
      break;

    case ENROLL_CHECK_CAPTURE:
      if (data->captured)
        fpi_ssm_next_state (ssm);
      else
        fpi_ssm_jump_to_state (ssm, ENROLL_CAPTURE);
      break;

    case APPEND_TEMPLATE_1:
      {
        guint8 command[] = { 0x68, (data->key >> 0) & 0xff, (data->key >> 8) & 0xff, (data->key >> 16) & 0xff, (data->key >> 24) & 0xff, 0, 0, 0, 0 };
        exec_command (dev, ssm, command, G_N_ELEMENTS (command));
        break;
      }

    case APPEND_TEMPLATE_1_NEW_KEY:
      {
        guint key = (self->buffer[2] << 0) +
                    (self->buffer[3] << 8) +
                    (self->buffer[4] << 16) +
                    (self->buffer[5] << 24);
        data->key = key;
        fpi_ssm_next_state (ssm);
        break;
      }

    case APPEND_TEMPLATE_1_WAIT:
      await_interrupt (dev, ssm, enroll_interrupt_cb);
      break;

    case APPEND_TEMPLATE_2:
      {
        guint8 *command = g_malloc0 (data->template->len + 1);
        command[0] = 0x6b;
        memcpy (command + 1, data->template->data, data->template->len);
        exec_command (dev, ssm, command, data->template->len + 1);
        g_free (command);
        break;
      }

    case APPEND_TEMPLATE_2_WAIT:
      await_interrupt (dev, ssm, enroll_interrupt_cb);
      break;

    case APPEND_TEMPLATE_3:
      {
        guint8 *command = g_malloc0 (data->template->len + 1);
        command[0] = 0x6b;
        memcpy (command + 1, data->template->data, data->template->len);
        exec_command (dev, ssm, command, data->template->len + 1);
        g_free (command);
        break;
      }

    case APPEND_TEMPLATE_3_CALC:
      {
        guint length = self->buffer[2] + (self->buffer[3] << 8);
        if (length != self->buffer_length - 4)
          fp_warn ("Incorrect response length");

        data->progress = self->buffer[4 + 0x3c];

        g_array_set_size (data->template, 0);
        g_array_insert_vals (data->template, 0, self->buffer + 0x6c + 4, self->buffer_length - 0x6c - 4);
      }

    case APPEND_TEMPLATE_4:
      {
        guint8 command[] = { 0x69, 0x00, 0x00, 0x00, 0x00 };
        exec_command (dev, ssm, command, G_N_ELEMENTS (command));
        break;
      }

    case CHECK_PROGRESS:
      fpi_device_enroll_progress (dev, data->progress / 10, data->print, NULL);
      if (data->progress == 100)
        fpi_ssm_next_state (ssm);
      else
        fpi_ssm_jump_to_state (ssm, ENROLL_CAPTURE);
      break;

    case PARSE_TEMPLATE:
      {
        FpiByteWriter writer;

        guint ciphertext_size = (guint8) data->template->data[2] + (((guint8) data->template->data[3]) << 8);
        guint template_size = 8 + ciphertext_size + 0x30;

        fpi_byte_writer_init (&writer);
        fpi_byte_writer_put_uint16_le (&writer, 1);
        fpi_byte_writer_put_uint16_le (&writer, template_size);
        fpi_byte_writer_put_data (&writer, (guint8 *) data->template->data, template_size);

        guint16 part1_len = fpi_byte_writer_get_size (&writer);
        guint8 *part1 = fpi_byte_writer_reset_and_get_data (&writer);

        fpi_byte_writer_init (&writer);
        fpi_byte_writer_put_uint16_le (&writer, 2);
        fpi_byte_writer_put_uint16_le (&writer, 0x20);
        fpi_byte_writer_put_data (&writer, (guint8 *) data->template->data + data->template->len - 0x20, 0x20);

        guint16 part2_len = fpi_byte_writer_get_size (&writer);
        guint8 *part2 = fpi_byte_writer_reset_and_get_data (&writer);

        fpi_byte_writer_init (&writer);
        fpi_byte_writer_put_uint16_le (&writer, finger_to_subtype (fp_print_get_finger (data->print)));
        fpi_byte_writer_put_uint16_le (&writer, 3);
        fpi_byte_writer_put_uint16_le (&writer, part1_len + part2_len);
        fpi_byte_writer_put_uint16_le (&writer, 0x20);
        fpi_byte_writer_put_data (&writer, part1, part1_len);
        fpi_byte_writer_put_data (&writer, part2, part2_len);

        guint8 padding[0x20] = { 0 };
        fpi_byte_writer_put_data (&writer, padding, 0x20);

        data->tinfo_len = fpi_byte_writer_get_size (&writer);
        data->tinfo = fpi_byte_writer_reset_and_get_data (&writer);

        fpi_ssm_next_state (ssm);
        break;
      }

    case LOOKUP_USER:
      data->user_id = 11; // TODO
      fpi_ssm_jump_to_state (ssm, ADD_FINGERPRINT); // TODO
      break;

    case CREATE_USER:
      fpi_ssm_jump_to_state (ssm, ADD_FINGERPRINT); // TODO
      break;

    case ADD_FINGERPRINT:
      do_create_record (dev, ssm, data->user_id, 0xb, data->tinfo, data->tinfo_len, &data->fingerprint_id);
      break;

    case ADD_FINGERPRINT_DATA:
      {
        fp_dbg ("Added FINGERPRINT with id: %d", data->fingerprint_id);

        guint8 *serialized;
        gsize length;
        GError *error;
        GVariant *fdata;
        FpiByteWriter writer;

        fpi_print_set_device_stored (data->print, TRUE);
        fpi_print_set_type (data->print, FPI_PRINT_RAW);

        fdata = g_variant_new ("q", data->fingerprint_id);
        g_object_set (data->print, "fpi-data", fdata, NULL);

        fp_print_serialize (data->print, &serialized, &length, &error);

        fpi_byte_writer_init (&writer);
        fpi_byte_writer_put_uint16_le (&writer, 1);
        fpi_byte_writer_put_uint16_le (&writer, length);
        fpi_byte_writer_put_data (&writer, serialized, length);

        guint buffer_length = fpi_byte_writer_get_size (&writer);
        guint8 *buffer = fpi_byte_writer_reset_and_get_data (&writer);

        do_create_record (dev, ssm, data->fingerprint_id, 0x8, buffer, buffer_length, &data->fingerprint_data_id);
        break;
      }

    case ENROLL_SUCCESS:
      {
        fp_dbg ("Added FINGERPRINT DATA with id: %d", data->fingerprint_data_id);
        exec_command (dev, ssm, LED_GREEN_BLINK, G_N_ELEMENTS (LED_GREEN_BLINK));
        break;
      }

    case ENROLL_SUCCESS_FINISH:
    case ENROLL_FAILED:
    case ENROLL_FAILED_FINISH:
      fpi_ssm_next_state (ssm); // TODO
      break;

    default:
      fp_err ("Unknown ENROLL_SM state");
      fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
    }
}

/* Clears all fprint data */
static void
clear_data (FpiDeviceVfs0097 *self)
{
  g_clear_pointer (&self->seed, g_free);
  g_clear_pointer (&self->buffer, g_free);
  g_clear_pointer (&self->certificate, g_free);
  g_clear_pointer (&self->session_id, g_free);
  g_clear_pointer (&self->private_key, EC_KEY_free);
  g_clear_pointer (&self->ecdh_q, EC_KEY_free);
  g_clear_object (&self->interrupt_cancellable);
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

  self->tls = FALSE;

  guint8 seed[] = "VirtualBox\0" "0";
  self->seed_length = G_N_ELEMENTS (seed);
  self->seed = g_malloc0 (G_N_ELEMENTS (seed));
  memcpy (self->seed, seed, G_N_ELEMENTS (seed));

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

  self->buffer = g_malloc0 (VFS_USB_BUFFER_SIZE);

  self->interrupt_cancellable = g_cancellable_new ();

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
dev_list_callback (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (dev);

  fpi_device_list_complete (FP_DEVICE (self),
                            g_steal_pointer (&self->list_result),
                            error);
}

static void
dev_list (FpDevice *device)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);

  self->list_result = g_ptr_array_new_with_free_func (g_object_unref);

  FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (self), get_users_db_ssm, GET_USERS_DB_STATES);
  fpi_ssm_start (ssm, dev_list_callback);
}

/* Enroll print */
static void
dev_enroll_callback (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (dev);

  struct enroll_ssm_data_t *ssm_data = fpi_ssm_get_data (ssm);

//  fpi_device_get_enroll_data (device, &print);
//  fpi_device_enroll_complete (device, g_object_ref (print), NULL);

  fpi_device_enroll_complete (FP_DEVICE (self), g_object_ref (ssm_data->print), NULL);
}

static void
dev_enroll (FpDevice *device)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);
  FpPrint *print = NULL;

  fpi_device_get_enroll_data (device, &print);

  FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (self), enroll_ssm, FINGERPRINT_ENROLL_STATES);

  struct enroll_ssm_data_t *data = g_new0 (struct enroll_ssm_data_t, 1);
  data->template = g_array_new (FALSE, TRUE, sizeof (guint8));
  data->print = print;

  fpi_ssm_set_data (ssm, data, enroll_ssm_data_clear);
  fpi_ssm_start (ssm, dev_enroll_callback);
}

/* Delete print */
static void
dev_delete (FpDevice *device)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);

  G_DEBUG_HERE ();

  fpi_device_delete_complete (FP_DEVICE (self), NULL);
}

/* Verify print */
static void
dev_verify_callback (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  gboolean *data = fpi_ssm_get_data (ssm);

  fpi_device_verify_report (dev, (*data < 0) ? FPI_MATCH_FAIL : FPI_MATCH_SUCCESS, NULL, NULL);
  fpi_device_verify_complete (dev, NULL);
}

static void
dev_verify (FpDevice *device)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);
  FpPrint *print = NULL;

  fpi_device_get_verify_data (device, &print);
  g_debug ("username: %s", fp_print_get_username (print));

  gboolean *data = g_new0 (gboolean, 1);

  FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (self), verify_ssm, FINGERPRINT_VERIFY_STATES);
  fpi_ssm_set_data (ssm, data, g_free);
  fpi_ssm_start (ssm, dev_verify_callback);
}

/* Cancel current action */
static void
dev_cancel (FpDevice *device)
{
  FpiDeviceVfs0097 *self = FPI_DEVICE_VFS0097 (device);

  // TODO: Send RESET and FINISH sequence?

  /* Cancel any current interrupt transfer (resulting us to go into
   * response reading mode again); then create a new cancellable
   * for the next transfers. */
  g_cancellable_cancel (self->interrupt_cancellable);
  g_clear_object (&self->interrupt_cancellable);
  self->interrupt_cancellable = g_cancellable_new ();
}

static guint
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
//  g_assert (FALSE);
  guint8 seed[] = "VirtualBox\0" "0";

  self->seed_length = G_N_ELEMENTS (seed);
  self->seed = g_malloc0 (G_N_ELEMENTS (seed));
  memcpy (self->seed, seed, G_N_ELEMENTS (seed));

// TODO: Device is initialized via VirtualBox, so real HW id is not useful for now

//  char name[1024], serial[1024];
//  guint name_len, serial_len;
//
//  name_len = read_dmi ("/sys/class/dmi/id/product_name", name, sizeof (name));
//  serial_len = read_dmi ("/sys/class/dmi/id/product_serial", serial, sizeof (serial));
//
//  if (name_len == 0)
//    {
//      // Set system id to default value (i.e. "VirtualBox")
//    }
//
//  self->seed = g_malloc0 (name_len + serial_len + 2);
//
//  memcpy (self->seed, name, name_len + 1);
//  memcpy (self->seed + name_len + 1, serial, serial_len + 1);

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
  dev_class->nr_enroll_stages = 10;

  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->delete = dev_delete;
  dev_class->verify = dev_verify;
  dev_class->cancel = dev_cancel;
  dev_class->list = dev_list;
}
