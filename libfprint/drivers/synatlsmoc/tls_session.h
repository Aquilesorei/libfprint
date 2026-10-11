/*
 * Synaptics Tudor Match-In-Sensor driver for libfprint
 *
 * Copyright (c) 2024 Francesco Circhetta, Vojtěch Pluskal
 *
 * Some parts are based on:
 *    - work of Popax21, see: https://github.com/Popax21/synaTudor/tree/rev
 *    - egismoc libfprint driver by Joshua Grisham, see egismoc.c,
 *       of which portions are from elanmoc libfprint driver (C) 2021 Elan
 *       Microelectronic
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

#include <glib.h>
#include <openssl/evp.h>

#define AES_GCM_KEY_SIZE 32
#define AES_GCM_IV_SIZE 4
#define AES_GCM_TAG_SIZE 16

#define NONCE_SIZE 8

typedef struct _TlsSession TlsSession;

TlsSession *tls_session_new (const guint8 *client_cert, gsize client_cert_len,
                             EVP_PKEY *client_key, EVP_PKEY *server_pub_key);
void tls_session_free (TlsSession *self);

gboolean tls_session_establish (TlsSession *self, GError **error);
gboolean tls_session_flush_send_buffer (TlsSession *self, guint8 **data, gsize *size, GError **error);
gboolean tls_session_has_data (TlsSession *self);
gboolean tls_session_receive_ciphertext (TlsSession *self, guint8 *data, gsize size, GError **error);
gboolean tls_session_wrap (TlsSession *self, guint8 *pdata, gsize pdata_size, guint8 **cdata, gsize *cdata_size, GError **error);
gboolean tls_session_unwrap (TlsSession *self, guint8 *cdata, gsize cdata_size, guint8 **pdata, gsize *pdata_size, GError **error);
gboolean tls_session_close (TlsSession *self, GError **error);

gboolean tls_prf (guint8 *secret, gsize secret_size, const gchar *label, guint label_len, guint8 *seed, guint seed_size, guint8 *out, gsize outsize, const char *hash_algo, GError **error);
