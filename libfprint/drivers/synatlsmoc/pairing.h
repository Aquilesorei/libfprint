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

/* Based on the only certificate magic supported by the sensor - 0x5f3f */
#define CERTIFICATE_SIZE 400
#define CERTIFICATE_DATA_SIZE 142 /* signed range; sign_size (u16) follows */
#define CERTIFICATE_SIGN_OFFSET (CERTIFICATE_DATA_SIZE + 2)
#define CERTIFICATE_MAX_SIGN_SIZE (CERTIFICATE_SIZE - CERTIFICATE_SIGN_OFFSET) /* 256 */
#define CERTIFICATE_MAX_KEY_SIZE 68

#define ECC_KEY_SIZE 32
#define CERTIFICATE_MAGIC 0x5F3F
#define CERTIFICATE_CURVE 23

typedef struct
{
  guint16 magic;
  guint16 curve;
  guint8 *x;
  guint8 *y;
  EVP_PKEY *pub_key;
  guint8 cert_type;
  guint16 sign_size;
  guint8 *sign;
} Certificate;

typedef struct
{
  EVP_PKEY *client_key;
  guint8 client_cert_raw[CERTIFICATE_SIZE];
  Certificate client_cert;
  guint8 server_cert_raw[CERTIFICATE_SIZE];
  Certificate server_cert;
} SensorPairingData;

void free_pairing_data (SensorPairingData *pairing_data);

gboolean create_host_certificate (EVP_PKEY *server_key,
                                  guint8 **host_certificate_bytes,
                                  GError **error);
