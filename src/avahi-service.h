/*
 * This file is part of steamos-devkit
 * SPDX-License-Identifier: LGPL-2.1+
 *
 * Copyright © 2017 Collabora Ltd
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this package.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <glib.h>
#include <glib-object.h>
#include <stdint.h>

typedef struct _DkdAvahiService DkdAvahiService;
typedef struct _DkdAvahiServiceClass DkdAvahiServiceClass;

#define DKD_TYPE_AVAHI_SERVICE (dkd_avahi_service_get_type ())
#define DKD_AVAHI_SERVICE(obj) \
  G_TYPE_CHECK_INSTANCE_CAST ((obj), DKD_TYPE_AVAHI_SERVICE, DkdAvahiService)
#define DKD_AVAHI_SERVICE_CLASS(cls) \
  G_TYPE_CHECK_CLASS_CAST ((cls), DKD_TYPE_AVAHI_SERVICE, DkdAvahiServiceClass)
#define DKD_IS_AVAHI_SERVICE(obj) \
  G_TYPE_CHECK_INSTANCE_TYPE ((obj), DKD_TYPE_AVAHI_SERVICE)
#define DKD_IS_AVAHI_SERVICE_CLASS(cls) \
  G_TYPE_CHECK_CLASS_TYPE ((cls), DKD_TYPE_AVAHI_SERVICE)
#define DKD_AVAHI_SERVICE_GET_CLASS(obj) \
  G_TYPE_INSTANCE_GET_CLASS ((obj), DKD_TYPE_AVAHI_SERVICE, DkdAvahiServiceClass)

DkdAvahiService *dkd_avahi_service_new (void);
GType dkd_avahi_service_get_type (void);

gboolean dkd_avahi_service_start (DkdAvahiService *self,
                                  const gchar *machine_name,
                                  uint64_t server_port,
                                  const gchar *entry_point_user,
                                  const gchar * const *devkit1_argv,
                                  const gchar *settings_json,
                                  GMainLoop *loop,
                                  GError **error);
gboolean dkd_avahi_service_reconfigure (DkdAvahiService *self,
                                        const gchar *machine_name,
                                        uint64_t server_port,
                                        const gchar *entry_point_user,
                                        const gchar * const *devkit1_argv,
                                        const gchar *settings_json,
                                        GError **error);
void dkd_avahi_service_stop (DkdAvahiService *self);
