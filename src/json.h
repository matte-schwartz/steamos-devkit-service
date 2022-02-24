/*
 * This file is part of steamos-devkit
 * SPDX-License-Identifier: LGPL-2.1+
 *
 * Copyright © 2018 Collabora Ltd
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

#include <json-glib/json-glib.h>

gboolean dk_json_parser_load_from_bytes (JsonParser *parser,
                                         GBytes *bytes,
                                         GError **error);

#if JSON_CHECK_VERSION(1, 2, 0)
#define dk_json_to_string(node, pretty) json_to_string (node, pretty)
#else
gchar *dk_json_to_string (JsonNode *node, gboolean pretty);
#endif
