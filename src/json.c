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

#include "json.h"
#include "defines.h"

gboolean
dk_json_parser_load_from_bytes (JsonParser *parser,
                                GBytes *bytes,
                                GError **error)
{
  gconstpointer data = NULL;
  gsize len = 0;

  g_return_val_if_fail (JSON_IS_PARSER (parser), FALSE);
  g_return_val_if_fail (bytes != NULL, FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  data = g_bytes_get_data (bytes, &len);

  if (data == NULL)
    {
      /* JsonParser doesn't like NULL data, even if its length is 0.
       * g_bytes_get_data() documents a guarantee that it will only
       * return NULL if the length is 0. */
      g_assert (len == 0);
      data = "";
    }

  return json_parser_load_from_data (parser, data, len, error);
}

#if !JSON_CHECK_VERSION(1, 2, 0)
gchar *
dk_json_to_string (JsonNode *node,
                   gboolean pretty)
{
  JsonGenerator *gen;
  gchar *ret;

  gen = json_generator_new ();
  json_generator_set_root (gen, node);  /* a copy */
  json_generator_set_pretty (gen, pretty);
  ret = json_generator_to_data (gen, NULL);
  g_object_unref (gen);
  return ret;
}
#endif
