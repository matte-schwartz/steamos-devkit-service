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

#include <glib.h>

gchar *dk_find_hook (const gchar * const *hook_dirs,
                     gboolean use_default_hooks,
                     const gchar *name, GError **error);
gchar *dk_sanitize_machine_name (const gchar *machine_name);
int dk_dup_close_on_exec_fd (gint fd, GError **error);
gboolean dk_hook_is_generic_python (const gchar *script);
const char * dk_get_best_python (void);
