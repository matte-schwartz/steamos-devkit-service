/*
 * This file is part of steamos-devkit
 * SPDX-License-Identifier: LGPL-2.1+
 *
 * Copyright © 2018 Collabora Ltd
 * Incorporates code from GLib, copyright © 2009 Codethink Ltd
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

#include "utils.h"
#include "defines.h"

#include <gio/gio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * Windows command-line parsing makes even Unix /bin/sh look
 * well-documented and consistent. To make life easier for the Windows
 * client-side, escape anything that could become a problem.
 * https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/
 */
gchar *
dk_sanitize_machine_name (const gchar *machine_name)
{
  const char *p = machine_name;
  GString *buffer = NULL;
  gsize i;

  g_return_val_if_fail (machine_name != NULL, NULL);

  buffer = g_string_new ("");

  while (*p != '\0')
    {
      gunichar u = g_utf8_get_char_validated (p, -1);

      /* Not UTF-8? Turn it into underscores. */
      if (u == (gunichar) -1 || u == (gunichar) -2)
        {
          g_string_append_c (buffer, '_');
          p++;
          continue;
        }

      /*
       * Allow all printable Unicode outside the ASCII range, plus the
       * ASCII punctuation that is not special for cmd.exe, PowerShell,
       * CommandLineFromArgvW (inside double quotes), Windows filenames,
       * or DNS.
       *
       * We forbid <>:"/\|?* because they are not allowed in filenames,
       * . because it's special in filenames and DNS, "`$ because they
       * are special in PowerShell, "\%^ because they are special in
       * cmd.exe, "\ because they are special for CommandLineFromArgvW.
       * There isn't a whole lot left.
       */
      if (u > 127)
        {
          if (g_unichar_isprint (u))
            g_string_append_unichar (buffer, u);
          else
            g_string_append_c (buffer, '_');
        }
      else
        {
          if (g_ascii_isalnum ((char) u) ||
              strchr (" !#&'()+,-;=@[]_{}~", (char) u) != NULL)
            g_string_append_unichar (buffer, u);
          else
            g_string_append_c (buffer, '_');
        }

      p = g_utf8_next_char (p);
    }

  for (i = 0; i < buffer->len; i++)
    {
      if (!g_ascii_isspace (buffer->str[i]))
        break;
    }

  g_string_erase (buffer, 0, i);

  for (i = buffer->len; i > 0; i--)
    {
      if (!g_ascii_isspace (buffer->str[i - 1]))
        break;
    }

  g_string_truncate (buffer, i);

  /* DNS-SD machine names are DNS labels, limited to 63 bytes, so if
   * it's longer than that we truncate to no more than 60 and append
   * an ellipsis */
  if (buffer->len > 63)
    {
      while (buffer->len > 60)
        {
          const gchar *nul = &buffer->str[buffer->len];
          const gchar *prev;

          prev = g_utf8_find_prev_char (buffer->str, nul);

          g_string_truncate (buffer, prev - buffer->str);
        }

      g_string_append (buffer, "\xe2\x80\xa6");
    }

  if (buffer->len == 0)
    g_string_append_c (buffer, '_');

  return g_string_free (buffer, FALSE);
}

/*
 * Returns: (transfer full): The absolute path of the hook script
 */
gchar *
dk_find_hook (const gchar * const *hook_dirs,
              gboolean use_default_hooks,
              const gchar *name,
              GError **error)
{
  const gchar * const *hook_dir;
  gchar *script;

  g_return_val_if_fail (name != NULL, NULL);

  for (hook_dir = hook_dirs;
       hook_dir != NULL && *hook_dir != NULL;
       hook_dir++)
    {
      script = g_build_filename (*hook_dir, name, NULL);

      if (access (script, X_OK) == 0)
        return script;

      g_free (script);
    }

  if (!use_default_hooks)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Unable to find script \"%s\" in specified "
                   "hook directories",
                   name);
      return NULL;
    }

  script = g_strdup_printf ("/etc/%s/hooks/%s", PACKAGE, name);

  if (access (script, X_OK) == 0)
    return script;

  g_free (script);

  script = g_strdup_printf ("%s/%s", DEVKIT_HOOKS_DIR, name);

  if (access (script, X_OK) == 0)
    return script;

  g_free (script);

  script = g_strdup_printf ("%s/%s.sample", DEVKIT_HOOKS_DIR, name);

  if (access (script, X_OK) == 0)
    return script;

  g_free (script);

  g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
               "Unable to find script \"%s\" in \"/etc/%s/hooks\" "
               "or \"%s\"",
               name, PACKAGE, DEVKIT_HOOKS_DIR);
  return NULL;
}

/* Taken from gio/gunixfdlist.c */
int
dk_dup_close_on_exec_fd (gint fd, GError ** error)
{
  gint new_fd;
  gint s;

#ifdef F_DUPFD_CLOEXEC
  do
    new_fd = fcntl (fd, F_DUPFD_CLOEXEC, 0l);
  while (new_fd < 0 && (errno == EINTR));

  if (new_fd >= 0)
    return new_fd;

  /* if that didn't work (new libc/old kernel?), try it the other way. */
#endif

  do
    new_fd = dup (fd);
  while (new_fd < 0 && (errno == EINTR));

  if (new_fd < 0)
    {
      int saved_errno = errno;

      g_set_error (error, G_IO_ERROR,
                   g_io_error_from_errno (saved_errno),
                   "dup: %s", g_strerror (saved_errno));

      return -1;
    }

  do
    {
      s = fcntl (new_fd, F_GETFD);

      if (s >= 0)
        s = fcntl (new_fd, F_SETFD, (long) (s | FD_CLOEXEC));
    }
  while (s < 0 && (errno == EINTR));

  if (s < 0)
    {
      int saved_errno = errno;

      g_set_error (error, G_IO_ERROR,
                   g_io_error_from_errno (saved_errno),
                   "fcntl: %s", g_strerror (saved_errno));
      close (new_fd);

      return -1;
    }

  return new_fd;
}

/*
 * Read the first few bytes of @script and return TRUE if its first
 * line is `#!/usr/bin/env python`, possibly with some extra whitespace.
 * The devkit server special-cases these scripts to be run by Python 3
 * if available, or Python 2 otherwise.
 *
 * Note that if the script starts with "#!/usr/bin/python",
 * "#!/usr/bin/python2", "#!/usr/bin/python3", "#!/usr/bin/env python2"
 * or "#!/usr/bin/python3", that doesn't count as a generic version of
 * Python for our purposes.
 */
gboolean
dk_hook_is_generic_python (const gchar *script)
{
  FILE *fh;
  char buf[80];
  size_t bytes_read;

  fh = fopen (script, "rb");

  if (fh == NULL)
    return FALSE;

  bytes_read = fread (buf, 1, sizeof (buf) - 1, fh);
  buf[bytes_read] = '\0';
  fclose (fh);

  if (g_str_has_prefix (buf, "#!") &&
      g_regex_match_simple ("#![ \t]*/usr/bin/env[ \t]+python[ \t]*\n",
                            buf, G_REGEX_ANCHORED, 0))
    return TRUE;

  return FALSE;
}

/*
 * Return a Python interpreter.
 *
 * The result is guaranteed to be non-NULL, but is not guaranteed to
 * exist: if neither python3 nor python exists in the PATH, we'll
 * try to run "python whatever.py" and fail, which is error-handling
 * that we'd need to have anyway.
 *
 * Returns: "python3", or "python" if there is no python3 in PATH
 */
const char *
dk_get_best_python (void)
{
  static const char *best_python = NULL;
  gchar *found;

  if (best_python != NULL)
    return best_python;

  found = g_find_program_in_path ("python3");

  if (found != NULL)
    best_python = "python3";
  else
    best_python = "python";

  g_free (found);
  return best_python;
}
