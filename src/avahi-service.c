/*
 * This file is part of steamos-devkit
 * SPDX-License-Identifier: LGPL-2.1+
 *
 * Copyright © 2017-2018 Collabora Ltd
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

#include "avahi-service.h"

#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/alternative.h>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/timeval.h>
#include <avahi-glib/glib-malloc.h>
#include <avahi-glib/glib-watch.h>
#include <errno.h>
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"
#include "defines.h"

struct _DkdAvahiService
{
  GObject parent_instance;
  AvahiEntryGroup *group;
  gchar *machine_name;
  char *service_name;
  uint64_t service_port;
  AvahiClient *client;
  AvahiGLibPoll *glib_poll;
  gchar *login;
  gchar *settings;
  /* devkit1= prefix followed by shell-escaped arguments */
  gchar *devkit1_txt;
  GMainLoop *loop;
  GKeyFile *state;
  const gchar *state_dir;
  gchar *state_subdir;
  gchar *state_file;
};

struct _DkdAvahiServiceClass
{
  GObjectClass parent_class;
};

G_DEFINE_TYPE (DkdAvahiService, dkd_avahi_service, G_TYPE_OBJECT)

/* Format version number for TXT record. Increment if we make an
 * incompatible change that would cause current clients to parse it
 * incorrectly (hopefully we will never need this). See
 * https://tools.ietf.org/html/rfc6763#section-6.7 */
#define CURRENT_TXTVERS "txtvers=1"

#define COLLISION_MAX_TRY 3
#define STATE_GROUP "State"
#define STATE_KEY_MACHINE_NAME "MachineName"
#define STATE_KEY_SERVICE_NAME "ServiceName"

static gboolean dkd_avahi_service_create_services (DkdAvahiService *self,
                                                   AvahiClient *c,
                                                   GError **error);

static void
dkd_avahi_service_load_state (DkdAvahiService *self)
{
  GError *error = NULL;

  if (self->state == NULL)
    {
      self->state = g_key_file_new ();

      /* Use /var/lib if we're root, or ~/.local/share otherwise */
      if (getuid () == 0)
        self->state_dir = DEVKIT_LOCALSTATEDIR "/lib";
      else
        self->state_dir = g_get_user_data_dir ();

      self->state_subdir = g_build_filename (self->state_dir, PACKAGE, NULL);
      self->state_file = g_build_filename (self->state_subdir, "state.ini",
                                           NULL);
    }

  /* Make a best-effort attempt to load state, but mostly ignore any errors:
   * a missing or malformed state file is equivalent to no state having
   * been saved at all */
  if (!g_key_file_load_from_file (self->state, self->state_file,
                                  G_KEY_FILE_NONE, &error))
    {
      g_debug ("Unable to load \"%s\": %s",
               self->state_file, error->message);
      g_clear_error (&error);
    }
}

static void
dkd_avahi_service_save_state (DkdAvahiService *self)
{
  GError *error = NULL;
  gchar **groups;
  gsize n_groups = 0;

  g_return_if_fail (self->state != NULL);

  groups = g_key_file_get_groups (self->state, &n_groups);

  if (n_groups == 0)
    {
      /* There is no state, so delete the file instead of creating it */
      g_debug ("No state to save: deleting \"%s\"", self->state_file);

      if (g_unlink (self->state_file) < 0 && errno != ENOENT)
        g_warning ("Unable to delete \"%s\": %s", self->state_file,
                   g_strerror (errno));

      if (g_rmdir (self->state_subdir) < 0 && errno != ENOENT &&
          errno != ENOTEMPTY)
        g_warning ("Unable to delete \"%s\": %s", self->state_subdir,
                   g_strerror (errno));

      return;
    }

  g_strfreev (groups);
  g_debug ("Saving state to \"%s\"", self->state_file);

  if (g_mkdir_with_parents (self->state_subdir, 0700) < 0 &&
      errno != ENOENT)
    {
      g_warning ("Unable to create \"%s\": %s", self->state_subdir,
                 g_strerror (errno));
      return;
    }

  if (!g_key_file_save_to_file (self->state, self->state_file, &error))
    {
      g_warning ("%s", error->message);
      g_clear_error (&error);
    }
}

static void
dkd_avahi_service_switch_to_alternative (DkdAvahiService *self)
{
  char *n;
  n = avahi_alternative_service_name (self->service_name);
  avahi_free (self->service_name);
  self->service_name = n;
  g_debug ("Service name collision, renaming service to '%s'",
           self->service_name);

  /* Try to save the name we intended to use, and the name we actually
   * used, so that we'll use the same fallback in future as mandated by
   * https://tools.ietf.org/html/rfc6762#section-9,
   * https://tools.ietf.org/html/rfc6763#appendix-D */
  dkd_avahi_service_load_state (self);
  g_key_file_set_string (self->state, STATE_GROUP,
                         STATE_KEY_MACHINE_NAME, self->machine_name);
  g_key_file_set_string (self->state, STATE_GROUP,
                         STATE_KEY_SERVICE_NAME, self->service_name);
  dkd_avahi_service_save_state (self);
}

static void
entry_group_callback (AvahiEntryGroup * g, AvahiEntryGroupState state,
                      gpointer userdata)
{
  DkdAvahiService *self = DKD_AVAHI_SERVICE (userdata);
  GError *error = NULL;

  assert (g == self->group || self->group == NULL);
  self->group = g;

  switch (state)
    {
    case AVAHI_ENTRY_GROUP_ESTABLISHED:
      g_debug ("Service '%s' successfully established.", self->service_name);
      break;
    case AVAHI_ENTRY_GROUP_COLLISION:
      {
        dkd_avahi_service_switch_to_alternative (self);

        if (!dkd_avahi_service_create_services (self, self->client, &error))
          {
            g_warning ("%s", error->message);
            g_main_loop_quit (self->loop);
          }

        break;
      }
    case AVAHI_ENTRY_GROUP_FAILURE:
      g_debug ("Entry group failure: %s",
               avahi_strerror (avahi_client_errno (self->client)));
      g_main_loop_quit (self->loop);
      break;
    case AVAHI_ENTRY_GROUP_UNCOMMITED:
    case AVAHI_ENTRY_GROUP_REGISTERING:
    default:
      ;
    }
}

static gboolean
dkd_avahi_service_create_services (DkdAvahiService *self,
                                   AvahiClient *c,
                                   GError **error)
{
  g_return_val_if_fail (DKD_IS_AVAHI_SERVICE (self), FALSE);
  g_return_val_if_fail (c != NULL, FALSE);

  if (!self->group)
    {
      if (!(self->group = avahi_entry_group_new (c, entry_group_callback, self)))
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "avahi_entry_group_new() failed: %s",
                       avahi_strerror (avahi_client_errno (c)));
          goto fail;
        }
    }
  if (avahi_entry_group_is_empty (self->group))
    {
      gchar *login_pair;
      gchar *settings_pair;
      int try;

      g_debug ("Adding service '%s'", self->service_name);
      login_pair = g_strdup_printf ("login=%s", self->login);
      settings_pair = g_strdup_printf ("settings=%s", self->settings);

      for (try = 0; try < COLLISION_MAX_TRY; try++)
        {
          int ret;

          if ((ret =
               avahi_entry_group_add_service (self->group, AVAHI_IF_UNSPEC,
                                              AVAHI_PROTO_UNSPEC, 0,
                                              self->service_name,
                                              "_steamos-devkit._tcp", NULL,
                                              NULL,
                                              self->service_port,
                                              CURRENT_TXTVERS,
                                              login_pair,
                                              self->devkit1_txt,
                                              settings_pair,
                                              NULL)) < 0)
            {
              if (ret == AVAHI_ERR_COLLISION)
                {
                  dkd_avahi_service_switch_to_alternative (self);
                  continue;
                }
              g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "Failed to add _steamos-devkit._tcp service: %s",
                           avahi_strerror (ret));
              goto fail;
            }
          if ((ret = avahi_entry_group_commit (self->group)) < 0)
            {
              g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "Failed to commit entry group: %s",
                           avahi_strerror (ret));
              goto fail;
            }
          break;
        }

      g_free (login_pair);
      g_free (settings_pair);

      if (try >= COLLISION_MAX_TRY)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "Too many name collisions");
          goto fail;
        }
    }
  return TRUE;

fail:
  return FALSE;
}

static void
client_state_changed_cb (AvahiClient * c, AvahiClientState state,
                         void *userdata)
{
  DkdAvahiService *self = DKD_AVAHI_SERVICE (userdata);
  GError *error = NULL;

  assert (c);
  assert (c == self->client || self->client == NULL);

  switch (state)
    {
    case AVAHI_CLIENT_S_RUNNING:
      if (!dkd_avahi_service_create_services (self, c, &error))
        {
          g_warning ("%s", error->message);
          g_main_loop_quit (self->loop);
        }
      break;
    case AVAHI_CLIENT_FAILURE:
      g_warning ("Client failure: %s",
                 avahi_strerror (avahi_client_errno (c)));
      g_main_loop_quit (self->loop);
      break;
    case AVAHI_CLIENT_S_COLLISION:
    case AVAHI_CLIENT_S_REGISTERING:
      if (self->group)
        avahi_entry_group_reset (self->group);
      break;
    case AVAHI_CLIENT_CONNECTING:
    default:
      ;
    }
}

gboolean
dkd_avahi_service_start (DkdAvahiService *self,
                         const gchar *machine_name,
                         uint64_t server_port,
                         const gchar *entry_point_user,
                         const gchar * const *devkit1_argv,
                         const gchar *settings_json,
                         GMainLoop *loop,
                         GError **error)
{
  int err = 0;
  const AvahiPoll *poll_api = NULL;

  if (!dkd_avahi_service_reconfigure (self, machine_name, server_port,
                                      entry_point_user, devkit1_argv, settings_json,
                                      error))
    return FALSE;

  poll_api = avahi_glib_poll_get (self->glib_poll);
  self->client =
    avahi_client_new (poll_api, 0, client_state_changed_cb, self, &err);
  self->loop = g_main_loop_ref (loop);

  if (self->client == NULL)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Error initializing Avahi: %s", avahi_strerror (err));
      return FALSE;
    }

  return TRUE;
}

gboolean
dkd_avahi_service_reconfigure (DkdAvahiService *self,
                               const gchar *machine_name,
                               uint64_t server_port,
                               const gchar *entry_point_user,
                               const gchar * const *devkit1_argv,
                               const gchar *settings_json,
                               GError **error)
{
  gboolean changed_name = FALSE;
  gboolean changed_txt = FALSE;
  GString *buffer;

  if (self->machine_name == NULL ||
      strcmp (self->machine_name, machine_name) != 0)
    {
      gchar *temp;

      g_free (self->machine_name);
      self->machine_name = g_strdup (machine_name);

      temp = dk_sanitize_machine_name (machine_name);
      avahi_free (self->service_name);
      self->service_name = avahi_strdup (temp);
      g_free (temp);
      g_debug ("Machine name \"%s\" -> service name \"%s\"",
               self->machine_name, self->service_name);

      /* If the machine name matches what we were trying to use last
       * time, substitute the alternative that we used last time, if
       * any. This means that once we've renamed a machine from
       * "Foocorp GameMachine X100" to "Foocorp GameMachine X100 #3",
       * we'll keep that name indefinitely, meaning we don't need to
       * put serial numbers in machine names to get a reasonable UX.
       * See https://tools.ietf.org/html/rfc6762#section-9,
       * https://tools.ietf.org/html/rfc6763#appendix-D
       *
       * This behaviour also means that if we change how
       * dk_sanitize_machine_name() works, existing machines will keep
       * their current names until reconfigured, so client state
       * won't be invalidated. */

      dkd_avahi_service_load_state (self);
      temp = g_key_file_get_string (self->state, STATE_GROUP,
                                    STATE_KEY_MACHINE_NAME, NULL);

      if (temp != NULL && strcmp (temp, machine_name) == 0)
        {
          g_free (temp);
          temp = g_key_file_get_string (self->state, STATE_GROUP,
                                        STATE_KEY_SERVICE_NAME, NULL);

          if (temp != NULL && strcmp (temp, self->service_name) != 0)
            {
              g_debug ("Using stored service name \"%s\" instead",
                       temp);
              avahi_free (self->service_name);
              self->service_name = avahi_strdup (temp);
            }
        }
      else if (strcmp (machine_name, self->service_name) == 0)
        {
          /* In the common case where the machine name is the same as
           * the service name, don't bother storing either. */
          g_debug ("Machine name matches service name: removing "
                   "saved collision state");
          g_key_file_remove_group (self->state, STATE_GROUP, NULL);
          dkd_avahi_service_save_state (self);
        }
      else
        {
          /* Store the new machine name and the resulting service name */
          g_debug ("Saving remapped name");
          g_key_file_set_string (self->state, STATE_GROUP,
                                 STATE_KEY_MACHINE_NAME, self->machine_name);
          g_key_file_set_string (self->state, STATE_GROUP,
                                 STATE_KEY_SERVICE_NAME, self->service_name);
          dkd_avahi_service_save_state (self);
        }

      g_free (temp);
      changed_name = TRUE;
    }

  if (self->login == NULL ||
      strcmp (self->login, entry_point_user) != 0)
    {
      g_free (self->login);
      self->login = g_strdup (entry_point_user);
      changed_txt = TRUE;
    }

  if (self->settings == NULL ||
      strcmp (self->settings, settings_json) != 0)
    {
      g_free (self->settings);
      self->settings = g_strdup (settings_json);
      changed_txt = TRUE;
    }

  if (self->service_port != server_port)
    {
      self->service_port = server_port;
    }

  buffer = g_string_new ("devkit1=");

  if (devkit1_argv == NULL || devkit1_argv[0] == NULL)
    {
      g_string_append (buffer, "devkit-1");
    }
  else
    {
      const gchar *const *iter;

      for (iter = devkit1_argv; *iter != NULL; iter++)
        {
          gchar *tmp = g_shell_quote (*iter);

          if (buffer->len > strlen ("devkit1="))
            g_string_append_c (buffer, ' ');

          g_string_append (buffer, tmp);
          g_free (tmp);
        }
    }

  if (self->devkit1_txt == NULL ||
      strcmp (self->devkit1_txt, buffer->str) != 0)
    {
      g_free (self->devkit1_txt);
      self->devkit1_txt = g_string_free (buffer, FALSE);
      changed_txt = TRUE;
    }
  else
    {
      g_string_free (buffer, TRUE);
    }

  if (self->client != NULL &&
      avahi_client_get_state (self->client) == AVAHI_CLIENT_S_RUNNING)
    {
      if (changed_name || (changed_txt && self->group == NULL))
        {
          if (self->group)
            avahi_entry_group_reset (self->group);

          if (!dkd_avahi_service_create_services (self, self->client, error))
            {
              g_prefix_error (error, "Unable to publish new service name: ");
              return FALSE;
            }
        }
      else if (changed_txt)
        {
          int code;
          gchar *login_pair;
          gchar *settings_pair;

          login_pair = g_strdup_printf ("login=%s", self->login);
          settings_pair = g_strdup_printf ("settings=%s", self->settings);
          code = avahi_entry_group_update_service_txt (self->group,
                                                       AVAHI_IF_UNSPEC,
                                                       AVAHI_PROTO_UNSPEC,
                                                       0,
                                                       self->service_name,
                                                       "_steamos-devkit._tcp",
                                                       NULL,
                                                       CURRENT_TXTVERS,
                                                       login_pair,
                                                       self->devkit1_txt,
                                                       settings_pair,
                                                       NULL);
          g_free (login_pair);
          g_free (settings_pair);

          if (code < 0)
            {
              g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "Failed to update DNS-SD TXT record: %s",
                           avahi_strerror (code));
              return FALSE;
            }
        }
    }

  return TRUE;
}

/* For some reason avahi_entry_group_free() returns int, which means
 * gcc 8 doesn't like to cast it as a GDestroyNotify */
static void
dkd_avahi_entry_group_free (AvahiEntryGroup *self)
{
  avahi_entry_group_free (self);
}

void
dkd_avahi_service_stop (DkdAvahiService *self)
{
  g_clear_pointer (&self->group, dkd_avahi_entry_group_free);
  g_clear_pointer (&self->client, avahi_client_free);
  g_clear_pointer (&self->glib_poll, avahi_glib_poll_free);
  g_clear_pointer (&self->service_name, avahi_free);
  g_clear_pointer (&self->login, g_free);
  g_clear_pointer (&self->loop, g_main_loop_unref);
}

static void
dkd_avahi_service_init (DkdAvahiService *self)
{
  self->service_name = NULL;
  self->service_port = SERVICE_PORT;
  self->glib_poll = avahi_glib_poll_new (NULL, G_PRIORITY_DEFAULT);
  self->client = NULL;
}

static void
dkd_avahi_service_finalize (GObject *object)
{
  DkdAvahiService *self = DKD_AVAHI_SERVICE (object);

  dkd_avahi_service_stop (self);

  g_clear_pointer (&self->state, g_key_file_unref);
  g_clear_pointer (&self->machine_name, g_free);
  g_clear_pointer (&self->state_subdir, g_free);
  g_clear_pointer (&self->state_file, g_free);

  G_OBJECT_CLASS (dkd_avahi_service_parent_class)->finalize (object);
}

static void
dkd_avahi_service_class_init (DkdAvahiServiceClass *cls)
{
  GObjectClass *object_class = G_OBJECT_CLASS (cls);

  avahi_set_allocator (avahi_glib_allocator ());

  object_class->finalize = dkd_avahi_service_finalize;
}

DkdAvahiService *
dkd_avahi_service_new (void)
{
  return g_object_new (DKD_TYPE_AVAHI_SERVICE,
                       NULL);
}
