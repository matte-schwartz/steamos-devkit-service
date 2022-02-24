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

#include <errno.h>
#include <gio/gio.h>
#include <gio/giotypes.h>
#include <gio/gunixoutputstream.h>
#include <glib-unix.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>
#include <json-glib/json-glib.h>
#include <json-glib/json-gobject.h>
#include <libsoup/soup.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <systemd/sd-daemon.h>
#include <unistd.h>

#include "avahi-service.h"
// #include "lib/backports.h"
#include "json.h"
#include "utils.h"

#include "defines.h"

/* https://www.freedesktop.org/wiki/Software/systemd/hostnamed/ */
#define HOSTNAME_BUS_NAME "org.freedesktop.hostname1"
#define HOSTNAME_OBJECT_PATH "/org/freedesktop/hostname1"
#define HOSTNAME_IFACE HOSTNAME_BUS_NAME
#define PROPERTIES_IFACE "org.freedesktop.DBus.Properties"

typedef struct
{
  GObject parent_instance;

  GKeyFile *config;
  GKeyFile *user_config;
  gchar *machine_name;
  gchar **users;
  const gchar *entry_point_user;

  GMainLoop *loop;
  SoupServer *server;
  uint64_t server_port;
  DkdAvahiService *avahi_service;
  GDBusConnection *system_bus;
  guint hup_signal_watch;
  guint hostname_property_changed_subscription;
  gchar **devkit1_argv;
  gchar *settings;

  struct
    {
      gchar **hooks;
      gchar *entry_point;
      gboolean close_stdout_when_ready;
      gboolean use_default_hooks;
    } options;
} DkdApplication;

typedef struct
{
  GObjectClass parent_class;
} DkdApplicationClass;

#define DKD_TYPE_APPLICATION (dkd_application_get_type ())
#define DKD_APPLICATION(obj) \
  G_TYPE_CHECK_INSTANCE_CAST ((obj), DKD_TYPE_APPLICATION, DkdApplication)
#define DKD_APPLICATION_CLASS(cls) \
  G_TYPE_CHECK_CLASS_CAST ((cls), DKD_TYPE_APPLICATION, DkdApplicationClass)
#define DKD_IS_APPLICATION(obj) \
  G_TYPE_CHECK_INSTANCE_TYPE ((obj), DKD_TYPE_APPLICATION)
#define DKD_IS_APPLICATION_CLASS(cls) \
  G_TYPE_CHECK_CLASS_TYPE ((cls), DKD_TYPE_APPLICATION)
#define DKD_APPLICATION_GET_CLASS(obj) \
  G_TYPE_INSTANCE_GET_CLASS ((obj), DKD_TYPE_APPLICATION, DkdApplicationClass)

static GType dkd_application_get_type (void);

G_DEFINE_TYPE (DkdApplication, dkd_application, G_TYPE_OBJECT)

typedef struct
{
  GTask *task;
  DkdApplication *app;
  SoupMessage *msg;
  gchar *reply;
  guint status;
  gchar *sender_ip;
} AsyncQuery;

static AsyncQuery *
async_query_new (DkdApplication *app,
                 SoupMessage *m)
{
  AsyncQuery *aq = g_new0 (AsyncQuery, 1);
  aq->app = g_object_ref (app);
  aq->msg = g_object_ref (m);
  aq->status = SOUP_STATUS_INTERNAL_SERVER_ERROR;
  return aq;
}

static void
async_query_free (AsyncQuery * aq)
{
  if (aq)
    {
      g_clear_object (&aq->task);
      g_clear_object (&aq->msg);
      g_clear_object (&aq->app);
      g_clear_pointer (&aq->reply, g_free);
      g_clear_pointer (&aq->sender_ip, g_free);
      g_free (aq);
    }
}

/* Runs in worker thread */
static gboolean
writefile (gchar * template, const guint8 * data, gsize len, gboolean newline)
{
  GOutputStream *ostream;
  GError *error = NULL;
  int fd;
  gboolean ret = FALSE;

  /* Create an unique file and write data */
  fd = mkstemp (template);
  if (fd >= 0)
    {
      ostream = g_unix_output_stream_new (fd, FALSE);
      /* Write data to the file */
      if (!g_output_stream_write_all (ostream, data, len, NULL, NULL, &error))
        {
          g_warning ("Failed to write %s: %s", template, error->message);
          g_clear_error (&error);
        }
      else
        {
          /* Add a new line if necessary */
          if (newline)
            {
              if (!g_output_stream_write_all
                  (ostream, "\n", 1, NULL, NULL, &error))
                {
                  g_warning ("Failed to write new line to %s: %s", template,
                             error->message);
                  g_clear_error (&error);
                }
              else
                ret = TRUE;
            }
          else
            ret = TRUE;
        }
      if (!g_output_stream_close (ostream, NULL, &error))
        {
          g_warning ("Failed to close %s: %s", template, error->message);
          g_clear_error (&error);
          ret = FALSE;
        }
      g_clear_object (&ostream);
      close (fd);
    }
  return ret;
}

/* Runs in worker thread */
static gchar *
writekey (SoupMessage * msg)
{
  gchar *filename = NULL;
  const guint8 *data = (const guint8 *) msg->request_body->data;
  gsize len = msg->request_body->length;
  char template[] = "/tmp/devkitd-XXXXXX";
  gboolean found_name = FALSE;

  if (data)
    {
      gsize idx;

      /* Check length */
      if (len >= (64 * 1024))
        goto out;
      /* Check data start with 'ssh-rsa ' */
      if (memcmp ("ssh-rsa ", data, 8) != 0)
        goto out;
      /* Count character until Base 64 data */
      for (idx = 8; idx < len; idx++)
        {
          if (data[idx] != ' ')
            break;
        }
      /* Check Base64 data */
      for (; idx < len; idx++)
        {
          if ((data[idx] == '+') ||
              (data[idx] >= '/' && data[idx] <= '9') ||
              (data[idx] >= 'a' && data[idx] <= 'z') ||
              (data[idx] >= 'A' && data[idx] <= 'Z'))
            continue;
          else if (data[idx] == '=')
            {
              idx++;
              if ((idx < len) && (data[idx] == ' '))
                break;
              else if ((idx < len) && (data[idx] == '='))
                {
                  idx++;
                  if ((idx < len) && (data[idx] == ' '))
                    break;
                }
              goto out;
            }
          else if (data[idx] == ' ')
            break;
          else
            goto out;
        }

      for (; idx < len; idx++)
        {
          if (data[idx] == ' ')
            {
              /* it's a space, the rest is name or magic phrase, don't write to disk */
              if (found_name)
                {
                  len = idx;
                }
              else
                {
                  found_name = TRUE;
                }
            }
          if (data[idx] == '\0')
            goto out;
          if (data[idx] == '\n' && idx != len - 1)
            goto out;
        }
      /* write data to the file */
      if (writefile
          (template, data, len, ((data[len - 1] != '\n') ? TRUE : FALSE)))
        filename = g_strdup (template);
      else
        unlink (template);
    }
out:
  return filename;
}

/* Runs in worker thread */
static void
deletekey (const gchar * filename)
{
  if (filename)
    unlink (filename);
}

/* Runs in worker thread */
static gboolean
exec_script (DkdApplication *self,
             const gchar *action,
             const gchar *keypath,
             const gchar *sender_ip,
             const gchar * const *users,
             gchar **script_output)
{
  GSubprocessLauncher *launcher = NULL;
  GSubprocess *subprocess = NULL;
  gchar *script = NULL;
  gboolean ret = FALSE;
  GError *error = NULL;
  GPtrArray *argv = NULL;
  guint i;
  GBytes *local_bytes = NULL;
  gchar *local_utf8 = NULL;

  g_return_val_if_fail (action != NULL, FALSE);
  g_return_val_if_fail (keypath != NULL, FALSE);

  script = dk_find_hook ((const gchar * const *) self->options.hooks,
                         self->options.use_default_hooks,
                         action, &error);

  if (!script)
    {
      g_warning ("%s", error->message);
      g_clear_error (&error);
      return FALSE;
    }

  argv = g_ptr_array_new_with_free_func (g_free);
  launcher = g_subprocess_launcher_new (G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE);

  if (dk_hook_is_generic_python (script))
    g_ptr_array_add (argv, g_strdup (dk_get_best_python ()));

  g_ptr_array_add (argv, g_strdup (script));
  g_ptr_array_add (argv, g_strdup (keypath));

  if (sender_ip != NULL)
    g_ptr_array_add(argv, g_strdup(sender_ip));

  for (i = 0; users != NULL && users[i] != NULL; i++)
    g_ptr_array_add (argv, g_strdup (users[i]));

  g_ptr_array_add (argv, NULL);

  subprocess = g_subprocess_launcher_spawnv (
      launcher,
      (const gchar * const *) argv->pdata,
      &error);

  if (!subprocess)
    {
      GString *command_line = g_string_new ("");

      for (i = 0; i < argv->len; i++)
        {
          if (argv->pdata[i] != NULL)
            {
              gchar *quoted = g_shell_quote (argv->pdata[i]);

              if (command_line->len > 0)
                g_string_append_c (command_line, ' ');

              g_string_append (command_line, quoted);
              g_free (quoted);
            }
        }

      g_warning ("Failed to create subprocess: %s: %s",
                 command_line->str, error->message);
      g_clear_error (&error);
      g_string_free (command_line, TRUE);
      goto out;
    }
  if (!g_subprocess_communicate (subprocess, NULL, NULL, &local_bytes, NULL, &error))
    {
      g_warning ("Fail to wait subprocess : %s", error->message);
      g_clear_error (&error);
      goto out;
    }

  local_utf8 = g_utf8_make_valid (g_bytes_get_data (local_bytes, NULL), -1);
  g_message ("Subprocess output: %s", local_utf8);

  if (!g_subprocess_get_if_exited (subprocess))
    {
      g_warning ("Subprocess exit abnormally");
      goto out;
    }
  else
    {
      gint exit_status = g_subprocess_get_exit_status (subprocess);
      if (exit_status == 0)
        {
          ret = TRUE;
        }
    }
out:
  if (script_output != NULL)
    *script_output = g_steal_pointer (&local_utf8);
  else
    g_clear_pointer (&local_utf8, g_free);
  g_bytes_unref (local_bytes);
  if (subprocess)
    g_object_unref (subprocess);
  g_clear_object (&launcher);
  g_free (script);
  if (argv)
    g_ptr_array_unref (argv);
  return ret;
}

/* Runs in worker thread */
static void
add_ssh_key_cb (GTask * task, gpointer source_object, gpointer task_data,
                GCancellable * cancellable)
{
  AsyncQuery *aq = task_data;
  gchar *keypath;
  gchar *script_output = NULL;

  g_debug ("add_ssh_key_cb runs in a separate thread");

  keypath = writekey (aq->msg);
  if (!keypath)
    {
      aq->status = SOUP_STATUS_FORBIDDEN;
      goto out;
    }

  if (!exec_script (aq->app, "approve-ssh-key", keypath, aq->sender_ip,
                    NULL,
                    &script_output))
    {
      aq->status = SOUP_STATUS_FORBIDDEN;
      aq->reply = g_strconcat ("approve-ssh-key:\n", script_output, NULL);
      g_clear_pointer (&script_output, g_free);
      goto out;
    }

  aq->reply = g_strconcat ("approve-ssh-key:\n", script_output, NULL);
  g_clear_pointer (&script_output, g_free);

  if (exec_script (aq->app, "install-ssh-key", keypath, NULL,
                   (const gchar * const *) aq->app->users,
                   &script_output))
    {
      aq->status = SOUP_STATUS_OK;
    }
  else
    {
      aq->status = SOUP_STATUS_INTERNAL_SERVER_ERROR;
    }
  aq->reply = g_strconcat (aq->reply, "install-ssh-key:\n", script_output, NULL);
  g_clear_pointer (&script_output, g_free);

out:
  deletekey (keypath);
}

static void
add_ssh_key_completed (GObject * source_object, GAsyncResult * res,
                       gpointer user_data)
{
  AsyncQuery *aq = user_data;

  if (aq->reply)
    soup_message_set_response (aq->msg, "text/plain", SOUP_MEMORY_TAKE,
                               aq->reply, strlen (aq->reply));
  aq->reply = NULL;   /* ownership transferred, do not free */
  soup_message_set_status (aq->msg, aq->status);
  soup_server_unpause_message (aq->app->server, aq->msg);

  async_query_free (aq);
  g_debug ("Task completed");
}

static void
server_callback (SoupServer * server, SoupMessage * msg,
                 const char *path, GHashTable * query,
                 SoupClientContext * context, gpointer data)
{
  DkdApplication *app = DKD_APPLICATION (data);
  SoupMessageHeadersIter iter;
  const char *name, *value;

  g_debug ("%s %s HTTP/1.%d", msg->method, path,
           soup_message_get_http_version (msg));
  soup_message_headers_iter_init (&iter, msg->request_headers);
  while (soup_message_headers_iter_next (&iter, &name, &value))
    g_debug ("%s: %s", name, value);
  if (msg->request_body->length)
    g_debug ("%s", msg->request_body->data);

  if ((msg->method == SOUP_METHOD_POST) && strcmp ("/register", path) == 0)
    {
      AsyncQuery *aq;
      GSocketAddress *sockaddr;
      GInetAddress *addr;
      gchar *sender_ip = NULL;
      sockaddr = soup_client_context_get_remote_address (context);
      if (sockaddr != NULL && G_IS_INET_SOCKET_ADDRESS (sockaddr))
        {
          addr = g_inet_socket_address_get_address (
              G_INET_SOCKET_ADDRESS (sockaddr));
          sender_ip = g_inet_address_to_string (addr);
          g_debug ("From %s", sender_ip);
        }
      else
        {
          g_debug ("Unable to get request ip address");
        }
      aq = async_query_new (app, msg);
      aq->task = g_task_new (NULL, NULL, add_ssh_key_completed, aq);
      aq->sender_ip = sender_ip;
      soup_server_pause_message (server, msg);
      g_task_set_task_data (aq->task, aq, NULL);
      g_task_run_in_thread (aq->task, add_ssh_key_cb);
    }
  else if (msg->method == SOUP_METHOD_GET && strcmp ("/login-name", path) == 0)
    {
      soup_message_set_response (msg, "text/plain", SOUP_MEMORY_COPY,
                                 app->entry_point_user,
                                 strlen (app->entry_point_user));
      soup_message_set_status (msg, SOUP_STATUS_OK);
    }
  else if (msg->method == SOUP_METHOD_GET &&
           strcmp ("/properties.json", path) == 0)
    {
      gchar *text;
      JsonNode *node;
      JsonObject *object;
      JsonArray *arr;
      gchar **arg;

      node = json_node_new (JSON_NODE_OBJECT);
      object = json_object_new ();
      json_node_set_object (node, object);
      json_object_set_int_member (object, "txtvers", 1);
      json_object_set_string_member (object, "login",
                                     app->entry_point_user);
      json_object_set_string_member (object, "settings",
                                     app->settings);
      arr = json_array_new ();

      for (arg = app->devkit1_argv; *arg != NULL; arg++)
        json_array_add_string_element (arr, *arg);

      /* This takes ownership: do not free arr now! */
      json_object_set_array_member (object, "devkit1", arr);

      text = dk_json_to_string (node, TRUE);
      soup_message_set_response (msg, "application/json",
                                 SOUP_MEMORY_TAKE,
                                 text, strlen (text));
      soup_message_set_status (msg, SOUP_STATUS_OK);
      json_object_unref (object);
      json_node_free (node);
    }
  else if (msg->method == SOUP_METHOD_GET && query
           && g_hash_table_size (query))
    {
      gchar *command = g_hash_table_lookup (query, "command");
      if (command)
        {
          g_debug ("Received command : %s", command);
          if (!strcmp ("ping", command))
            {
              soup_message_set_response (msg, "text/plain",
                                         SOUP_MEMORY_STATIC, "pong\n", 6);
              soup_message_set_status (msg, SOUP_STATUS_OK);
            }
          else
            {
              soup_message_set_status (msg, SOUP_STATUS_NOT_FOUND);
            }
        }
    }
  else
    {
      soup_message_set_status (msg, SOUP_STATUS_NOT_FOUND);
    }
}

static void
dkd_application_init (DkdApplication *self)
{
  self->config = g_key_file_new ();
  self->user_config = g_key_file_new ();
  self->loop = g_main_loop_new (NULL, TRUE);
  self->server = soup_server_new (SOUP_SERVER_SERVER_HEADER,
                                  "steamos-devkit-service", NULL);
  self->options.hooks = NULL;
  self->options.close_stdout_when_ready = FALSE;
  self->options.use_default_hooks = TRUE;
}

#if !GLIB_CHECK_VERSION(2, 69, 0)
#define g_spawn_check_wait_status(x, e) (g_spawn_check_exit_status (x, e))
#endif

static gboolean
dkd_application_identify (DkdApplication *self,
                          GError **error)
{
  GSubprocessLauncher *launcher = NULL;
  GSubprocess *subprocess = NULL;
  JsonParser *parser = NULL;
  JsonReader *reader = NULL;
  JsonNode *root = NULL;
  gchar *script = NULL;
  GBytes *stdout_buf = NULL;
  gboolean ret = FALSE;
  const gchar *machine_name;

  script = dk_find_hook ((const gchar * const *) self->options.hooks,
                         self->options.use_default_hooks,
                         "devkit-1-identify", error);

  if (script == NULL)
    goto out;

  launcher = g_subprocess_launcher_new (G_SUBPROCESS_FLAGS_STDOUT_PIPE);

  if (dk_hook_is_generic_python (script))
    subprocess = g_subprocess_launcher_spawn (launcher, error,
                                              dk_get_best_python (),
                                              script, NULL);
  else
    subprocess = g_subprocess_launcher_spawn (launcher, error, script, NULL);

  if (!subprocess)
    {
      g_prefix_error (error, "Failed to create subprocess '%s': ", script);
      goto out;
    }

  if (!g_subprocess_communicate (subprocess, NULL, NULL, &stdout_buf,
                                 NULL, error))
    {
      g_prefix_error (error, "Failed to communicate with subprocess '%s': ",
                      script);
      goto out;
    }

  if (!g_spawn_check_wait_status (g_subprocess_get_status (subprocess),
                                  error))
    {
      g_prefix_error (error, "Subprocess '%s' failed: ", script);
      goto out;
    }

  parser = json_parser_new ();

  if (!dk_json_parser_load_from_bytes (parser, stdout_buf, error))
    {
      g_prefix_error (error, "Failed to parse output of subprocess '%s': ",
                      script);
      goto out;
    }

  root = json_parser_get_root (parser);

  if (root == NULL)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Subprocess '%s' returned empty result", script);
      goto out;
    }

  if (json_node_get_node_type (root) != JSON_NODE_OBJECT)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Subprocess '%s' did not return a JSON object", script);
      goto out;
    }

  reader = json_reader_new (root);
  json_reader_read_member (reader, "machine_name");
  machine_name = json_reader_get_string_value (reader);

  if (machine_name != NULL)
    {
      g_free (self->machine_name);
      self->machine_name = g_strdup (machine_name);
    }

  json_reader_end_member (reader);
  ret = TRUE;

out:
  g_clear_pointer (&stdout_buf, g_bytes_unref);
  g_clear_object (&launcher);
  g_clear_object (&subprocess);
  g_clear_object (&parser);
  g_clear_object (&reader);
  g_free (script);
  return ret;
}

static gboolean
dkd_application_load_configuration (DkdApplication *self,
                                    GError **error)
{
  gchar *user_config_path = g_build_path("/", g_get_home_dir(), ".config", PACKAGE "/" PACKAGE ".conf", NULL);
  const gchar * const search_dirs[] =
    {
      "/etc",
      DEVKIT_DATADIR,
      NULL
    };

  GError *local_error = NULL;
  gchar *port;

  if (!dkd_application_identify (self, error)) {
    g_free (user_config_path);
    return FALSE;
  }

  if (self->machine_name == NULL)
    {
      /* Last resort: use gethostname() even if the result is something
       * useless like steamos or localhost. This will only happen the
       * first time. On reloads, the previous machine_name will be
       * carried over if the identify script can't come up with
       * anything better. */
      self->machine_name = g_strdup (g_get_host_name ());
    }

  if (!g_key_file_load_from_dirs (self->config, PACKAGE "/" PACKAGE ".conf",
                                  (const gchar **) search_dirs,
                                  NULL, G_KEY_FILE_NONE, &local_error))
    {
      if (g_error_matches (local_error, G_KEY_FILE_ERROR,
                           G_KEY_FILE_ERROR_NOT_FOUND))
        {
          g_clear_error (&local_error);
          g_debug ("Site config file not found");
        }
      else
        {
          g_propagate_prefixed_error (error, local_error,
                                      "Failed to load configuration: ");
        }
    }

  /* Next load user config to try to override any defaults in system config */
  if (!g_key_file_load_from_file (self->user_config, user_config_path,
                                  G_KEY_FILE_NONE, &local_error))
    {
      // Ignore since user config is not required
      g_clear_error (&local_error);
      g_debug ("User config file not found");
    }
  g_free (user_config_path);

  // Now load server_port, since we are going to do listen_all after we return
  port = g_key_file_get_string (self->config, "Settings", "Port", NULL);
  if (port == NULL)
    {
      // Use default value unless user config has one
      self->server_port = SERVICE_PORT;
    }
  else
    {
      self->server_port = atol (port);
      // Invalid port or atol failed.
      if (self->server_port == 0)
        {
          self->server_port = SERVICE_PORT;
        }
    }

  port = g_key_file_get_string (self->user_config, "Settings", "Port", NULL);
  if (port == NULL)
    {
      // Ignore, we set default above or have system wide setting
    }
  else
    {
      // TODO: Make sure result is valid?
      self->server_port = atol (port);
    }

  return TRUE;
}

static gboolean
dkd_application_publish (DkdApplication *self,
                         GError **error)
{
  const gchar * const standard_users[] = { "root", "desktop", "steam" };
  GPtrArray *users = NULL;
  gsize length = 0;
  gchar **settings = g_key_file_get_keys (self->config, "Settings", &length, NULL);
  gsize user_length = 0;
  gchar **user_settings = g_key_file_get_keys (self->user_config, "Settings", &user_length, NULL);

  JsonNode *node;
  JsonObject *object;

  guint s = 0;
  gchar *key;

  if (length > 0)
    key = settings[s];
  else
    key = NULL;

  node = json_node_new (JSON_NODE_OBJECT);
  object = json_object_new ();
  json_node_set_object (node, object);

  while (key != NULL) {
    gchar *value = g_key_file_get_string (self->config, "Settings", key, NULL);
    if (value != NULL) {
      json_object_set_string_member (object, key,
                                     value);
    }
    key = settings[s++];
  }

  // Now override system settings with user settings if present
  s = 0;
  if (length > 0)
    g_strfreev (settings);

  if (user_length > 0)
    key = user_settings[0];
  else
    key = NULL;

  while (key != NULL) {
    gchar *value = g_key_file_get_string (self->user_config, "Settings", key, NULL);
    if (value != NULL) {
      json_object_set_string_member (object, key, value);
    }
    key = user_settings[s++];
  }

  self->settings = dk_json_to_string (node, FALSE);

  users = g_ptr_array_new_with_free_func (g_free);

  if (geteuid () == 0)
    {
      gchar **configured_users = NULL;
      guint i;

      configured_users = g_key_file_get_string_list (self->config,
                                                     "Users",
                                                     "ShellUsers",
                                                     NULL, NULL);

      if (configured_users != NULL)
        {
          for (i = 0; configured_users[i] != NULL; i++)
            g_ptr_array_add (users, g_strdup (configured_users[i]));
        }
      else
        {
          for (i = 0; i < G_N_ELEMENTS (standard_users); i++)
            g_ptr_array_add (users, g_strdup (standard_users[i]));
        }

      g_strfreev (configured_users);
    }
  else
    {
      gchar **configured_users = NULL;
      guint i;

      configured_users = g_key_file_get_string_list (self->user_config,
                                                     "Users",
                                                     "ShellUsers",
                                                     NULL, NULL);

      if (configured_users != NULL)
        {
          for (i = 0; configured_users[i] != NULL; i++)
            g_ptr_array_add (users, g_strdup (configured_users[i]));
        }
      else
        {
          // No user config, so just use current username
          g_ptr_array_add (users, g_strdup (g_get_user_name ()));
        }
    }

  /* Check the length before appending the NULL that makes it into
   * a GStrv */
  if (users->len == 1)
    {
      /* There is only one user, so we can run new-game and ensure-game
       * as that user directly */
      self->entry_point_user = g_ptr_array_index (users, 0);
    }
  else
    {
      /* We need to be root to enable swapping between users */
      self->entry_point_user = "root";
    }

  g_ptr_array_add (users, NULL);

  /* "Steal" contents of GPtrArray as a gchar ** */
  self->users = (gchar **) g_ptr_array_free (users, FALSE);

  if (self->avahi_service == NULL)
    {
      self->avahi_service = dkd_avahi_service_new ();

      if (!dkd_avahi_service_start (self->avahi_service,
                                    self->machine_name,
                                    self->server_port,
                                    self->entry_point_user,
                                    (const gchar * const *) self->devkit1_argv,
                                    self->settings,
                                    self->loop, error))
        {
          g_prefix_error (error, "Failed to start mDNS service: ");
          return FALSE;
        }
    }
  else if (!dkd_avahi_service_reconfigure (self->avahi_service,
                                           self->machine_name,
                                           self->server_port,
                                           self->entry_point_user,
                                           (const gchar * const *) self->devkit1_argv,
                                            self->settings,
                                           error))
    {
      g_prefix_error (error, "Failed to reconfigure mDNS service: ");
      return FALSE;
    }

  return TRUE;
}

static void
dkd_application_reconfigure (DkdApplication *self)
{
  GError *error = NULL;

  if (!dkd_application_load_configuration (self, &error))
    {
      g_warning ("Could not reload configuration: %s", error->message);
      g_clear_error (&error);
    }
  else if (!dkd_application_publish (self, &error))
    {
      g_warning ("Could not apply new configuration: %s", error->message);
      g_clear_error (&error);
    }
}

static gboolean
hup_signal_cb (gpointer user_data)
{
  DkdApplication *self = DKD_APPLICATION (user_data);

  dkd_application_reconfigure (self);
  return G_SOURCE_CONTINUE;
}

static void
hostname_changed_cb (GDBusConnection *system_bus G_GNUC_UNUSED,
                     const gchar *sender G_GNUC_UNUSED,
                     const gchar *object_path G_GNUC_UNUSED,
                     const gchar *iface G_GNUC_UNUSED,
                     const gchar *signal G_GNUC_UNUSED,
                     GVariant *parameters G_GNUC_UNUSED,
                     gpointer user_data)
{
  DkdApplication *self = DKD_APPLICATION (user_data);

  /* Ignore the parameters: any property change potentially causes a
   * machine identity change */
  dkd_application_reconfigure (self);
}

static void
system_bus_get_cb (GObject *source_object G_GNUC_UNUSED,
                   GAsyncResult *result,
                   gpointer user_data)
{
  DkdApplication *self = DKD_APPLICATION (user_data);
  GError *error = NULL;

  self->system_bus = g_bus_get_finish (result, &error);

  if (self->system_bus != NULL)
    {
      self->hostname_property_changed_subscription =
          g_dbus_connection_signal_subscribe (
              self->system_bus, HOSTNAME_BUS_NAME, PROPERTIES_IFACE,
              "PropertiesChanged", HOSTNAME_OBJECT_PATH, HOSTNAME_IFACE,
              G_DBUS_SIGNAL_FLAGS_NONE, hostname_changed_cb, self, NULL);
    }
  else
    {
      g_warning ("Unable to connect to system bus: %s", error->message);
      g_clear_error (&error);
    }

  g_object_unref (self);
}

static gboolean
deprecated_option_cb (const char *option,
                      const char *value,
                      gpointer option_group_data,
                      GError **error)
{
  g_printerr ("steamos-devkit-service: Ignoring deprecated option \"%s\"\n",
              option);
  return TRUE;
}

static gboolean
dkd_application_start (DkdApplication *self,
                       int *argcp,
                       gchar ***argvp,
                       GError **error)
{
  gboolean ret = FALSE;
  GOptionContext *context = NULL;
  GOptionEntry entries[] =
    {
      { "hooks", '\0', G_OPTION_FLAG_NONE, G_OPTION_ARG_FILENAME_ARRAY,
        &self->options.hooks,
        "Directory to read to find hook scripts (can be repeated, "
        "most important first)",
        "DIR" },
      { "entry-point", '\0', G_OPTION_FLAG_NONE, G_OPTION_ARG_FILENAME,
        &self->options.entry_point,
        "devkit-1 entry point" },
      { "close-stdout-when-ready", '\0', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE,
        &self->options.close_stdout_when_ready,
        "Close the standard output file descriptor (which should be a pipe) "
        "when ready to receive requests" },
      { "default-hooks", '\0', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE,
        &self->options.use_default_hooks,
        "Use the default search path for hook scripts after anything "
        "specified with --hooks [default]" },
      { "no-default-hooks", '\0', G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE,
        &self->options.use_default_hooks,
        "Don't use the default search path for hook scripts after "
        "anything specified with --hooks" },
      { "system-log", '\0', G_OPTION_FLAG_HIDDEN|G_OPTION_FLAG_NO_ARG,
        G_OPTION_ARG_CALLBACK, deprecated_option_cb, "Does nothing" },
      { "no-system-log", '\0', G_OPTION_FLAG_HIDDEN|G_OPTION_FLAG_NO_ARG,
        G_OPTION_ARG_CALLBACK, deprecated_option_cb, "Does nothing" },
      { NULL }
    };
  GSList *uris = NULL;
  GSList *u;
  gchar **hook;
  gchar *cwd = NULL;
  GPtrArray *devkit1_argv;

  context = g_option_context_new ("- devkit discovery server");
  g_option_context_add_main_entries (context, entries, NULL);

  if (!g_option_context_parse (context, argcp, argvp, error))
    goto out;

  /* Make hooks absolute */
  for (hook = self->options.hooks; hook != NULL && *hook != NULL; hook++)
    {
      if (*hook[0] != '/')
        {
          gchar *tmp = *hook;

          if (cwd == NULL)
            cwd = g_get_current_dir ();

          *hook = g_build_filename (cwd, tmp, NULL);
          g_free (tmp);
        }
    }

  devkit1_argv = g_ptr_array_new_with_free_func (g_free);
  if (self->options.entry_point != NULL)
    {
      g_ptr_array_add (devkit1_argv, g_strdup (self->options.entry_point));
    }
  else
    {
      g_ptr_array_add (devkit1_argv, g_strdup ("devkit-1"));
    }

  if (self->options.hooks != NULL && self->options.hooks[0] != NULL)
    {
      gchar **iter;

      for (iter = self->options.hooks; *iter != NULL; iter++)
        g_ptr_array_add (devkit1_argv,
                         g_strdup_printf ("--hooks=%s", *iter));
    }

  if (!self->options.use_default_hooks)
    g_ptr_array_add (devkit1_argv, g_strdup ("--no-default-hooks"));

  g_ptr_array_add (devkit1_argv, NULL);

  /* "Steal" contents of GPtrArray as a gchar ** */
  g_strfreev (self->devkit1_argv);
  self->devkit1_argv = (gchar **) g_ptr_array_free (devkit1_argv, FALSE);

  g_bus_get (G_BUS_TYPE_SYSTEM, NULL, system_bus_get_cb,
             g_object_ref (self));

  self->hup_signal_watch = g_unix_signal_add (SIGHUP, hup_signal_cb, self);

  if (!dkd_application_load_configuration (self, error))
    goto out;

  if (!soup_server_listen_all (self->server, self->server_port, 0, error))
    {
      // TODO: Maybe try the next port, etc. until one works, then save the
      // value in user_config or config...
      g_prefix_error (error, "Failed to listen on port: %ld",
                      self->server_port);
      goto out;
    }

  soup_server_add_handler (self->server, "/", server_callback, self, NULL);

  uris = soup_server_get_uris (self->server);

  for (u = uris; u; u = u->next)
    {
      gchar *str = soup_uri_to_string (u->data, FALSE);

      g_debug ("Listening on %s", str);
      g_free (str);
      soup_uri_free (u->data);
    }

  if (!dkd_application_publish (self, error))
    goto out;

  if (self->options.close_stdout_when_ready)
    {
      if (dup2 (STDERR_FILENO, STDOUT_FILENO) != STDOUT_FILENO)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "Unable to make stdout a copy of stderr: %s",
                       g_strerror (errno));
          goto out;
        }
    }

  ret = TRUE;

out:
  if (context != NULL)
    g_option_context_free (context);

  g_free (cwd);
  g_slist_free (uris);
  return ret;
}

static void
dkd_application_dispose (GObject *object)
{
  DkdApplication *self = DKD_APPLICATION (object);

  if (self->system_bus != NULL &&
      self->hostname_property_changed_subscription != 0)
    {
      g_dbus_connection_signal_unsubscribe (
          self->system_bus,
          self->hostname_property_changed_subscription);
      self->hostname_property_changed_subscription = 0;
    }

  g_clear_object (&self->system_bus);

  if (self->hup_signal_watch != 0)
    {
      g_source_remove (self->hup_signal_watch);
      self->hup_signal_watch = 0;
    }

  if (self->server != NULL)
    {
      soup_server_remove_handler (self->server, "/");
      soup_server_disconnect (self->server);
      g_clear_object (&self->server);
    }

  g_clear_object (&self->avahi_service);

  G_OBJECT_CLASS (dkd_application_parent_class)->dispose (object);
}

static void
dkd_application_finalize (GObject *object)
{
  DkdApplication *self = DKD_APPLICATION (object);

  g_clear_pointer (&self->config, g_key_file_unref);
  g_clear_pointer (&self->user_config, g_key_file_unref);
  self->entry_point_user = NULL;
  g_clear_pointer (&self->users, g_strfreev);
  g_clear_pointer (&self->loop, g_main_loop_unref);

  G_OBJECT_CLASS (dkd_application_parent_class)->finalize (object);
}

static void
dkd_application_class_init (DkdApplicationClass *cls)
{
  GObjectClass *object_class = G_OBJECT_CLASS (cls);

  object_class->dispose = dkd_application_dispose;
  object_class->finalize = dkd_application_finalize;
}

int
main (int argc, char **argv)
{
  DkdApplication *app;
  GError *error = NULL;
  int ret = 0;

  app = g_object_new (DKD_TYPE_APPLICATION, NULL);

  if (!dkd_application_start (app, &argc, &argv, &error))
    {
      if (error != NULL)
        {
          g_warning ("%s", error->message);
          g_clear_error (&error);
        }
      else
        {
           g_warning("Unable to start devkit daemon application");
        }
      ret = 1;
      goto out;
    }

  sd_notify (0, "READY=1");
  g_main_loop_run (app->loop);

out:
  if (app != NULL && app->avahi_service != NULL)
    dkd_avahi_service_stop (app->avahi_service);

  g_clear_object (&app);

  return ret;
}
